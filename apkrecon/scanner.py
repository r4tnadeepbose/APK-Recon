"""Scanning primitives: extraction passes, archive inventory and helpers."""

import glob
import math
import os
import shutil
import zipfile
from urllib.parse import parse_qsl, urlsplit

from .config import ENTROPY_THRESHOLD, JADX_CANDIDATES
from .regexes import (
    CRYPTO_LOOKUP, CRYPTO_RE, DOMAIN_RE, EMAIL_RE, ENTROPY_RE, EXT_RE,
    IPV4_RE, IPV6_RE, SECRET_PATTERNS, SDK_LOOKUP, SDK_RE, SIGNAL_LOOKUP,
    SIGNAL_RE, URL_RE,
)

def shannon_entropy(token):
    if not token:
        return 0.0
    counts = {}
    for char in token:
        counts[char] = counts.get(char, 0) + 1
    length = len(token)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


# ===========================================================================

def find_jadx(explicit=None):
    """Locate the jadx CLI, including bundled jadx-gui-with-JRE packages."""
    if explicit:
        prefix, label = find_tool([explicit])
        if prefix:
            return prefix, label
    prefix, label = find_tool(JADX_CANDIDATES)
    if prefix:
        return prefix, label

    home = os.path.expanduser("~")
    bundled_patterns = (
        os.path.join(home, "Downloads", "jadx-gui-*-with-jre-win"),
        os.path.join(home, "Downloads", "jadx-gui-*"),
        os.path.join(home, "jadx-gui-*-with-jre-win"),
        os.path.join("C:\\", "jadx-gui-*-with-jre-win"),
    )
    seen = set()
    for pattern in bundled_patterns:
        for folder in sorted(glob.glob(pattern), reverse=True):
            if folder in seen:
                continue
            seen.add(folder)
            for java_name in ("java.exe", "java"):
                java = os.path.join(folder, "jre", "bin", java_name)
                if not os.path.isfile(java):
                    continue
                jars = sorted(glob.glob(os.path.join(folder, "lib", "jadx-*all.jar")))
                if jars:
                    return (
                        [java, "-cp", jars[-1], "jadx.cli.JadxCLI"],
                        "jadx (bundled jre)",
                    )

    cli_patterns = (
        os.path.join(home, "Downloads", "jadx-*", "bin", "jadx.bat"),
        os.path.join(home, "Downloads", "jadx-*", "bin", "jadx"),
        os.path.join(home, "jadx-*", "bin", "jadx.bat"),
        os.path.join(home, "jadx-*", "bin", "jadx"),
    )
    for pattern in cli_patterns:
        for candidate in sorted(glob.glob(pattern), reverse=True):
            prefix, label = find_tool([candidate])
            if prefix:
                return prefix, label
    return None, None


def find_tool(candidates):
    for c in candidates:
        if os.path.sep not in c:
            if shutil.which(c):
                return [c], c
            continue
        if not os.path.exists(c):
            continue
        if c.lower().endswith(".jar"):
            return ["java", "-jar", c], os.path.basename(c)
        return [c], os.path.basename(c)
    return None, None



# ===========================================================================

class ScanResult:
    __slots__ = (
        "urls", "domains", "ips", "emails", "exts", "secrets", "files_scanned",
        "metadata", "permissions", "components", "sdks", "inventory", "security",
        "entropy", "crypto", "signals",
    )
    def __init__(self):
        self.urls = set()
        self.domains = set()
        self.ips = set()
        self.emails = set()
        self.exts = set()
        self.secrets = []
        self.files_scanned = 0
        self.metadata = {}
        self.permissions = set()
        self.components = []
        self.sdks = {}
        self.inventory = {}
        self.security = {}
        self.entropy = {}
        self.crypto = {}
        self.signals = {}

    def merge(self, other):
        self.urls |= other.urls
        self.domains |= other.domains
        self.ips |= other.ips
        self.emails |= other.emails
        self.exts |= other.exts
        self.secrets.extend(other.secrets)
        self.files_scanned += other.files_scanned
        self.metadata.update(other.metadata)
        self.permissions |= other.permissions
        self.components.extend(other.components)
        for sdk, markers in other.sdks.items():
            self.sdks.setdefault(sdk, set()).update(markers)
        self.inventory.update(other.inventory)
        self.security.update(other.security)
        for token, payload in other.entropy.items():
            self.entropy.setdefault(token, payload)
        for name, count in other.crypto.items():
            self.crypto[name] = self.crypto.get(name, 0) + count
        for name, count in other.signals.items():
            self.signals[name] = self.signals.get(name, 0) + count



def scan_text(content, rel_path, deep=True):
    r = ScanResult()
    r.files_scanned = 1

    for m in URL_RE.findall(content):
        r.urls.add(m)
    for m in DOMAIN_RE.findall(content):
        r.domains.add(m)
    for m in IPV4_RE.findall(content):
        r.ips.add(m)
    for m in IPV6_RE.findall(content):
        r.ips.add(m)
    for m in EMAIL_RE.findall(content):
        r.emails.add(m)
    for m in EXT_RE.findall(content):
        r.exts.add(m.lower())

    for name, pat in SECRET_PATTERNS.items():
        for hit in pat.findall(content):
            val = hit if isinstance(hit, str) else (hit[0] if hit else "")
            if val:
                r.secrets.append((name, val, rel_path))

    for match in SDK_RE.finditer(content):
        sdk = SDK_LOOKUP.get(match.group(0).lower())
        if sdk:
            r.sdks.setdefault(sdk, set()).add(match.group(0).lower())

    for match in CRYPTO_RE.finditer(content):
        name = CRYPTO_LOOKUP.get(match.group(0).lower())
        if name:
            r.crypto[name] = r.crypto.get(name, 0) + 1

    for match in SIGNAL_RE.finditer(content):
        name = SIGNAL_LOOKUP.get(match.group(0).lower())
        if name:
            r.signals[name] = r.signals.get(name, 0) + 1

    if not deep:
        return r

    candidates = 0
    for match in ENTROPY_RE.finditer(content):
        token = match.group(0)
        candidates += 1
        if candidates > 250:
            break
        if token in r.entropy or len(set(token)) < 8:
            continue
        if not (any(c.isdigit() for c in token) and any(c.isalpha() for c in token)):
            continue
        entropy = shannon_entropy(token)
        if entropy >= ENTROPY_THRESHOLD:
            r.entropy[token] = (round(entropy, 2), rel_path)
    return r



def collect_apk_inventory(path):
    inv = {
        "apk_size": os.path.getsize(path), "entries": 0, "uncompressed": 0,
        "dex_count": 0, "dex_bytes": 0, "so_count": 0, "abis": [],
        "so_sample": [], "assets": 0, "res": 0, "signature_files": [],
        "largest": [],
    }
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        inv["entries"] = len(infos)
        total = 0
        largest = []
        abis = set()
        so_files = []
        for info in infos:
            name = info.filename
            low = name.lower()
            size = info.file_size
            total += size
            largest.append((size, name))
            if low.endswith(".dex"):
                inv["dex_count"] += 1
                inv["dex_bytes"] += size
            elif low.endswith(".so"):
                inv["so_count"] += 1
                parts = name.split("/")
                if len(parts) > 2 and parts[0] == "lib":
                    abis.add(parts[1])
                if len(so_files) < 8:
                    so_files.append(name)
            elif name.startswith("assets/"):
                inv["assets"] += 1
            elif name.startswith("res/"):
                inv["res"] += 1
            if name.startswith("META-INF/"):
                tail = low.rsplit(".", 1)[-1]
                if tail in ("rsa", "dsa", "ec", "sf") or low.endswith("manifest.mf"):
                    inv["signature_files"].append(name)
        inv["uncompressed"] = total
        inv["largest"] = sorted(largest, reverse=True)[:8]
        inv["abis"] = sorted(abis)
        inv["so_sample"] = so_files
    return inv



def group_urls_by_host(urls):
    hosts = {}
    params = {}
    for url in urls:
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        entry = hosts.setdefault(host, {"count": 0, "schemes": set(), "paths": set()})
        entry["count"] += 1
        entry["schemes"].add((parts.scheme or "").lower())
        entry["paths"].add((parts.path or "/") or "/")
        for key, _value in parse_qsl(parts.query, keep_blank_values=True):
            if key:
                params[key] = params.get(key, 0) + 1
    return hosts, params



def fmt_eta(seconds):
    if seconds is None or seconds < 0 or seconds != seconds:
        return "—"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    return f"{seconds // 60}m {seconds % 60:02d}s"


def fmt_bytes(count):
    value = float(count)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{count} B"


