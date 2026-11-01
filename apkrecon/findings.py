"""Risk scoring and OWASP MASVS posture mapping."""

from .config import (
    DANGEROUS_PERMISSIONS, MASVS_CATEGORIES, REFERENCE_LINKS,
    SECRET_SEVERITY, SEVERITY_ORDER, SEVERITY_WEIGHT,
)

def compute_findings(result):
    findings = []

    def add(severity, title, detail="", group="misc", evidence=None):
        samples = []
        for value in (evidence or []):
            text = str(value).strip()
            if not text:
                continue
            if len(text) > 120:
                text = text[:117] + "…"
            if text not in samples:
                samples.append(text)
            if len(samples) >= 5:
                break
        findings.append({
            "severity": severity, "title": title,
            "detail": detail, "group": group, "evidence": samples,
        })

    secret_cats = {}
    secret_samples = {}
    for category, value, path in result.secrets:
        if category == "Deep Link":
            continue
        secret_cats.setdefault(category, set()).add(value)
        bucket = secret_samples.setdefault(category, [])
        sample = f"{value}   ‹{path}›"
        if sample not in bucket and len(bucket) < 4:
            bucket.append(sample)
    for category in sorted(secret_cats):
        add(
            SECRET_SEVERITY.get(category, "LOW"),
            f"Hardcoded {category}",
            f"{len(secret_cats[category])} unique value(s)",
            "secrets",
            secret_samples.get(category),
        )

    cleartext = sorted({u for u in result.urls if u.lower().startswith("http://")})
    if cleartext:
        add("MEDIUM", "Cleartext HTTP endpoints",
            f"{len(cleartext)} endpoint(s) served over http://", "network",
            cleartext[:3])

    security = result.security or {}
    if security.get("debuggable"):
        add("HIGH", "Application is debuggable",
            "android:debuggable allows runtime attach and data access", "manifest",
            ['AndroidManifest.xml → android:debuggable="true"'])
    if security.get("allow_backup") is True:
        add("MEDIUM", "Application backup enabled",
            "android:allowBackup exposes private data via backup channels", "manifest",
            ['AndroidManifest.xml → android:allowBackup="true"'])
    if security.get("cleartext") is True:
        add("MEDIUM", "Manifest permits cleartext traffic",
            "android:usesCleartextTraffic=true", "manifest",
            ['AndroidManifest.xml → android:usesCleartextTraffic="true"'])
    if security.get("test_only"):
        add("LOW", "Test-only build flag", "android:testOnly=true", "manifest",
            ['AndroidManifest.xml → android:testOnly="true"'])
    if security.get("network_config"):
        add("INFO", "Network security config present",
            str(security["network_config"]), "manifest",
            [str(security["network_config"])])

    exported = security.get("exported") or []
    if exported:
        kinds = {}
        for comp in exported:
            kinds[comp["kind"]] = kinds.get(comp["kind"], 0) + 1
        add(
            "HIGH" if any(k in ("receiver", "provider") for k in kinds) else "MEDIUM",
            "Exported components",
            ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items())),
            "manifest",
            [f'{comp["kind"]}: {comp["name"]}' for comp in exported[:5]],
        )

    perm_groups = {}
    for permission in result.permissions:
        segment = permission.rsplit(".", 1)[-1]
        if segment in DANGEROUS_PERMISSIONS:
            severity, _label = DANGEROUS_PERMISSIONS[segment]
            perm_groups.setdefault(severity, []).append(permission)
    for severity, names in perm_groups.items():
        add(severity, f"{len(names)} risky permission(s)",
            ", ".join(sorted(name.rsplit(".", 1)[-1] for name in names)),
            "permissions", sorted(names))

    try:
        target = int(str(result.metadata.get("Target SDK", "")).strip())
    except ValueError:
        target = None
    if target is not None:
        if target < 28:
            add("HIGH", "Outdated target SDK", f"targetSdkVersion={target}", "manifest",
                [f"AndroidManifest.xml → targetSdkVersion={target}"])
        elif target < 31:
            add("MEDIUM", "Dated target SDK", f"targetSdkVersion={target}", "manifest",
                [f"AndroidManifest.xml → targetSdkVersion={target}"])

    signature = security.get("signature") or {}
    if signature.get("available"):
        certs = signature.get("certs") or []
        if not certs and not signature.get("v1_meta"):
            add("CRITICAL", "APK is not signed", "no signing certificate found", "signature",
                ["META-INF: no v1/v2/v3 signature material"])
        if signature.get("debug"):
            add("CRITICAL", "Signed with debug certificate",
                "development keystore detected", "signature",
                [f"{cert.get('subject', '')}  (sha256 {cert.get('sha256', '')[:16]}…)"
                 for cert in certs if "Debug" in cert.get("subject", "")] or
                ["certificate subject contains 'Android Debug'"])
        for cert in certs:
            if cert.get("expired"):
                add("HIGH", "Signing certificate expired",
                    cert.get("subject", ""), "signature",
                    [f"{cert.get('subject', '')} · notAfter {cert.get('not_after', '?')}"])
        if certs and not (signature.get("v2") or signature.get("v3")):
            add("MEDIUM", "No v2/v3 signature scheme",
                "only JAR (v1) signing detected", "signature",
                [f"v1={bool(signature.get('v1_meta'))} v2={bool(signature.get('v2'))} "
                 f"v3={bool(signature.get('v3'))}"])

    if result.sdks:
        add("INFO", "Third-party SDKs", ", ".join(sorted(result.sdks)), "sdks",
            [f"{sdk}: {', '.join(sorted(result.sdks[sdk]))}"
             for sdk in sorted(result.sdks)[:4]])
    weak_crypto = sorted(result.crypto)
    if weak_crypto:
        add("MEDIUM", "Weak cryptography markers",
            ", ".join(weak_crypto), "crypto",
            [f"{name} × {result.crypto[name]} reference(s)" for name in weak_crypto])
    if result.signals.get("Dynamic code loading"):
        add("LOW", "Dynamic code loading",
            f"{result.signals['Dynamic code loading']} reference(s)", "signals",
            ["DexClassLoader / PathClassLoader / InMemoryDexClassLoader"])
    if result.entropy:
        top_tokens = sorted(result.entropy.items(), key=lambda item: -item[1][0])[:2]
        add("INFO", "High-entropy strings",
            f"{len(result.entropy)} candidate(s) — verify manually", "entropy",
            [f"{token}  (entropy {score:.2f})" for token, (score, _path) in top_tokens])
    if not result.secrets:
        add("INFO", "No hardcoded secrets detected",
            "regex catalog returned no matches", "positive")

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["title"]))

    penalties = {"secrets": 0, "permissions": 0, "other": 0}
    for finding in findings:
        group = finding["group"]
        bucket = "secrets" if group == "secrets" else "permissions" if group == "permissions" else "other"
        penalties[bucket] += SEVERITY_WEIGHT[finding["severity"]]
    score = max(0, 100 - (
        min(45, penalties["secrets"]) +
        min(25, penalties["permissions"]) +
        penalties["other"]
    ))
    grade = (
        "A" if score >= 90 else
        "B" if score >= 75 else
        "C" if score >= 60 else
        "D" if score >= 40 else "F"
    )
    return findings, score, grade



MASVS_LINKS = {
    "MASVS-STORAGE": [("MASVS", REFERENCE_LINKS["MASVS"]),
                      ("MASTG tests", REFERENCE_LINKS["MASTG"])],
    "MASVS-CRYPTO": [("MASVS", REFERENCE_LINKS["MASVS"]),
                     ("Android security tips", REFERENCE_LINKS["Android security tips"])],
    "MASVS-AUTH": [("MASVS", REFERENCE_LINKS["MASVS"]),
                   ("MASVS/MASTG", REFERENCE_LINKS["MASTG"])],
    "MASVS-NETWORK": [("MASVS", REFERENCE_LINKS["MASVS"]),
                      ("Network security config", REFERENCE_LINKS["Network security config"])],
    "MASVS-PLATFORM": [("MASVS", REFERENCE_LINKS["MASVS"]),
                       ("Android security tips", REFERENCE_LINKS["Android security tips"])],
    "MASVS-CODE": [("MASVS", REFERENCE_LINKS["MASVS"]),
                   ("Android security tips", REFERENCE_LINKS["Android security tips"])],
    "MASVS-RESILIENCE": [("MASVS", REFERENCE_LINKS["MASVS"]),
                         ("APK signature scheme", REFERENCE_LINKS["APK signature scheme"])],
    "MASVS-PRIVACY": [("MASVS", REFERENCE_LINKS["MASVS"]),
                      ("Mobile Top 10", REFERENCE_LINKS["OWASP Mobile Top 10"])],
}


def compute_masvs(result, findings):
    def group(name):
        return [f for f in findings if f["group"] == name]

    def severe(name, levels):
        return [f for f in group(name) if f["severity"] in levels]

    security = result.security or {}
    signature = security.get("signature") or {}
    exported = security.get("exported") or []
    categories = []

    def add(cat_id, title, summary, status, evidence):
        categories.append({
            "id": cat_id, "title": title, "summary": summary,
            "status": status, "evidence": evidence,
            "links": MASVS_LINKS.get(cat_id, [("MASVS", REFERENCE_LINKS["MASVS"])]),
        })

    # Storage
    storage_issues = severe("secrets", {"CRITICAL", "HIGH"})
    evidence = [f"{f['title']} ({f['severity']})" for f in storage_issues[:5]]
    if security.get("allow_backup") is True:
        evidence.append("android:allowBackup=true")
    status = "WARN" if storage_issues else (
        "REVIEW" if security.get("allow_backup") is True else "PASS")
    add(*MASVS_CATEGORIES[0], status, evidence or ["no high-severity hardcoded secrets"])

    # Crypto
    weak = sorted(result.crypto)
    status = "WARN" if weak else "PASS"
    evidence = [f"{name} markers: {result.crypto[name]} reference(s)" for name in weak]
    add(*MASVS_CATEGORIES[1], status, evidence or ["no weak crypto markers observed"])

    # Auth
    auth_cats = {"Password (heuristic)", "Basic Auth", "Generic Bearer", "JWT Token",
                 "Private key (generic)", "Mnemonic (heuristic)"}
    auth_hits = sorted(cat for cat in {s[0] for s in result.secrets} if cat in auth_cats)
    status = "WARN" if auth_hits else "PASS"
    evidence = [f"hardcoded {name}" for name in auth_hits]
    if result.signals.get("Biometric auth"):
        evidence.append("biometric authentication APIs referenced")
    add(*MASVS_CATEGORIES[2], status, evidence or ["no hardcoded auth material"])

    # Network
    cleartext = sorted({u for u in result.urls if u.lower().startswith("http://")})
    evidence = []
    if cleartext:
        evidence.append(f"{len(cleartext)} cleartext http:// endpoint(s)")
    if security.get("cleartext") is True:
        evidence.append("android:usesCleartextTraffic=true")
    if security.get("network_config"):
        evidence.append(f"network security config: {security['network_config']}")
    if result.signals.get("Certificate pinning"):
        evidence.append("certificate pinning references detected")
    if cleartext or security.get("cleartext") is True:
        status = "WARN"
    elif not security.get("network_config") and not result.signals.get("Certificate pinning"):
        status = "REVIEW"
    else:
        status = "PASS"
    add(*MASVS_CATEGORIES[3], status, evidence or ["no cleartext endpoints; transport hardening present"])

    # Platform
    evidence = []
    if exported:
        kinds = {}
        for comp in exported:
            kinds[comp["kind"]] = kinds.get(comp["kind"], 0) + 1
        evidence.append("exported: " + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())))
    deep_links = {u for u in result.urls
                  if "://" in u and not u.lower().startswith(
                      ("http://", "https://", "ftp://", "ftps://", "ws://", "wss://"))}
    if deep_links:
        evidence.append(f"{len(deep_links)} deep link route(s) handled")
    if result.signals.get("WebView bridge"):
        evidence.append("WebView JavaScript bridges referenced")
    if exported:
        status = "WARN"
    elif len(deep_links) > 15:
        status = "REVIEW"
    else:
        status = "PASS"
    add(*MASVS_CATEGORIES[4], status, evidence or ["no exported components detected"])

    # Code
    evidence = []
    status = "PASS"
    if security.get("debuggable"):
        evidence.append("android:debuggable=true")
        status = "WARN"
    if security.get("test_only"):
        evidence.append("android:testOnly=true")
        status = "WARN" if status == "PASS" else status
    try:
        target = int(str(result.metadata.get("Target SDK", "")))
    except ValueError:
        target = None
    if target is not None:
        evidence.append(f"targetSdkVersion={target}")
        if target < 28:
            status = "WARN"
        elif target < 31 and status == "PASS":
            status = "REVIEW"
    if result.signals.get("Dynamic code loading"):
        evidence.append("dynamic code loading APIs referenced")
        if status == "PASS":
            status = "REVIEW"
    add(*MASVS_CATEGORIES[5], status, evidence or ["no debug or build hardening issues detected"])

    # Resilience
    evidence = []
    status = "PASS"
    if signature.get("debug"):
        evidence.append("signed with debug certificate")
        status = "WARN"
    if signature.get("available") and not (signature.get("v2") or signature.get("v3")):
        evidence.append("v2/v3 signature scheme absent")
        if status == "PASS":
            status = "REVIEW"
    for cert in signature.get("certs") or []:
        if cert.get("expired"):
            evidence.append("signing certificate expired")
            status = "WARN"
    if result.signals.get("Root detection"):
        evidence.append("root detection references present")
    elif status == "PASS":
        evidence.append("no root or anti-tamper references observed")
        status = "REVIEW"
    add(*MASVS_CATEGORIES[6], status, evidence or ["signing and tamper checks look sane"])

    # Privacy
    evidence = []
    status = "PASS"
    if result.sdks:
        evidence.append("tracking SDKs: " + ", ".join(sorted(result.sdks)))
        status = "REVIEW"
    privacy_perms = sorted(
        p.rsplit(".", 1)[-1] for p in result.permissions
        if p.rsplit(".", 1)[-1] in {
            "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "READ_CONTACTS",
            "READ_SMS", "RECORD_AUDIO", "CAMERA",
        }
    )
    if privacy_perms:
        evidence.append("sensitive permissions: " + ", ".join(privacy_perms))
        status = "REVIEW"
    if len(result.sdks) > 6:
        status = "WARN"
    if result.emails:
        evidence.append(f"{len(result.emails)} embedded email address(es)")
    add(*MASVS_CATEGORIES[7], status, evidence or ["no tracking or sensitive collection signals"])

    return categories


