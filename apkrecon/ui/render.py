"""Renderer: turns a ScanResult into the raw item lists for every view."""

import os
import re
from urllib.parse import urlsplit

from ..config import (
    DANGEROUS_PERMISSIONS, PALETTE, SECRET_SEVERITY, SEVERITY_ORDER, SIGNAL_MARKERS,
)
from ..findings import compute_findings, compute_masvs
from ..scanner import fmt_bytes, fmt_eta, group_urls_by_host


class RenderMixin:
    def _render(self):
        r = self.result
        security = r.security or {}
        signature = security.get("signature") or {}

        deep_links = set()
        plain_urls = set()
        for u in r.urls:
            low = u.lower()
            if low.startswith(("http://", "https://", "ftp://", "ftps://", "ws://", "wss://")):
                plain_urls.add(u)
            else:
                deep_links.add(u)

        grouped = {}
        for cat, val, fpath in r.secrets:
            grouped.setdefault(cat, set()).add((val, fpath))

        hosts, query_params = group_urls_by_host(plain_urls)
        findings, score, grade = compute_findings(r)
        self.findings = findings
        self.risk_score = score
        self.risk_grade = grade

        raw = {key: [] for key, _ in self.TABS}

        # -- overview ------------------------------------------------------
        raw["stats"].append(("▸ SESSION SUMMARY", "hdr", None))
        raw["stats"].append((f"APK: {os.path.basename(self.current_apk_path or '—')}", "kv", None))
        raw["stats"].append((f"Risk: {score} / 100   grade {grade}", "kv", None))
        raw["stats"].append((f"Findings: {len(findings)}", "kv", None))
        raw["stats"].append((f"Files scanned: {r.files_scanned}", "kv", None))
        raw["stats"].append((f"Endpoints: {len(plain_urls)}", "kv", None))
        raw["stats"].append((f"Hosts: {len(hosts)}", "kv", None))
        raw["stats"].append((f"Deep links: {len(deep_links)}", "kv", None))
        raw["stats"].append((f"Domains: {len(r.domains)}", "kv", None))
        raw["stats"].append((f"IPs: {len(r.ips)}", "kv", None))
        raw["stats"].append((f"Emails: {len(r.emails)}", "kv", None))
        raw["stats"].append((f"Extensions: {len(r.exts)}", "kv", None))
        raw["stats"].append((f"Secrets: {len(r.secrets)}", "kv", None))
        raw["stats"].append((f"SDKs: {len(r.sdks)}", "kv", None))
        raw["stats"].append((f"Entropy candidates: {len(r.entropy)}", "kv", None))
        raw["stats"].append((f"Signals: {len(r.signals)}", "kv", None))
        if grouped:
            raw["stats"].append(("▸ SECRET CATEGORIES", "hdr", None))
            for cat, items in sorted(grouped.items()):
                raw["stats"].append((f"{cat}: {len(items)}", "kv", None))

        # -- findings ------------------------------------------------------
        raw["findings"].append(("▸ RISK POSTURE", "hdr", None))
        raw["findings"].append((f"Score: {score} / 100   grade {grade}", "kv", None))
        raw["findings"].append((f"Total findings: {len(findings)}", "kv", None))
        for severity in SEVERITY_ORDER:
            count = sum(1 for f in findings if f["severity"] == severity)
            if count:
                raw["findings"].append((f"{severity.title()}: {count}", "kv", None))
        raw["findings"].append(("▸ FINDINGS", "hdr", None))
        if findings:
            for finding in findings:
                raw["findings"].append((finding["title"], "finding", finding))
                if finding["severity"] in ("CRITICAL", "HIGH", "MEDIUM"):
                    for sample in finding.get("evidence", [])[:4]:
                        raw["findings"].append((sample, "evidence", None))
        else:
            raw["findings"].append(("no findings recorded", "note", None))

        # -- MASVS ---------------------------------------------------------
        masvs = compute_masvs(r, findings)
        self.masvs_report = masvs
        raw["masvs"].append(("▸ OWASP MASVS", "hdr", None))
        raw["masvs"].append((
            "verification posture mapped from static evidence · open MASVS for full requirements",
            "note", None,
        ))
        for category in masvs:
            raw["masvs"].append((f"▸ {category['id']} · {category['title']}", "hdr", None))
            raw["masvs"].append((
                category["summary"], "statusline", category["status"],
            ))
            for evidence in category["evidence"]:
                raw["masvs"].append((evidence, "bullet", None))
            for label, url in category["links"]:
                raw["masvs"].append((label, "link", url))

        # -- entropy -------------------------------------------------------
        raw["entropy"].append(("▸ HIGH-ENTROPY CANDIDATES", "hdr", None))
        raw["entropy"].append((
            "heuristic string audit — confirm manually before treating as a credential",
            "note", None,
        ))
        if r.entropy:
            for token, (entropy_score, fpath) in sorted(
                r.entropy.items(), key=lambda item: -item[1][0]
            )[:300]:
                raw["entropy"].append((token, "entropy", (entropy_score, fpath)))
        else:
            raw["entropy"].append(("no high-entropy candidates above threshold", "note", None))

        # -- discovery -----------------------------------------------------
        for u in sorted(plain_urls):
            raw["urls"].append((u, "url", None))
        for dl in sorted(deep_links):
            raw["deeplink"].append((dl, "accent", None))
        for d in sorted(r.domains):
            raw["domains"].append((d, "norm", None))
        for i in sorted(r.ips):
            raw["ips"].append((i, "norm", None))
        for e in sorted(r.emails):
            raw["emails"].append((e, "norm", None))
        for x in sorted(r.exts):
            raw["exts"].append((x, "accent", None))

        # URL hygiene + path surface
        http_endpoints = sorted({u for u in plain_urls if u.lower().startswith("http://")})
        ip_hosts = set()
        odd_ports = set()
        idn_hosts = set()
        for url in plain_urls:
            try:
                parts = urlsplit(url)
            except ValueError:
                continue
            hostname = (parts.hostname or "").lower()
            if not hostname:
                continue
            if re.fullmatch(r"[0-9.]+", hostname):
                ip_hosts.add(hostname)
            if parts.port and parts.port not in (80, 443):
                odd_ports.add(hostname)
            if hostname.startswith("xn--") or "xn--" in hostname:
                idn_hosts.add(hostname)

        path_prefixes = {}
        for url in plain_urls:
            try:
                path = urlsplit(url).path
            except ValueError:
                continue
            segments = [segment for segment in path.split("/") if segment]
            prefix = "/".join(segments[:2]) or "/"
            path_prefixes[prefix] = path_prefixes.get(prefix, 0) + 1

        scheme_counts = {}
        for link in deep_links:
            scheme = link.split("://", 1)[0].lower() if "://" in link else "?"
            scheme_counts[scheme] = scheme_counts.get(scheme, 0) + 1

        raw["hosts"].append(("▸ URL HYGIENE", "hdr", None))
        raw["hosts"].append((f"Cleartext endpoints: {len(http_endpoints)}", "kv", None))
        raw["hosts"].append((f"IP-literal hosts: {len(ip_hosts)}", "kv", None))
        raw["hosts"].append((f"Non-standard ports: {len(odd_ports)}", "kv", None))
        raw["hosts"].append((f"Punycode hosts: {len(idn_hosts)}", "kv", None))
        raw["hosts"].append((f"Unique hosts: {len(hosts)}", "kv", None))
        if odd_ports:
            raw["hosts"].append(("hosts on odd ports: " + ", ".join(sorted(odd_ports)[:8]), "ref", None))
        if idn_hosts:
            raw["hosts"].append(("punycode hosts: " + ", ".join(sorted(idn_hosts)[:8]), "ref", None))

        raw["hosts"].append(("▸ PATH PREFIXES", "hdr", None))
        if path_prefixes:
            for prefix, count in sorted(path_prefixes.items(), key=lambda kv: (-kv[1], kv[0]))[:12]:
                raw["hosts"].append((f"{prefix}   ({count})", "kv", None))
        else:
            raw["hosts"].append(("no URL paths observed", "note", None))

        raw["hosts"].append(("▸ DEEP-LINK SCHEMES", "hdr", None))
        if scheme_counts:
            for scheme, count in sorted(scheme_counts.items(), key=lambda kv: (-kv[1], kv[0])):
                raw["hosts"].append((f"{scheme}://   ({count})", "kv", None))
        else:
            raw["hosts"].append(("no custom schemes observed", "note", None))

        raw["hosts"].append(("▸ QUERY PARAMETERS", "hdr", None))
        if query_params:
            for name, count in sorted(query_params.items(), key=lambda kv: (-kv[1], kv[0]))[:20]:
                raw["hosts"].append((f"{name}: {count} reference(s)", "kv", None))
        else:
            raw["hosts"].append(("no query parameters observed", "note", None))
        for host in sorted(hosts, key=lambda name: (-hosts[name]["count"], name)):
            entry = hosts[host]
            raw["hosts"].append((f"▸ {host}   ({entry['count']})", "hdr", None))
            raw["hosts"].append((f"schemes: {', '.join(sorted(entry['schemes']))}", "kv", None))
            paths = sorted(entry["paths"])
            for path in paths[:10]:
                raw["hosts"].append((path, "ref", None))
            if len(paths) > 10:
                raw["hosts"].append((f"+{len(paths) - 10} more path(s)", "note", None))
        if not hosts:
            raw["hosts"].append(("no HTTP hosts resolved", "note", None))

        for cat in sorted(grouped):
            raw["secrets"].append((f"▸ {cat.upper()}   ({len(grouped[cat])})", "hdr", None))
            for val, fpath in sorted(grouped[cat]):
                raw["secrets"].append((val, "secret", fpath))

        # -- checklist -----------------------------------------------------
        cleartext = any(u.lower().startswith("http://") for u in r.urls)
        checklist = [
            ("Secrets and API keys", not bool(r.secrets),
             f"{len(r.secrets)} potential secret(s) found" if r.secrets else "no secret material detected"),
            ("Network endpoints", not cleartext,
             "cleartext HTTP endpoint present" if cleartext
             else ("all endpoints use secure schemes" if r.urls else "no endpoints found")),
            ("Deep-link surface", not bool(deep_links),
             f"{len(deep_links)} deep link(s) found" if deep_links else "no deep links found"),
            ("Scan coverage", r.files_scanned > 0, f"{r.files_scanned} file(s) scanned"),
            ("Target SDK", r.metadata.get("Target SDK", "Unknown") not in ("Unknown", ""),
             f"target SDK {r.metadata.get('Target SDK', 'unknown')}"),
            ("Sensitive permissions",
             not any(p.rsplit(".", 1)[-1] in DANGEROUS_PERMISSIONS for p in r.permissions),
             "no high-impact permission detected" if not r.permissions
             else "review high-impact permissions"),
        ]
        if security:
            exported = security.get("exported") or []
            checklist.extend([
                ("Debuggable build", not security.get("debuggable"),
                 "android:debuggable=true" if security.get("debuggable") else "debug flag not set"),
                ("Backup posture", security.get("allow_backup") is not True,
                 "allowBackup enabled" if security.get("allow_backup") is True else "backup disabled"),
                ("Exported components", not exported,
                 f"{len(exported)} exported component(s)" if exported else "no exported components"),
            ])
        if signature.get("available"):
            modern = bool(signature.get("v2") or signature.get("v3"))
            checklist.append(("Signature scheme", modern,
                              "v2/v3 signing present" if modern else "JAR signing only"))
        for label, passed, detail in checklist:
            state = "PASS" if passed else "REVIEW"
            raw["checklist"].append(
                (f"{state:<7}{label} — {detail}", "pass" if passed else "review", None)
            )

        # -- metadata ------------------------------------------------------
        raw["metadata"].append(("▸ MANIFEST", "hdr", None))
        for key, value in r.metadata.items():
            raw["metadata"].append((f"{key}: {value}", "kv", None))
        if r.metadata:
            raw["metadata"].append((f"Permissions: {len(r.permissions)}", "kv", None))
            raw["metadata"].append((f"Components: {len(r.components)}", "kv", None))
        if security:
            raw["metadata"].append(("▸ MANIFEST FLAGS", "hdr", None))
            for label, key in (
                ("Debuggable", "debuggable"),
                ("Allow backup", "allow_backup"),
                ("Cleartext traffic", "cleartext"),
                ("Test only", "test_only"),
            ):
                value = security.get(key)
                if value is not None:
                    raw["metadata"].append((f"{label}: {'yes' if value else 'no'}", "kv", None))
            if security.get("network_config"):
                raw["metadata"].append((f"Network config: {security['network_config']}", "kv", None))
            raw["metadata"].append((f"Exported components: {len(security.get('exported') or [])}", "kv", None))
        if signature.get("available"):
            raw["metadata"].append(("▸ SIGNING", "hdr", None))
            raw["metadata"].append(("v1 (JAR): present" if signature.get("v1_meta") else "v1 (JAR): absent", "kv", None))
            raw["metadata"].append(("v2: verified" if signature.get("v2") else "v2: absent", "kv", None))
            raw["metadata"].append(("v3: verified" if signature.get("v3") else "v3: absent", "kv", None))
            if signature.get("debug"):
                raw["metadata"].append(("Debug certificate: YES", "kv", None))
            for cert in signature.get("certs") or []:
                raw["metadata"].append((f"Subject: {cert.get('subject', 'unknown')}", "kv", None))
                raw["metadata"].append((f"Issuer: {cert.get('issuer', 'unknown')}", "kv", None))
                if cert.get("sha256"):
                    raw["metadata"].append((f"SHA-256: {cert['sha256']}", "kv", None))
                validity = cert.get("not_after", "unknown")
                if cert.get("expired"):
                    validity += "  (expired)"
                raw["metadata"].append((f"Valid until: {validity}", "kv", None))

        # -- permissions ---------------------------------------------------
        def permission_rank(permission):
            segment = permission.rsplit(".", 1)[-1]
            risk = DANGEROUS_PERMISSIONS.get(segment)
            if not risk:
                return (1, len(SEVERITY_ORDER), permission)
            return (0, SEVERITY_ORDER.index(risk[0]), permission)

        for permission in sorted(r.permissions, key=permission_rank):
            segment = permission.rsplit(".", 1)[-1]
            risk = DANGEROUS_PERMISSIONS.get(segment)
            raw["permissions"].append((
                permission, "perm",
                {"severity": risk[0] if risk else None, "label": risk[1] if risk else ""},
            ))
        if not r.permissions:
            raw["permissions"].append(("no permissions declared", "note", None))

        # -- components ----------------------------------------------------
        details = security.get("components") or []
        if details:
            order = {"activity": 0, "service": 1, "receiver": 2, "provider": 3}
            for comp in sorted(details, key=lambda c: (order.get(c["kind"], 9), c["name"])):
                raw["components"].append((f"{comp['kind'].title()}: {comp['name']}", "comp", comp))
        else:
            for comp in sorted(set(r.components)):
                raw["components"].append((comp, "kv", None))
        if not details and not r.components:
            raw["components"].append(("no components listed", "note", None))

        # -- inventory -----------------------------------------------------
        inv = r.inventory or {}
        if inv:
            raw["inventory"].append(("▸ ARCHIVE", "hdr", None))
            raw["inventory"].append((f"APK size: {fmt_bytes(inv['apk_size'])} ({inv['apk_size']:,} bytes)", "kv", None))
            raw["inventory"].append((f"ZIP entries: {inv['entries']:,}", "kv", None))
            raw["inventory"].append((f"Uncompressed: {fmt_bytes(inv['uncompressed'])}", "kv", None))
            raw["inventory"].append((f"DEX files: {inv['dex_count']} ({fmt_bytes(inv['dex_bytes'])})", "kv", None))
            raw["inventory"].append((f"Native libraries: {inv['so_count']}", "kv", None))
            raw["inventory"].append((f"ABIs: {', '.join(inv['abis']) or '—'}", "kv", None))
            raw["inventory"].append((f"Assets: {inv['assets']:,}", "kv", None))
            raw["inventory"].append((f"Resources: {inv['res']:,}", "kv", None))
            raw["inventory"].append((f"V1 signature files: {len(inv['signature_files'])}", "kv", None))
            if inv["so_sample"]:
                raw["inventory"].append(("▸ NATIVE LIBRARIES", "hdr", None))
                for name in inv["so_sample"]:
                    raw["inventory"].append((name, "ref", None))
            if inv["signature_files"]:
                raw["inventory"].append(("▸ SIGNATURE FILES", "hdr", None))
                for name in inv["signature_files"]:
                    raw["inventory"].append((name, "ref", None))
            if inv["largest"]:
                raw["inventory"].append(("▸ LARGEST ENTRIES", "hdr", None))
                for size, name in inv["largest"]:
                    raw["inventory"].append((f"{fmt_bytes(size):>9}   {name}", "ref", None))
        else:
            raw["inventory"].append(("▸ ARCHIVE", "hdr", None))
            raw["inventory"].append(("no archive data — run analysis", "note", None))

        # -- sdks ----------------------------------------------------------
        raw["sdks"].append(("▸ DETECTED SDKS", "hdr", None))
        if r.sdks:
            for sdk in sorted(r.sdks):
                raw["sdks"].append((sdk, "sdk", ", ".join(sorted(r.sdks[sdk]))))
        else:
            raw["sdks"].append(("no known SDK signatures detected", "note", None))

        # -- signals -------------------------------------------------------
        raw["signals"].append(("▸ CRYPTOGRAPHIC MARKERS", "hdr", None))
        if r.crypto:
            for name in sorted(r.crypto):
                raw["signals"].append((f"{name}: {r.crypto[name]} reference(s)", "kv", None))
        else:
            raw["signals"].append(("no weak crypto markers observed", "note", None))
        raw["signals"].append(("▸ PLATFORM SIGNALS", "hdr", None))
        if r.signals:
            for name in sorted(r.signals):
                raw["signals"].append((f"{name}: {r.signals[name]} reference(s)", "kv", None))
        else:
            raw["signals"].append(("no platform hardening signals detected", "note", None))
        raw["signals"].append(("▸ DETECTION NOTES", "hdr", None))
        for name, markers in sorted(SIGNAL_MARKERS.items()):
            raw["signals"].append((
                f"{name}: {', '.join(markers)}", "ref", None,
            ))

        # -- scan history --------------------------------------------------
        raw["history"] = self._history_items()

        # -- cheat sheet / environment ------------------------------------
        raw["cheatsheet"] = self._cheatsheet_items()
        raw["environment"] = self._environment_items()

        # -- diff (persisted across renders) -------------------------------
        if self.diff_summary and self.diff_summary.get("lines"):
            raw["diff"] = list(self.diff_summary["lines"])
        else:
            raw["diff"].append(("▸ BASELINE COMPARISON", "hdr", None))
            raw["diff"].append(("load a previous JSON export with COMPARE to diff this scan", "note", None))

        self._raw = raw
        self._counts = {
            "dashboard": len(findings),
            "stats": len(plain_urls) + len(r.domains) + len(r.ips) + len(r.emails) + len(r.secrets),
            "findings": len(findings),
            "masvs": sum(1 for c in masvs if c["status"] != "PASS"),
            "urls": len(plain_urls),
            "hosts": len(hosts),
            "domains": len(r.domains),
            "ips": len(r.ips),
            "emails": len(r.emails),
            "exts": len(r.exts),
            "secrets": len(r.secrets),
            "entropy": len(r.entropy),
            "deeplink": len(deep_links),
            "signals": len(r.signals) + len(r.crypto),
            "checklist": len(checklist),
            "metadata": len(r.metadata),
            "permissions": len(r.permissions),
            "components": len(details) if details else len(set(r.components)),
            "inventory": inv.get("entries", 0),
            "sdks": len(r.sdks),
            "history": len(self.history),
            "diff": (self.diff_summary or {}).get("total", 0),
            "search": 0,
            "cheatsheet": 0,
            "environment": 0,
            "log": self.log_lines,
        }

        self.kpi_values["urls"].configure(text=str(len(plain_urls)))
        self.kpi_values["domains"].configure(text=str(len(r.domains)))
        self.kpi_values["secrets"].configure(text=str(len(r.secrets)))
        self.kpi_values["findings"].configure(text=str(len(findings)))
        risk_color = (
            PALETTE["accent"] if score >= 75 else
            PALETTE["amber"] if score >= 50 else PALETTE["critical"]
        )
        self.kpi_values["risk"].configure(text=f"{score} {grade}", fg=risk_color)

        signature = security.get("signature") or {}
        signed = bool(signature.get("certs") or signature.get("v2")
                      or signature.get("v3") or signature.get("v1_meta"))
        signed_label = ("DEBUG KEY" if signature.get("debug")
                        else "SIGNED" if signed else "UNSIGNED")
        self.chart_data = {
            "target": {
                "name": os.path.basename(self.current_apk_path or "—"),
                "package": r.metadata.get("Package", "—"),
                "version": r.metadata.get("Version", "—"),
                "min_sdk": r.metadata.get("Min SDK", "?"),
                "target_sdk": r.metadata.get("Target SDK", "?"),
                "size": (fmt_bytes(inv.get("apk_size", 0)) if inv else
                         r.metadata.get("File size", "—")),
                "signed": signed,
                "signed_label": signed_label,
                "debug": bool(signature.get("debug")),
                "engine": self.last_engine or self.engine_var.get(),
                "files": r.files_scanned,
                "dex": inv.get("dex_count", 0),
                "libs": inv.get("so_count", 0),
            },
            "top_findings": [
                (finding["title"], finding["severity"]) for finding in findings[:7]
            ],
            "severity": {
                severity: sum(1 for f in findings if f["severity"] == severity)
                for severity in SEVERITY_ORDER
            },
            "hosts": [
                (host, hosts[host]["count"])
                for host in sorted(hosts, key=lambda h: (-hosts[h]["count"], h))[:7]
            ],
            "secrets": [
                (category, len(items), SECRET_SEVERITY.get(category, "LOW"))
                for category, items in sorted(
                    grouped.items(), key=lambda kv: (-len(kv[1]), kv[0])
                )[:7]
            ],
            "masvs": [(c["id"].replace("MASVS-", ""), c["status"]) for c in masvs],
            "counts": {
                "endpoints": len(plain_urls),
                "hosts": len(hosts),
                "secrets": len(r.secrets),
                "findings": len(findings),
                "sdks": len(r.sdks),
                "entropy": len(r.entropy),
            },
            "phases": dict(self.phase_status),
            "running": self.running,
            "eta": self.eta_text,
            "progress": (self.progress_value, self.progress_max),
        }

        for key, (_row, _bar, _name, count) in self.nav_rows.items():
            count.configure(text=str(self._counts.get(key, 0)))
        self._paint_nav()

        self.view_count.configure(text=str(self._counts.get(self.active_tab, 0)))
        self._apply_filter()
        if self.active_tab == "dashboard":
            self._draw_dashboard()

    def _history_items(self):
        items = [("▸ RECENT SCANS", "hdr", None)]
        if not self.history:
            items.append(("no earlier scans recorded yet", "note", None))
            items.append(("run an analysis and the session will be logged here", "bullet", None))
            return items
        for entry in self.history[:40]:
            stamp = str(entry.get("time", "?"))[:19].replace("T", " ")
            grade = entry.get("grade", "—")
            risk = entry.get("risk", "—")
            items.append((f"▸ {stamp} · {entry.get('apk', 'unknown')}   "
                          f"risk {risk} {grade}", "hdr", None))
            engine = entry.get("engine", "?")
            duration = fmt_eta(entry.get("duration") or 0)
            items.append((f"engine: {engine} · duration {duration}", "kv", None))
            items.append((
                f"findings: {entry.get('findings', 0)} · "
                f"secrets: {entry.get('secrets', 0)} · "
                f"urls: {entry.get('urls', 0)} · "
                f"files: {entry.get('files', 0)}", "kv", None))
            package = entry.get("package") or "—"
            version = entry.get("version") or "—"
            items.append((f"package: {package} · version {version}", "kv", None))
            if entry.get("report"):
                items.append((str(entry["report"]), "ref", None))
        return items
