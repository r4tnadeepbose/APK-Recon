"""Exports: HTML / Markdown / JSON / CSV / text reports."""

import csv
import datetime
import html as html_lib
import json
import os
import pathlib
import re
import webbrowser
from tkinter import filedialog, messagebox

from ..config import DANGEROUS_PERMISSIONS, PALETTE, REPORTS_DIR, SEVERITY_ORDER
from ..scanner import fmt_bytes
from ..templates_loader import load_template


class ReportsMixin:
    # ---------------- Export ----------------
    def _write_html_report(self):
        base = os.path.splitext(os.path.basename(self.current_apk_path or "apkrecon"))[0]
        safe = re.sub(r"[^A-Za-z0-9._-]+", "-", base).strip("-._") or "apkrecon"
        directory = REPORTS_DIR
        os.makedirs(directory, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = os.path.join(directory, f"{safe}-{stamp}.html")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self._build_report_html())
        return path

    def open_html_report(self, auto=False):
        r = self.result
        if not (r.urls or r.secrets or r.metadata or r.inventory or r.files_scanned):
            if not auto:
                messagebox.showinfo("Nothing to show", "Run analysis first.")
            return
        try:
            path = self._write_html_report()
            webbrowser.open(pathlib.Path(path).resolve().as_uri())
            self.last_report_path = path
            prefix = "Auto-opened " if auto else "Opened "
            self._status(prefix + f"HTML report · {os.path.basename(path)}")
            self._log(f"html report → {path}", "accent")
        except Exception as e:
            if auto:
                self._log(f"html report failed: {e}", "crit")
            else:
                self._error("HTML report failed", str(e))

    def _maybe_auto_report(self):
        if not self.auto_html_var.get():
            return
        if not (self.findings or self.result.urls or self.result.inventory):
            return
        self.open_html_report(auto=True)

    def export_results(self):
        r = self.result
        if not (r.urls or r.domains or r.ips or r.emails or r.exts or r.secrets
                or r.metadata or r.inventory):
            messagebox.showinfo("Nothing to export", "Run analysis first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialdir=self.last_dir or os.getcwd(),
            initialfile=os.path.splitext(
                os.path.basename(self.current_apk_path or "apkrecon")
            )[0] + "-report",
            filetypes=[
                ("JSON", "*.json"), ("HTML report", "*.html"),
                ("Markdown report", "*.md"), ("CSV", "*.csv"), ("Text", "*.txt"),
            ],
        )
        if not path:
            return
        ext = os.path.splitext(path)[1].lower()
        try:
            if ext == ".json":
                deep_links = sorted(
                    u for u in r.urls
                    if not u.lower().startswith(
                        ("http://", "https://", "ftp://", "ftps://", "ws://", "wss://")
                    )
                )
                data = {
                    "apk": os.path.basename(self.current_apk_path or ""),
                    "generated": datetime.datetime.now().isoformat(timespec="seconds"),
                    "urls":    sorted(r.urls),
                    "deep_links": deep_links,
                    "domains": sorted(r.domains),
                    "ips":      sorted(r.ips),
                    "emails":   sorted(r.emails),
                    "exts":     sorted(r.exts),
                    "files_scanned": r.files_scanned,
                    "metadata": r.metadata,
                    "permissions": sorted(r.permissions),
                    "components": sorted(set(r.components)),
                    "secrets": [{"type": c, "value": v, "file": f} for c, v, f in r.secrets],
                    "sdks": {name: sorted(markers) for name, markers in r.sdks.items()},
                    "inventory": r.inventory,
                    "security": r.security,
                    "findings": self.findings,
                    "risk": {"score": self.risk_score, "grade": self.risk_grade},
                }
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            elif ext == ".md":
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self._build_report_markdown())
            elif ext == ".html":
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self._build_report_html())
            elif ext == ".csv":
                with open(path, "w", encoding="utf-8", newline="") as f:
                    w = csv.writer(f)
                    w.writerow(["category", "value", "file"])
                    for u in sorted(r.urls):    w.writerow(["url", u, ""])
                    for d in sorted(r.domains): w.writerow(["domain", d, ""])
                    for i in sorted(r.ips):     w.writerow(["ip", i, ""])
                    for e in sorted(r.emails):  w.writerow(["email", e, ""])
                    for x in sorted(r.exts):    w.writerow(["ext", x, ""])
                    for c, v, fpath in r.secrets:
                        w.writerow([c, v, fpath])
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("== URLs ==\n" + "\n".join(sorted(r.urls)) + "\n\n")
                    f.write("== Domains ==\n" + "\n".join(sorted(r.domains)) + "\n\n")
                    f.write("== IPs ==\n" + "\n".join(sorted(r.ips)) + "\n\n")
                    f.write("== Emails ==\n" + "\n".join(sorted(r.emails)) + "\n\n")
                    f.write("== Extensions ==\n" + "\n".join(sorted(r.exts)) + "\n\n")
                    f.write("== Secrets ==\n")
                    for c, v, fp in r.secrets:
                        f.write(f"[{c}] {v} ({fp})\n")
            self._status(f"Exported to {os.path.basename(path)}")
            self._log(f"exported {os.path.basename(path)}", "accent")
            self.last_dir = os.path.dirname(path)
            self._save_settings()
        except Exception as e:
            self._error("Export failed", str(e))

    def _build_report_markdown(self):
        r = self.result
        lines = []
        apk_name = os.path.basename(self.current_apk_path or "unknown.apk")
        lines.append(f"# APK-Recon report — {apk_name}")
        lines.append("")
        lines.append(f"- Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"- Risk score: **{self.risk_score}/100** (grade {self.risk_grade})")
        lines.append(f"- Findings: {len(self.findings)}")
        lines.append(f"- Files scanned: {r.files_scanned}")
        lines.append(f"- Endpoints: {len(r.urls)} · Domains: {len(r.domains)} · Secrets: {len(r.secrets)}")
        lines.append("")

        lines.append("## Metadata")
        lines.append("")
        for key, value in r.metadata.items():
            lines.append(f"- **{key}:** `{value}`")
        lines.append("")

        if self.findings:
            lines.append("## Findings")
            lines.append("")
            lines.append("| Severity | Finding | Detail |")
            lines.append("| --- | --- | --- |")
            for finding in self.findings:
                title = finding["title"].replace("|", "\\|")
                detail = finding.get("detail", "").replace("|", "\\|")
                evidence = " · ".join(finding.get("evidence") or []).replace("|", "\\|")
                if evidence:
                    detail = f"{detail} — evidence: {evidence}" if detail else f"evidence: {evidence}"
                lines.append(f"| {finding['severity']} | {title} | {detail} |")
            lines.append("")

        if r.secrets:
            lines.append("## Secrets")
            lines.append("")
            for category, value, fpath in sorted(r.secrets):
                lines.append(f"- **{category}** — `{value}`  \n  _in `{fpath}`_")
            lines.append("")

        if r.urls:
            lines.append("## Endpoints")
            lines.append("")
            for url in sorted(r.urls):
                lines.append(f"- `{url}`")
            lines.append("")

        if r.permissions:
            lines.append("## Permissions")
            lines.append("")
            for permission in sorted(r.permissions):
                lines.append(f"- `{permission}`")
            lines.append("")

        if r.components:
            lines.append("## Components")
            lines.append("")
            for component in sorted(set(r.components)):
                lines.append(f"- `{component}`")
            lines.append("")

        if r.sdks:
            lines.append("## Third-party SDKs")
            lines.append("")
            for sdk in sorted(r.sdks):
                lines.append(f"- **{sdk}** — {', '.join(sorted(r.sdks[sdk]))}")
            lines.append("")

        if r.inventory:
            inv = r.inventory
            lines.append("## Inventory")
            lines.append("")
            lines.append(f"- APK size: {fmt_bytes(inv['apk_size'])}")
            lines.append(f"- ZIP entries: {inv['entries']}")
            lines.append(f"- DEX files: {inv['dex_count']} ({fmt_bytes(inv['dex_bytes'])})")
            lines.append(f"- Native libraries: {inv['so_count']} ({', '.join(inv['abis']) or 'no ABIs'})")
            lines.append("")

        return "\n".join(lines) + "\n"

    @staticmethod
    def _html_finding_row(finding):
        escape = html_lib.escape
        severity = finding["severity"]
        evidence = "".join(
            f'<div class="ev">↳ {escape(sample)}</div>'
            for sample in (finding.get("evidence") or [])
        )
        return (
            f'<tr><td class="sev {severity.lower()}">{severity}</td>'
            f'<td>{escape(finding["title"])}{evidence}</td>'
            f'<td class="muted">{escape(finding.get("detail", ""))}</td></tr>'
        )

    def _build_report_html(self):
        r = self.result
        esc = html_lib.escape
        sev_counts = {
            severity: sum(1 for f in self.findings if f["severity"] == severity)
            for severity in SEVERITY_ORDER
        }
        risk_color = (
            PALETTE["accent"] if self.risk_score >= 75 else
            PALETTE["amber"] if self.risk_score >= 50 else PALETTE["critical"]
        )
        findings_rows = "".join(self._html_finding_row(f) for f in self.findings)
        masvs_cards = "".join(
            f"<div class=\"card masvs-{c['status'].lower()}\">"
            f"<div class=\"row\"><strong>{esc(c['id'])}</strong>"
            f"<span class=\"tag {c['status'].lower()}\">{c['status']}</span></div>"
            f"<div class=\"muted small\">{esc(c['title'])} — {esc(c['summary'])}</div>"
            f"<ul>{''.join(f'<li>{esc(e)}</li>' for e in c['evidence'])}</ul>"
            f"<div class=\"links\">{''.join(f'<a href=\"{esc(url)}\" target=\"_blank\">{esc(label)}</a>' for label, url in c.get('links', []))}</div>"
            f"</div>"
            for c in self.masvs_report
        )
        secret_rows = "".join(
            f"<tr><td>{esc(category)}</td><td class=\"mono\">{esc(value)}</td>"
            f"<td class=\"muted\">{esc(fpath)}</td></tr>"
            for category, value, fpath in sorted(r.secrets)[:500]
        )
        permission_rows = "".join(
            f"<tr><td class=\"mono\">{esc(permission)}</td>"
            f"<td class=\"sev {DANGEROUS_PERMISSIONS.get(permission.rsplit('.', 1)[-1], ('', ''))[0].lower()}\">"
            f"{DANGEROUS_PERMISSIONS.get(permission.rsplit('.', 1)[-1], ('—',))[0]}</td></tr>"
            for permission in sorted(r.permissions)
        )
        host_rows = "".join(
            f"<tr><td class=\"mono\">{esc(host)}</td><td>{count}</td></tr>"
            for host, count in sorted(
                ((h, len([u for u in r.urls if h in u])) for h in r.domains), key=lambda x: -x[1]
            )[:50]
        )
        sdk_rows = "".join(
            f"<tr><td>{esc(name)}</td><td class=\"muted\">{esc(', '.join(sorted(markers)))}</td></tr>"
            for name, markers in sorted(r.sdks.items())
        )
        endpoint_items = "".join(
            f"<li class=\"mono\">{esc(url)}</li>" for url in sorted(r.urls)[:500]
        )
        meta_rows = "".join(
            f"<tr><td class=\"muted\">{esc(key)}</td><td class=\"mono\">{esc(str(value))}</td></tr>"
            for key, value in r.metadata.items()
        )
        inv = r.inventory
        inventory_rows = ""
        if inv:
            inventory_rows = "".join(
                f"<tr><td class=\"muted\">{esc(label)}</td><td>{value}</td></tr>"
                for label, value in (
                    ("APK size", fmt_bytes(inv.get("apk_size", 0))),
                    ("ZIP entries", inv.get("entries", 0)),
                    ("DEX files", f"{inv.get('dex_count', 0)} ({fmt_bytes(inv.get('dex_bytes', 0))})"),
                    ("Native libraries", inv.get("so_count", 0)),
                    ("ABIs", ", ".join(inv.get("abis", [])) or "—"),
                    ("Assets", inv.get("assets", 0)),
                    ("Resources", inv.get("res", 0)),
                    ("Signature files", len(inv.get("signature_files", []))),
                )
            )

        css = load_template("report.css")
        css = css.replace("__RISK__", risk_color).replace(
            "__PCT__", f"{min(100, max(0, self.risk_score)):.1f}"
        )
        apk_name = esc(os.path.basename(self.current_apk_path or "unknown.apk"))
        body = f"""
<h1>APK-RECON · {apk_name}</h1>
<div class="sub">generated {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} ·
local static analysis · risk grade {esc(self.risk_grade)}</div>

<h2>Risk overview</h2>
<div class="grid">
  <div class="card" style="display:flex;align-items:center;gap:18px">
    <div class="ring"><div>{self.risk_score}</div></div>
    <div>
      <div class="muted small">RISK SCORE / 100</div>
      <div style="font-size:20px;color:var(--bright)">grade {esc(self.risk_grade)}</div>
      <div class="muted small">{len(self.findings)} findings ·
      {len(r.urls)} endpoints · {len(r.secrets)} secrets</div>
    </div>
  </div>
  <div class="card">
    <div class="row"><strong>Severity distribution</strong></div>
    <table>
      {''.join(f'<tr><td class="sev {s.lower()}">{s}</td><td>{sev_counts[s]}</td></tr>' for s in SEVERITY_ORDER)}
    </table>
  </div>
</div>

<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Detail</th></tr></thead>
<tbody>{findings_rows or '<tr><td colspan="3" class="muted">no findings</td></tr>'}</tbody></table>

<h2>MASVS posture</h2>
<div class="grid">{masvs_cards}</div>

<h2>Secrets</h2>
<table><thead><tr><th>Category</th><th>Value</th><th>Source</th></tr></thead>
<tbody>{secret_rows or '<tr><td colspan="3" class="muted">none detected</td></tr>'}</tbody></table>

<h2>Endpoints</h2>
<details open><summary>{len(r.urls)} endpoints</summary><ul>{endpoint_items}</ul></details>

<h2>Hosts</h2>
<table><thead><tr><th>Host</th><th>References</th></tr></thead><tbody>{host_rows}</tbody></table>

<h2>Permissions</h2>
<table><thead><tr><th>Permission</th><th>Risk</th></tr></thead>
<tbody>{permission_rows or '<tr><td colspan="2" class="muted">none</td></tr>'}</tbody></table>

<h2>SDKs</h2>
<table><thead><tr><th>SDK</th><th>Evidence</th></tr></thead>
<tbody>{sdk_rows or '<tr><td colspan="2" class="muted">none detected</td></tr>'}</tbody></table>

<h2>Inventory</h2>
<table><tbody>{inventory_rows}</tbody></table>

<h2>Metadata</h2>
<table><tbody>{meta_rows}</tbody></table>

<footer>APK-Recon · offline recon report · verify every secret manually before use</footer>
"""
        return (
            load_template("report.html")
            .replace("__TITLE__", f"APK-Recon · {apk_name}")
            .replace("__CSS__", css)
            .replace("__BODY__", body)
        )
