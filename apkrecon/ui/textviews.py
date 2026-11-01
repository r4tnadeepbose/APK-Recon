"""Result text views: insertion, filtering, copy and reference content."""

import os
import platform
import re
import tkinter as tk
import webbrowser

from ..androguard_support import HAS_ANDROGUARD
from ..config import (
    APKTOOL_CANDIDATES, JADX_CANDIDATES, PALETTE, REFERENCE_LINKS, SIGNAL_MARKERS,
)
from ..scanner import find_tool


class TextViewsMixin:
    # ---------------- Reference / environment ----------------
    def _cheatsheet_items(self):
        items = [
            ("▸ OWASP & ANDROID SECURITY", "hdr", None),
            ("MASVS — mobile application security verification standard", "link",
             REFERENCE_LINKS["MASVS"]),
            ("MASTG — mobile application security testing guide", "link",
             REFERENCE_LINKS["MASTG"]),
            ("OWASP Mobile Top 10", "link", REFERENCE_LINKS["OWASP Mobile Top 10"]),
            ("Android security tips", "link", REFERENCE_LINKS["Android security tips"]),
            ("Network security config", "link", REFERENCE_LINKS["Network security config"]),
            ("APK signature scheme", "link", REFERENCE_LINKS["APK signature scheme"]),
            ("Play Integrity API", "link", REFERENCE_LINKS["Play Integrity API"]),
            ("▸ QUICK COMMANDS", "hdr", None),
            ("jadx -d out app.apk", "cmdnote", "decompile java/kotlin sources"),
            ("jadx --deobf -d out app.apk", "cmdnote", "decompile with deobfuscation"),
            ("apktool d app.apk -o out", "cmdnote", "decode smali + resources"),
            ("apksigner verify --print-certs app.apk", "cmdnote", "inspect signing chain"),
            ("aapt dump badging app.apk", "cmdnote", "package, version, sdk info"),
            ("keytool -printcert -jarfile app.apk", "cmdnote", "certificate details"),
            ("adb shell pm path com.example", "cmdnote", "installed apk path"),
            ("grep -R \"http\" out/", "cmdnote", "endpoint sweep"),
            ("▸ SECRET HUNTING", "hdr", None),
            ("AIza[0-9A-Za-z_-]{35}", "cmdnote", "google api key"),
            ("AKIA[0-9A-Z]{16}", "cmdnote", "aws access key id"),
            ("sk_live_…", "cmdnote", "stripe live secret"),
            ("eyJ…", "cmdnote", "json web token"),
            ("-----BEGIN PRIVATE KEY-----", "cmdnote", "embedded private key"),
            ("firebaseio.com", "cmdnote", "firebase realtime database"),
            ("▸ SEVERITY MODEL", "hdr", None),
            ("CRITICAL  +28", "sevnote", "live credentials, private keys, debug signing"),
            ("HIGH      +14", "sevnote", "debuggable builds, exported components, risky data"),
            ("MEDIUM    +6", "sevnote", "cleartext traffic, weak crypto, backup enabled"),
            ("LOW       +2", "sevnote", "hygiene issues and informational exposure"),
            ("INFO       0", "sevnote", "context that does not change risk"),
            ("▸ WORKFLOW", "hdr", None),
            ("1. load apk → analyze → review findings", "bullet", None),
            ("2. confirm each secret manually before reporting", "bullet", None),
            ("3. export markdown/html for the engagement record", "bullet", None),
            ("4. export json, rescan a new build, then COMPARE the baseline", "bullet", None),
        ]
        return items

    def _environment_items(self):
        items = [("▸ RUNTIME", "hdr", None)]
        items.append((f"Python: {platform.python_version()}", "kv", None))
        items.append((f"Tk: {tk.TkVersion}", "kv", None))
        items.append((f"OS: {platform.platform()}", "kv", None))
        items.append((f"Working dir: {os.getcwd()}", "kv", None))
        items.append((f"Settings: {self._settings_path()}", "kv", None))
        items.append((f"Decompile dir: {self.decompile_dir}", "kv", None))
        items.append(("▸ CAPABILITIES", "hdr", None))

        if HAS_ANDROGUARD:
            try:
                from importlib.metadata import version as package_version
                ag_version = package_version("androguard")
            except Exception:
                ag_version = "installed"
            items.append((f"androguard: {ag_version}", "kv", None))
        else:
            items.append(("androguard: not installed (pip install androguard)", "kv", None))

        jadx_override = self.tool_paths.get("jadx_path")
        apktool_override = self.tool_paths.get("apktool_path")
        jadx = find_tool(([jadx_override] if jadx_override else []) + JADX_CANDIDATES)
        apktool = find_tool(([apktool_override] if apktool_override else []) + APKTOOL_CANDIDATES)
        items.append((f"jadx: {jadx[1]}" if jadx[1] else "jadx: not found", "kv", None))
        items.append((f"apktool: {apktool[1]}" if apktool[1] else "apktool: not found", "kv", None))
        items.append((f"Engine: {self.engine_var.get()} · workers {self.workers_var.get()}", "kv", None))
        items.append(("▸ GET THE TOOLS", "hdr", None))
        items.append(("jadx", "link", REFERENCE_LINKS["jadx"]))
        items.append(("apktool", "link", REFERENCE_LINKS["apktool"]))
        items.append(("androguard", "link", REFERENCE_LINKS["androguard"]))
        items.append(("MASVS", "link", REFERENCE_LINKS["MASVS"]))
        return items

    # ---------------- Text helpers ----------------
    def _insert_item(self, widget, key, item):
        text, kind, extra = item
        start = widget.index("insert")

        if kind == "hdr":
            widget.insert("insert", text + "\n", "hdr")
        elif kind == "kv":
            label, sep, value = text.partition(":")
            if sep:
                widget.insert("insert", label + ":", "muted")
                widget.insert("insert", value + "\n", "bright")
            else:
                widget.insert("insert", text + "\n", "norm")
        elif kind == "secret":
            widget.insert("insert", "  " + text, "norm")
            if extra:
                widget.insert("insert", "   ‹" + extra + "›", "muted")
            widget.insert("insert", "\n")
        elif kind == "url":
            widget.insert("insert", text + "\n")
            scheme = text.split("://", 1)[0] + "://" if "://" in text else ""
            if scheme:
                widget.tag_add(
                    "warn" if scheme == "http://" else "accent",
                    start, f"{start}+{len(scheme)}c",
                )
        elif kind == "perm":
            risk = (extra or {}).get("severity") if isinstance(extra, dict) else None
            label = (extra or {}).get("label") if isinstance(extra, dict) else ""
            head = text.rsplit(".", 1)[0] + "." if "." in text else ""
            tag = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med",
                   "LOW": "low"}.get(risk, "bright")
            widget.insert("insert", head, "muted")
            widget.insert("insert", text[len(head):], tag)
            if label:
                widget.insert("insert", "  · " + label, "muted")
            widget.insert("insert", "\n")
        elif kind == "finding":
            detail = (extra or {})
            severity = detail.get("severity", "INFO")
            tag = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med",
                   "LOW": "low"}.get(severity, "info")
            widget.insert("insert", f"{severity:<9}", tag)
            widget.insert("insert", text, "bright")
            if detail.get("detail"):
                widget.insert("insert", "  —  " + detail["detail"], "muted")
            widget.insert("insert", "\n")
        elif kind == "comp":
            detail = extra or {}
            kind_name = text.split(":", 1)[0]
            widget.insert("insert", kind_name + ":", "muted")
            widget.insert("insert", text.split(":", 1)[1], "bright")
            if detail.get("exported"):
                widget.insert("insert", "   EXPORTED", "warn")
            if detail.get("permission"):
                widget.insert("insert", "   perm=" + detail["permission"], "muted")
            widget.insert("insert", "\n")
        elif kind == "sdk":
            widget.insert("insert", text, "accent")
            if extra:
                widget.insert("insert", "   " + extra, "muted")
            widget.insert("insert", "\n")
        elif kind == "entropy":
            score, fpath = extra
            tag = "high" if score >= 4.7 else "warn"
            widget.insert("insert", f"{score:>5.2f}  ", tag)
            token = text if len(text) <= 140 else text[:137] + "…"
            widget.insert("insert", token, "bright")
            if fpath:
                widget.insert("insert", "   ‹" + fpath + "›", "muted")
            widget.insert("insert", "\n")
        elif kind == "searchhit":
            widget.insert("insert", f"[{extra}] ", "accent")
            widget.insert("insert", text + "\n", "norm")
        elif kind == "link":
            tag = f"link{self._link_seq}"
            self._link_seq += 1
            widget.tag_configure(tag, foreground=PALETTE["accent"], underline=True)
            widget.insert("insert", text, tag)
            if extra:
                widget.insert("insert", "   " + extra, "muted")
            widget.insert("insert", "\n")
            widget.tag_bind(tag, "<Button-1>", lambda _e, u=extra: webbrowser.open(u))
            widget.tag_bind(tag, "<Enter>",
                            lambda _e, w=widget: w.configure(cursor="hand2"))
            widget.tag_bind(tag, "<Leave>",
                            lambda _e, w=widget: w.configure(cursor="xterm"))
        elif kind == "ref":
            widget.insert("insert", "  " + text + "\n", "muted")
        elif kind == "bullet":
            widget.insert("insert", "  · ", "accent")
            widget.insert("insert", text + "\n", "norm")
        elif kind == "cmdnote":
            widget.insert("insert", "  " + text, "bright")
            if extra:
                widget.insert("insert", "   — " + extra, "muted")
            widget.insert("insert", "\n")
        elif kind == "sevnote":
            severity = text.split()[0] if text else ""
            widget.insert("insert", severity, {
                "CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med",
                "LOW": "low", "INFO": "info",
            }.get(severity, "norm"))
            rest = text[len(severity):]
            widget.insert("insert", rest, "muted")
            if extra:
                widget.insert("insert", "   — " + extra, "muted")
            widget.insert("insert", "\n")
        elif kind == "statusline":
            tag = {"PASS": "pass", "REVIEW": "review",
                   "WARN": "crit"}.get(extra, "norm")
            widget.insert("insert", f"{str(extra):<8}", tag)
            widget.insert("insert", text + "\n", "muted")
        elif kind == "evidence":
            widget.insert("insert", "          ↳ ", "muted")
            widget.insert("insert", text + "\n", "evid")
        elif kind == "para":
            widget.insert("insert", text + "\n", "muted")
        elif kind == "note":
            widget.insert("insert", "// " + text + "\n", "empty")
        elif kind in ("pass", "review", "accent"):
            widget.insert("insert", text + "\n", kind)
        else:
            widget.insert("insert", text + "\n", "norm")

    def _apply_filter(self, *args):
        query = self.search_var.get().strip()
        use_regex = self.regex_var.get()
        pattern = None
        if use_regex and query:
            try:
                pattern = re.compile(query, re.IGNORECASE)
            except re.error:
                self._status("Invalid regular expression in filter.")
                pattern = None
                query = ""
        lowered = query.lower()

        def matches(text):
            if not query:
                return True
            if pattern is not None:
                return bool(pattern.search(text))
            if use_regex:
                return True
            return lowered in text.lower()

        for key, widget in self.text_widgets.items():
            if key == "log":
                continue
            widget.delete("1.0", tk.END)
            if key == "search":
                if not query:
                    shown = [("type a filter query above to search every view", "note", None)]
                else:
                    shown = []
                    for other, items in self._raw.items():
                        if other in ("search", "log"):
                            continue
                        for item in items:
                            if item[1] == "hdr":
                                continue
                            if matches(item[0]):
                                shown.append((item[0], "searchhit", other))
                    if not shown:
                        shown = [(f'no matches for "{query}"', "note", None)]
                for item in shown:
                    self._insert_item(widget, key, item)
                hits = sum(1 for item in shown if item[1] == "searchhit")
                self._counts["search"] = hits
                if "search" in self.nav_rows:
                    self.nav_rows["search"][3].configure(text=str(hits))
                    self._paint_nav()
                if self.active_tab == "search":
                    self.view_count.configure(text=str(hits))
                continue

            items = self._raw.get(key, [])
            shown = [it for it in items if matches(it[0])]
            if not shown:
                if query:
                    message = f'// no matches for "{query}"'
                elif self.running:
                    message = "// scanning in progress…"
                else:
                    message = "// no records — load a package and run analyze"
                widget.insert(tk.END, message + "\n", "empty")
                continue
            for item in shown:
                self._insert_item(widget, key, item)

    def _schedule_filter(self, *args):
        job = getattr(self, "_filter_job", None)
        if job:
            try:
                self.root.after_cancel(job)
            except tk.TclError:
                pass
        self._filter_job = self.root.after(120, self._apply_filter)

    def clear_filter(self):
        self.search_var.set("")
        job = getattr(self, "_filter_job", None)
        if job:
            try:
                self.root.after_cancel(job)
            except tk.TclError:
                pass
        self._filter_job = None
        self._apply_filter()

    def copy_current(self):
        if self.active_tab == "dashboard":
            summary = (
                f"APK-Recon · {os.path.basename(self.current_apk_path or '')}\n"
                f"risk {self.risk_score}/100 ({self.risk_grade}) · "
                f"{len(self.findings)} findings\n"
                + "\n".join(f"[{f['severity']}] {f['title']} — {f.get('detail', '')}"
                            for f in self.findings)
            )
            self.root.clipboard_clear()
            self.root.clipboard_append(summary)
            self._status("Dashboard summary copied.")
            return
        widget = self.text_widgets.get(self.active_tab)
        if not widget:
            return
        content = widget.get("1.0", tk.END).strip("\n")
        if not content:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self._status(f"Copied {len(content.splitlines())} line(s) from {self.active_tab}.")

    def copy_line(self, widget):
        try:
            index = widget.index("current linestart")
            line = widget.get(index, f"{index} lineend")
        except tk.TclError:
            return
        if not line.strip():
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(line)
        self._status("Line copied to clipboard.")
