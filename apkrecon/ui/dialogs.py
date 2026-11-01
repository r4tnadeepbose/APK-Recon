"""Configuration, scan-setup and how-to dialogs."""

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ..androguard_support import HAS_ANDROGUARD
from ..config import (
    APKTOOL_CANDIDATES, JADX_CANDIDATES, PALETTE,
)
from ..scanner import find_tool


class DialogsMixin:
    # ---------------- Configuration dialog ----------------
    def _pick_tool(self, variable):
        path = filedialog.askopenfilename(
            title="Select executable",
            filetypes=[("Executables", "*.bat *.exe *.jar *.cmd"), ("All files", "*.*")],
        )
        if path:
            variable.set(path)

    def open_settings(self):
        existing = getattr(self, "_settings_win", None)
        if existing is not None and existing.winfo_exists():
            existing.lift()
            existing.focus_force()
            return

        win = tk.Toplevel(self.root)
        self._settings_win = win
        win.title("APKRecon · configuration")
        win.configure(bg=PALETTE["bg"])
        win.geometry("780x520")
        win.transient(self.root)
        win.resizable(False, False)

        panel = tk.Frame(
            win, bg=PALETTE["surface"],
            highlightthickness=1, highlightbackground=PALETTE["border"],
        )
        panel.pack(fill="both", expand=True, padx=18, pady=18)
        inner = tk.Frame(panel, bg=PALETTE["surface"])
        inner.pack(fill="both", expand=True, padx=18, pady=16)

        tk.Label(inner, text="CONFIGURATION", bg=PALETTE["surface"],
                 fg=PALETTE["text_bright"], font=self.f_bold_md).pack(anchor="w")
        tk.Label(inner, text="tool paths and scan defaults · stored next to the app",
                 bg=PALETTE["surface"], fg=PALETTE["muted"],
                 font=self.f_xs).pack(anchor="w", pady=(2, 16))

        jadx_var = tk.StringVar(value=self.tool_paths.get("jadx_path", ""))
        apktool_var = tk.StringVar(value=self.tool_paths.get("apktool_path", ""))
        for label, variable in (("JADX PATH", jadx_var), ("APKTOOL PATH", apktool_var)):
            row = tk.Frame(inner, bg=PALETTE["surface"])
            row.pack(fill="x", pady=5)
            tk.Label(row, text=label, width=13, anchor="w", bg=PALETTE["surface"],
                     fg=PALETTE["muted"], font=self.f_xs).pack(side="left")
            entry = self._entry(row, variable)
            entry.pack(side="left", fill="x", expand=True, ipady=5)
            self._button(row, "BROWSE",
                         lambda v=variable: self._pick_tool(v)).pack(side="left", padx=(8, 0))

        defaults = tk.Frame(inner, bg=PALETTE["surface"])
        defaults.pack(fill="x", pady=(16, 0))
        for text, variable in (("Fast mode", self.fast_mode_var),
                               ("Reuse cache", self.reuse_var)):
            tk.Checkbutton(
                defaults, text=text, variable=variable, bg=PALETTE["surface"],
                fg=PALETTE["text"], activebackground=PALETTE["surface"],
                activeforeground=PALETTE["accent"], selectcolor=PALETTE["input"],
                font=self.f_sm, bd=0, highlightthickness=0, cursor="hand2",
            ).pack(side="left", padx=(0, 16))
        tk.Label(defaults, text="ENGINE", bg=PALETTE["surface"],
                 fg=PALETTE["muted"], font=self.f_xs).pack(side="left", padx=(8, 6))
        ttk.Combobox(
            defaults, textvariable=self.engine_var,
            values=["auto", "dex-only", "jadx", "apktool"],
            width=9, state="readonly", style="Dark.TCombobox", font=self.f_sm,
        ).pack(side="left")
        tk.Label(defaults, text="WORKERS", bg=PALETTE["surface"],
                 fg=PALETTE["muted"], font=self.f_xs).pack(side="left", padx=(16, 6))
        ttk.Spinbox(
            defaults, from_=1, to=64, textvariable=self.workers_var,
            width=4, style="Dark.TSpinbox", font=self.f_sm,
        ).pack(side="left")

        tk.Label(
            inner,
            text=f"settings file: {self._settings_path()}",
            bg=PALETTE["surface"], fg=PALETTE["muted"], font=self.f_xs,
        ).pack(anchor="w", pady=(14, 0))

        auto_row = tk.Frame(inner, bg=PALETTE["surface"])
        auto_row.pack(fill="x", pady=(6, 0))
        for text, variable in (
            ("Auto-open HTML report after each scan", self.auto_html_var),
            ("Deep string scan (entropy)", self.deep_var),
        ):
            tk.Checkbutton(
                auto_row, text=text, variable=variable, bg=PALETTE["surface"],
                fg=PALETTE["text"], activebackground=PALETTE["surface"],
                activeforeground=PALETTE["accent"], selectcolor=PALETTE["input"],
                font=self.f_sm, bd=0, highlightthickness=0, cursor="hand2",
            ).pack(side="left", padx=(0, 20))

        setup_row = tk.Frame(inner, bg=PALETTE["surface"])
        setup_row.pack(fill="x", pady=(4, 0))
        tk.Checkbutton(
            setup_row, text="Ask for scan setup (engine chooser) before each scan",
            variable=self.ask_scan_var, bg=PALETTE["surface"],
            fg=PALETTE["text"], activebackground=PALETTE["surface"],
            activeforeground=PALETTE["accent"], selectcolor=PALETTE["input"],
            font=self.f_sm, bd=0, highlightthickness=0, cursor="hand2",
        ).pack(side="left")

        buttons = tk.Frame(inner, bg=PALETTE["surface"])
        buttons.pack(side="bottom", fill="x", pady=(12, 0))

        def save():
            self.tool_paths["jadx_path"] = jadx_var.get().strip()
            self.tool_paths["apktool_path"] = apktool_var.get().strip()
            self._save_settings()
            self._raw["environment"] = self._environment_items()
            self._apply_filter()
            self._status("Configuration saved.")
            self._log("configuration saved", "accent")
            win.destroy()

        self._button(buttons, "CLEAR SCAN HISTORY", self.clear_history).pack(side="left")
        self._button(buttons, "SAVE CONFIG", save, primary=True).pack(side="right")
        self._button(buttons, "CLOSE", win.destroy).pack(side="right", padx=(0, 8))

    # ---------------- Scan setup (engine chooser) ----------------
    def _engine_snapshot(self):
        jadx_prefix, jadx_label = find_tool(
            ([self.tool_paths["jadx_path"]] if self.tool_paths.get("jadx_path") else [])
            + JADX_CANDIDATES
        )
        apktool_prefix, apktool_label = find_tool(
            ([self.tool_paths["apktool_path"]] if self.tool_paths.get("apktool_path") else [])
            + APKTOOL_CANDIDATES
        )
        ag_version = ""
        if HAS_ANDROGUARD:
            try:
                from importlib.metadata import version as package_version
                ag_version = package_version("androguard")
            except Exception:
                ag_version = "installed"
        return {
            "auto": (True, "fastest available engine"),
            "dex-only": (HAS_ANDROGUARD,
                         f"androguard {ag_version}" if HAS_ANDROGUARD
                         else "androguard not installed"),
            "jadx": (bool(jadx_prefix), jadx_label or "jadx not found"),
            "apktool": (bool(apktool_prefix), apktool_label or "apktool not found"),
        }

    def ask_scan_setup(self):
        snapshot = self._engine_snapshot()
        current = self.engine_var.get()
        if current not in snapshot or not snapshot[current][0]:
            current = "auto"

        win = tk.Toplevel(self.root)
        win.title("APKRecon · scan setup")
        win.configure(bg=PALETTE["bg"])
        win.geometry("760x600")
        win.transient(self.root)
        win.resizable(False, False)

        panel = tk.Frame(win, bg=PALETTE["surface"],
                         highlightthickness=1, highlightbackground=PALETTE["border"])
        panel.pack(fill="both", expand=True, padx=18, pady=18)
        inner = tk.Frame(panel, bg=PALETTE["surface"])
        inner.pack(fill="both", expand=True, padx=20, pady=16)

        tk.Label(inner, text="SCAN SETUP", bg=PALETTE["surface"],
                 fg=PALETTE["text_bright"], font=self.f_bold_md).pack(anchor="w")
        tk.Label(
            inner,
            text=f"target: {os.path.basename(self.current_apk_path or '—')} · choose how to extract",
            bg=PALETTE["surface"], fg=PALETTE["muted"], font=self.f_xs,
        ).pack(anchor="w", pady=(2, 14))

        engine_var = tk.StringVar(value=current)
        descriptions = {
            "auto": "auto-pick the fastest available engine (recommended)",
            "dex-only": "scan raw DEX strings with androguard — fastest, no sources",
            "jadx": "decompile Java/Kotlin sources — best coverage, slower",
            "apktool": "decode smali + resources — manifest/resource focus, slower",
        }
        for key in ("auto", "dex-only", "jadx", "apktool"):
            available, detail = snapshot[key]
            row = tk.Frame(inner, bg=PALETTE["surface"], cursor="hand2")
            row.pack(fill="x", pady=3)
            radio = tk.Radiobutton(
                row, text="", variable=engine_var, value=key,
                bg=PALETTE["surface"], activebackground=PALETTE["surface"],
                selectcolor=PALETTE["input"], bd=0, highlightthickness=0,
                cursor="hand2",
                state="normal" if available else "disabled",
            )
            radio.pack(side="left")
            body = tk.Frame(row, bg=PALETTE["surface"])
            body.pack(side="left", fill="x", expand=True)
            title = key if key != "auto" else "auto (recommended)"
            tk.Label(body, text=title, bg=PALETTE["surface"], fg=PALETTE["text_bright"],
                     font=self.f_bold, anchor="w").pack(anchor="w")
            tk.Label(body, text=descriptions[key], bg=PALETTE["surface"],
                     fg=PALETTE["muted"], font=self.f_xs, anchor="w").pack(anchor="w")
            detail_color = PALETTE["accent"] if available else PALETTE["critical"]
            detail_text = detail if available else "unavailable — " + detail
            tk.Label(row, text=detail_text, bg=PALETTE["surface"], fg=detail_color,
                     font=self.f_xs, anchor="e").pack(side="right", padx=6)

        options = tk.Frame(inner, bg=PALETTE["surface"])
        options.pack(fill="x", pady=(16, 0))
        fast_var = tk.BooleanVar(value=self.fast_mode_var.get())
        reuse_var = tk.BooleanVar(value=self.reuse_var.get())
        deep_var = tk.BooleanVar(value=self.deep_var.get())
        workers_var = tk.IntVar(value=self.workers_var.get())
        for text, variable in (("Fast mode", fast_var), ("Reuse cache", reuse_var),
                               ("Deep strings", deep_var)):
            tk.Checkbutton(
                options, text=text, variable=variable, bg=PALETTE["surface"],
                fg=PALETTE["text"], activebackground=PALETTE["surface"],
                activeforeground=PALETTE["accent"], selectcolor=PALETTE["input"],
                font=self.f_sm, bd=0, highlightthickness=0, cursor="hand2",
            ).pack(side="left", padx=(0, 18))
        tk.Label(options, text="WORKERS", bg=PALETTE["surface"], fg=PALETTE["muted"],
                 font=self.f_xs).pack(side="left", padx=(4, 6))
        ttk.Spinbox(options, from_=1, to=64, textvariable=workers_var,
                    width=4, style="Dark.TSpinbox", font=self.f_sm).pack(side="left")

        slowest = [key for key in ("dex-only", "jadx", "apktool")
                   if snapshot[key][0]]
        note = ("no decompiler detected — install androguard, jadx or apktool; "
                "a cached decompile may still be reused")
        if not slowest:
            tk.Label(inner, text=note, bg=PALETTE["surface"],
                     fg=PALETTE["critical"], font=self.f_xs,
                     wraplength=660, justify="left").pack(anchor="w", pady=(10, 0))

        dont_ask = tk.BooleanVar(value=False)
        tk.Checkbutton(
            inner, text="Don't show this again (re-enable in CONFIG)",
            variable=dont_ask, bg=PALETTE["surface"], fg=PALETTE["muted"],
            activebackground=PALETTE["surface"], activeforeground=PALETTE["accent"],
            selectcolor=PALETTE["input"], font=self.f_xs, bd=0,
            highlightthickness=0, cursor="hand2",
        ).pack(anchor="w", pady=(14, 0))

        buttons = tk.Frame(inner, bg=PALETTE["surface"])
        buttons.pack(side="bottom", fill="x")
        result = {"start": False}

        def start():
            self.engine_var.set(engine_var.get())
            self.fast_mode_var.set(bool(fast_var.get()))
            self.reuse_var.set(bool(reuse_var.get()))
            self.deep_var.set(bool(deep_var.get()))
            try:
                self.workers_var.set(max(1, min(64, int(workers_var.get()))))
            except (tk.TclError, ValueError):
                pass
            if dont_ask.get():
                self.ask_scan_var.set(False)
            self._save_settings()
            self._log(
                f"scan setup · engine={engine_var.get()} "
                f"deep={'on' if self.deep_var.get() else 'off'}",
                "muted",
            )
            result["start"] = True
            win.destroy()

        self._button(buttons, "START SCAN", start, danger=True).pack(side="right")
        self._button(buttons, "CANCEL", win.destroy).pack(side="right", padx=(0, 8))

        win.grab_set()
        self.root.wait_window(win)
        return result["start"]

    # ---------------- How-to dialog ----------------
    def open_help(self):
        existing = getattr(self, "_help_win", None)
        if existing is not None and existing.winfo_exists():
            existing.lift()
            existing.focus_force()
            return

        win = tk.Toplevel(self.root)
        self._help_win = win
        win.title("APKRecon · how to use")
        win.configure(bg=PALETTE["bg"])
        win.geometry("780x640")
        win.transient(self.root)
        win.resizable(False, False)

        panel = tk.Frame(
            win, bg=PALETTE["surface"],
            highlightthickness=1, highlightbackground=PALETTE["border"],
        )
        panel.pack(fill="both", expand=True, padx=18, pady=18)
        inner = tk.Frame(panel, bg=PALETTE["surface"])
        inner.pack(fill="both", expand=True, padx=20, pady=16)

        tk.Label(inner, text="HOW TO USE APKRECON", bg=PALETTE["surface"],
                 fg=PALETTE["text_bright"], font=self.f_bold_md).pack(anchor="w")
        tk.Label(inner, text="a 30-second orientation · everything runs locally",
                 bg=PALETTE["surface"], fg=PALETTE["muted"],
                 font=self.f_xs).pack(anchor="w", pady=(2, 14))

        steps = (
            ("1", "LOAD A TARGET",
             "Click BROWSE (red) and pick an .apk. Once loaded, BROWSE returns to "
             "normal and ANALYZE turns red."),
            ("2", "ANALYZE",
             "ANALYZE opens SCAN SETUP where you choose the extraction engine "
             "(auto / dex-only / jadx / apktool), then turns light red while the scan "
             "runs. The dashboard pipeline shows ARCHIVE → MANIFEST → EXTRACT → SCAN → "
             "RISK with progress and ETA, and the Activity log streams details."),
            ("3", "REVIEW",
             "FINDINGS lists severity plus evidence samples (actual values and files). "
             "MASVS maps posture per category; HOSTS shows endpoint hygiene; ENTROPY "
             "surfaces suspicious high-entropy strings."),
            ("4", "REPORT / COMPARE",
             "EXPORT writes JSON, Markdown or a self-contained HTML report. After each "
             "scan a clickable HTML report opens in your browser automatically; toggle "
             "Auto HTML off to stop that. HTML / Ctrl+H regenerates it any time. Scan a "
             "newer build and hit COMPARE to diff it against an earlier export."),
        )
        for number, title, text in steps:
            row = tk.Frame(inner, bg=PALETTE["surface"])
            row.pack(fill="x", pady=(0, 10))
            tk.Label(row, text=number, width=3, anchor="nw", bg=PALETTE["surface"],
                     fg=PALETTE["accent"], font=self.f_bold_md).pack(
                         side="left", anchor="n", padx=(0, 4),
                     )
            body = tk.Frame(row, bg=PALETTE["surface"])
            body.pack(side="left", fill="x", expand=True)
            tk.Label(body, text=title, bg=PALETTE["surface"], fg=PALETTE["text_bright"],
                     font=self.f_bold, anchor="w").pack(anchor="w")
            tk.Label(body, text=text, bg=PALETTE["surface"], fg=PALETTE["muted"],
                     font=self.f_sm, anchor="w", justify="left",
                     wraplength=640).pack(anchor="w", pady=(2, 0))

        tk.Frame(inner, bg=PALETTE["border_soft"], height=1).pack(fill="x", pady=(6, 10))
        tk.Label(inner, text="SHORTCUTS", bg=PALETTE["surface"],
                 fg=PALETTE["accent_soft"], font=self.f_bold).pack(anchor="w", pady=(0, 6))

        shortcuts = (
            ("Ctrl+O", "open apk"), ("F5", "run analysis"),
            ("Ctrl+F", "focus filter"), ("Ctrl+E", "export"),
            ("Ctrl+B", "compare baseline"), ("Ctrl+D", "dashboard"),
            ("Ctrl+H", "html report"), ("Ctrl+L", "clear filter"),
            ("F1", "this guide"),
        )
        grid = tk.Frame(inner, bg=PALETTE["surface"])
        grid.pack(fill="x")
        for index, (key, description) in enumerate(shortcuts):
            column = index % 2
            row_index = index // 2
            cell = tk.Frame(grid, bg=PALETTE["surface"])
            cell.grid(row=row_index, column=column, sticky="w", padx=(0, 30), pady=2)
            tk.Label(cell, text=key, width=8, anchor="w", bg=PALETTE["surface"],
                     fg=PALETTE["accent"], font=self.f_sm).pack(side="left")
            tk.Label(cell, text=description, anchor="w", bg=PALETTE["surface"],
                     fg=PALETTE["muted"], font=self.f_xs).pack(side="left")

        tk.Label(
            inner,
            text="filter supports plain text or regex (toggle .*) · double-click any line to copy it",
            bg=PALETTE["surface"], fg=PALETTE["muted"], font=self.f_xs,
        ).pack(anchor="w", pady=(12, 0))

        buttons = tk.Frame(inner, bg=PALETTE["surface"])
        buttons.pack(side="bottom", fill="x", pady=(14, 0))

        def open_cheatsheet():
            win.destroy()
            self._switch_tab("cheatsheet")

        self._button(buttons, "OPEN CHEAT SHEET", open_cheatsheet, primary=True).pack(side="right")
        self._button(buttons, "GOT IT", win.destroy).pack(side="right", padx=(0, 8))
