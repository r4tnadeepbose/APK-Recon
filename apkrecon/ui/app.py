"""Application shell: state, window construction, actions and diff."""

import datetime
import json
import os
import threading
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, ttk

from ..config import (
    DECOMPILE_DIR, HISTORY_PATH, PALETTE, SETTINGS_PATH, apply_theme,
)
from ..scanner import ScanResult
from .dashboard import DashboardMixin
from .dialogs import DialogsMixin
from .render import RenderMixin
from .reports import ReportsMixin
from .scan import ScanMixin
from .textviews import TextViewsMixin
from .theme import ThemeMixin

class APKReconGUI(ThemeMixin, DashboardMixin, TextViewsMixin,
                     DialogsMixin, ScanMixin, RenderMixin, ReportsMixin):
    TABS = [
        ("dashboard",   "DASHBOARD"),
        ("stats",       "OVERVIEW"),
        ("findings",    "FINDINGS"),
        ("history",     "SCAN HISTORY"),
        ("masvs",       "MASVS"),
        ("urls",        "LINKS / URLS"),
        ("hosts",       "HOSTS"),
        ("domains",     "DOMAINS"),
        ("ips",         "IP ADDRESSES"),
        ("emails",      "EMAILS"),
        ("exts",        "FILE TYPES"),
        ("secrets",     "SECRETS / KEYS"),
        ("entropy",     "ENTROPY"),
        ("deeplink",    "DEEP LINKS"),
        ("signals",     "SIGNALS"),
        ("checklist",   "SECURITY CHECKLIST"),
        ("metadata",    "APK METADATA"),
        ("permissions", "PERMISSIONS"),
        ("components",  "COMPONENTS"),
        ("inventory",   "APK INVENTORY"),
        ("sdks",        "SDKS / TRACKERS"),
        ("diff",        "BASELINE DIFF"),
        ("search",      "SEARCH"),
        ("cheatsheet",  "CHEATSHEET"),
        ("environment", "ENVIRONMENT"),
        ("log",         "ACTIVITY LOG"),
    ]

    NAV = [
        ("SESSION",   [("dashboard",   "Dashboard"),
                       ("stats",       "Overview"),
                       ("findings",    "Findings"),
                       ("history",     "Scan history"),
                       ("log",         "Activity log")]),
        ("DISCOVERY", [("urls",        "Links / URLs"),
                       ("hosts",       "Hosts"),
                       ("domains",     "Domains"),
                       ("ips",         "IP addresses"),
                       ("emails",      "Emails"),
                       ("exts",        "File types"),
                       ("secrets",     "Secrets / keys"),
                       ("entropy",     "Entropy"),
                       ("deeplink",    "Deep links"),
                       ("search",      "Search")]),
        ("PACKAGE",   [("metadata",    "Metadata"),
                       ("permissions", "Permissions"),
                       ("components",  "Components"),
                       ("inventory",   "Inventory"),
                       ("sdks",        "SDKs / trackers"),
                       ("signals",     "Signals")]),
        ("REPORT",    [("masvs",       "MASVS report"),
                       ("checklist",   "Security checklist"),
                       ("diff",        "Baseline diff")]),
        ("REFERENCE", [("cheatsheet",  "Cheat sheet"),
                       ("environment", "Environment")]),
    ]

    PHASES = (
        ("inventory", "ARCHIVE"),
        ("manifest",  "MANIFEST"),
        ("extract",   "EXTRACT"),
        ("scan",      "SCAN"),
        ("score",     "RISK"),
    )

    def __init__(self, root):
        self.root = root
        self.root.title("APK-Recon")
        self.root.geometry("1320x860")
        self.root.minsize(1080, 680)
        try:
            self.root.state("zoomed")
        except tk.TclError:
            pass
        self.root.configure(bg=PALETTE["bg"])

        self.family = next(
            (f for f in ("Consolas", "Cascadia Mono", "JetBrains Mono", "Courier New")
             if f in tkfont.families()),
            "Courier",
        )
        family = self.family
        self.f_xs      = (family, 8)
        self.f_sm      = (family, 9)
        self.f_md      = (family, 10)
        self.f_bold    = (family, 9, "bold")
        self.f_bold_md = (family, 10, "bold")
        self.f_title   = (family, 15, "bold")
        self.f_kpi     = (family, 21, "bold")

        self.current_apk_path = None
        self.decompile_dir = DECOMPILE_DIR
        self.cancel_event = threading.Event()
        self.result = ScanResult()
        self.text_widgets = {}
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._schedule_filter)
        self.regex_var = tk.BooleanVar(value=False)

        self.fast_mode_var = tk.BooleanVar(value=True)
        self.reuse_var     = tk.BooleanVar(value=True)
        self.auto_html_var = tk.BooleanVar(value=True)
        self.deep_var      = tk.BooleanVar(value=True)
        self.ask_scan_var  = tk.BooleanVar(value=True)
        self.engine_var    = tk.StringVar(value="auto")
        self.workers_var   = tk.IntVar(value=min(16, (os.cpu_count() or 4) * 2))
        self.tool_paths = {}
        self.last_dir = ""
        self.theme_name = "dark"
        self._state_label = None
        self._state_color = None
        self._load_settings()

        self.running = False
        self.active_tab = "dashboard"
        self._raw = {key: [] for key, _ in self.TABS}
        self._counts = {}
        self.nav_rows = {}
        self.kpi_values = {}
        self.findings = []
        self.masvs_report = []
        self.risk_score = 0
        self.risk_grade = "—"
        self.diff_summary = None
        self.log_lines = 0
        self._log_entries = []
        self.last_report_path = None
        self.last_engine = None
        self.last_duration = 0.0
        self.history = self._load_history()
        self._filter_job = None
        self.chart_data = {}
        self.phase_status = {key: "pending" for key, _ in self.PHASES}
        self.progress_value = 0
        self.progress_max = 0
        self.scan_started = None
        self.eta_text = ""
        self._dash_job = None
        self._anim_job = None
        self.spin_angle = 0
        self._link_seq = 0

        self._build_ui()
        self._apply_filter()
        self._bind_shortcuts()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._log("session started", "muted")

    # ---------------- Settings ----------------
    def _settings_path(self):
        return SETTINGS_PATH

    def _load_settings(self):
        try:
            with open(self._settings_path(), "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return
        engine = data.get("engine")
        if engine in ("auto", "dex-only", "jadx", "apktool"):
            self.engine_var.set(engine)
        if isinstance(data.get("fast_mode"), bool):
            self.fast_mode_var.set(data["fast_mode"])
        if isinstance(data.get("reuse"), bool):
            self.reuse_var.set(data["reuse"])
        if isinstance(data.get("auto_html"), bool):
            self.auto_html_var.set(data["auto_html"])
        if isinstance(data.get("deep_scan"), bool):
            self.deep_var.set(data["deep_scan"])
        if isinstance(data.get("ask_before_scan"), bool):
            self.ask_scan_var.set(data["ask_before_scan"])
        theme = data.get("theme")
        if theme in ("dark", "light"):
            apply_theme(theme)
            self.theme_name = theme
        workers = data.get("workers")
        if isinstance(workers, int) and 1 <= workers <= 64:
            self.workers_var.set(workers)
        for key in ("jadx_path", "apktool_path"):
            if isinstance(data.get(key), str) and data[key].strip():
                self.tool_paths[key] = data[key].strip()
        last_dir = data.get("last_dir")
        if isinstance(last_dir, str) and os.path.isdir(last_dir):
            self.last_dir = last_dir

    def _save_settings(self):
        try:
            payload = {
                "engine": self.engine_var.get(),
                "fast_mode": self.fast_mode_var.get(),
                "reuse": self.reuse_var.get(),
                "auto_html": self.auto_html_var.get(),
                "deep_scan": self.deep_var.get(),
                "ask_before_scan": self.ask_scan_var.get(),
                "theme": self.theme_name,
                "workers": self.workers_var.get(),
                "jadx_path": self.tool_paths.get("jadx_path", ""),
                "apktool_path": self.tool_paths.get("apktool_path", ""),
                "last_dir": getattr(self, "last_dir", ""),
            }
            with open(self._settings_path(), "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
        except (OSError, ValueError, tk.TclError):
            pass

    def _on_close(self):
        self._save_settings()
        self.root.destroy()


    # ---------------- Scan history ----------------
    def _load_history(self):
        try:
            with open(HISTORY_PATH, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return []
        if not isinstance(data, list):
            return []
        return [entry for entry in data if isinstance(entry, dict)][:100]

    def _save_history(self):
        try:
            with open(HISTORY_PATH, "w", encoding="utf-8") as fh:
                json.dump(self.history[:100], fh, indent=2)
        except (OSError, ValueError):
            pass

    def _record_history(self):
        entry = {
            "time": datetime.datetime.now().isoformat(timespec="seconds"),
            "apk": os.path.basename(self.current_apk_path or ""),
            "path": self.current_apk_path or "",
            "package": self.result.metadata.get("Package", ""),
            "version": self.result.metadata.get("Version", ""),
            "engine": self.last_engine or self.engine_var.get(),
            "duration": round(self.last_duration or 0, 2),
            "files": self.result.files_scanned,
            "urls": len(self.result.urls),
            "domains": len(self.result.domains),
            "secrets": len(self.result.secrets),
            "findings": len(self.findings),
            "risk": self.risk_score,
            "grade": self.risk_grade,
            "report": self.last_report_path or "",
        }
        self.history.insert(0, entry)
        del self.history[100:]
        self._save_history()
        self._refresh_history_views()
        self._log(f"history recorded · risk {self.risk_score} {self.risk_grade}", "muted")

    def _refresh_history_views(self):
        self._raw["history"] = self._history_items()
        self._counts["history"] = len(self.history)
        if "history" in self.nav_rows:
            self.nav_rows["history"][3].configure(text=str(len(self.history)))
            self._paint_nav()
        self._apply_filter()

    def clear_history(self):
        if not self.history:
            self._status("Scan history is already empty.")
            return
        if not messagebox.askyesno("Clear scan history",
                                   "Delete all locally stored scan history?"):
            return
        self.history = []
        self._save_history()
        self._refresh_history_views()
        self._status("Scan history cleared.")
        self._log("scan history cleared", "review")

    # ---------------- Theme ----------------
    def toggle_theme(self):
        if self.running:
            self._status("Finish or cancel the scan before switching theme.")
            return
        self.theme_name = "light" if self.theme_name == "dark" else "dark"
        apply_theme(self.theme_name)
        self._save_settings()
        self._rebuild_ui()

    def _rebuild_ui(self):
        status_text = self.status_var.get() if hasattr(self, "status_var") else "Ready."
        window_title = self.root.title()
        for child in list(self.root.winfo_children()):
            child.destroy()
        self.text_widgets.clear()
        self.nav_rows.clear()
        self.kpi_values.clear()
        self.pages.clear()
        self.log_lines = 0
        self._dash_job = None
        self._anim_job = None
        self.root.configure(bg=PALETTE["bg"])
        self._build_ui()
        log_widget = self.text_widgets.get("log")
        if log_widget is not None and self._log_entries:
            for stamp, message, tag in self._log_entries[-150:]:
                log_widget.insert(tk.END, f"{stamp}  ", "muted")
                log_widget.insert(tk.END, message + "\n", tag)
            self.log_lines = min(150, len(self._log_entries))
        self._render()
        target_tab = self.active_tab if self.active_tab in self.pages else "dashboard"
        self._switch_tab(target_tab)
        self.root.title(window_title)
        self.status_var.set(status_text or "Ready.")
        if self._state_label:
            self._set_state(self._state_label, self._state_color)
        if not self.running and all(
            status in ("done", "skip") for status in self.phase_status.values()
        ):
            self.progress.config(maximum=1, value=1)
        self._sync_buttons()
        self._log(f"theme switched to {self.theme_name}", "accent")

    # ---------------- Build ----------------
    def _build_ui(self):
        self._build_style()
        self._build_header()

        body = tk.Frame(self.root, bg=PALETTE["bg"])
        body.pack(fill="both", expand=True)
        self._build_sidebar(body)

        main = tk.Frame(body, bg=PALETTE["bg"])
        main.pack(side="left", fill="both", expand=True, padx=(16, 18), pady=(14, 12))

        self._build_target(main)
        self._build_kpi(main)
        self._build_results(main)
        self._build_status(main)

    def _build_style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(
            ".", background=PALETTE["surface"], foreground=PALETTE["text"],
            fieldbackground=PALETTE["input"], bordercolor=PALETTE["border"],
            insertcolor=PALETTE["text"],
        )

        for orient in ("Vertical", "Horizontal"):
            style.configure(
                f"Dark.{orient}.TScrollbar",
                background=PALETTE["border"], troughcolor=PALETTE["surface"],
                bordercolor=PALETTE["surface"], arrowcolor=PALETTE["muted"],
                lightcolor=PALETTE["border"], darkcolor=PALETTE["border"],
                gripcount=0, arrowsize=10, width=10,
            )
            style.map(
                f"Dark.{orient}.TScrollbar",
                background=[("active", PALETTE["accent_dim"])],
            )

        style.configure(
            "Line.Horizontal.TProgressbar",
            troughcolor=PALETTE["input"], background=PALETTE["accent"],
            bordercolor=PALETTE["input"], lightcolor=PALETTE["accent"],
            darkcolor=PALETTE["accent"], thickness=4, borderwidth=0,
        )

        style.configure(
            "Dark.TCombobox",
            fieldbackground=PALETTE["input"], background=PALETTE["surface_alt"],
            foreground=PALETTE["text_bright"], arrowcolor=PALETTE["accent"],
            bordercolor=PALETTE["border"], lightcolor=PALETTE["surface_alt"],
            darkcolor=PALETTE["surface_alt"], padding=(6, 3),
            selectbackground=PALETTE["accent_dim"],
            selectforeground=PALETTE["text_bright"],
        )
        style.map(
            "Dark.TCombobox",
            fieldbackground=[("readonly", PALETTE["input"])],
            foreground=[("readonly", PALETTE["text_bright"])],
            background=[("active", PALETTE["border"])],
            bordercolor=[("focus", PALETTE["accent_soft"])],
        )
        style.configure(
            "Dark.TSpinbox",
            fieldbackground=PALETTE["input"], background=PALETTE["surface_alt"],
            foreground=PALETTE["text_bright"], arrowcolor=PALETTE["accent"],
            bordercolor=PALETTE["border"], padding=(6, 3),
            selectbackground=PALETTE["accent_dim"],
        )

        for pattern, value in (
            ("*TCombobox*Listbox.background",        PALETTE["surface_alt"]),
            ("*TCombobox*Listbox.foreground",        PALETTE["text"]),
            ("*TCombobox*Listbox.selectBackground",  PALETTE["accent_dim"]),
            ("*TCombobox*Listbox.selectForeground",  PALETTE["text_bright"]),
        ):
            self.root.option_add(pattern, value)
        self.root.option_add("*TCombobox*Listbox.font", f"{self.family} 9")

    def _build_header(self):
        header = tk.Frame(
            self.root, bg=PALETTE["bg"],
            highlightthickness=0, padx=22, pady=12,
        )
        header.pack(fill="x")

        logo = tk.Canvas(header, width=26, height=26, bg=PALETTE["bg"], highlightthickness=0)
        logo.pack(side="left", pady=2)
        logo.create_rectangle(0, 0, 26, 26, fill=PALETTE["accent"], outline="")
        for y0, y1, x1 in ((7, 9, 21), (12, 14, 16), (17, 19, 21)):
            logo.create_rectangle(5, y0, x1, y1, fill=PALETTE["on_accent"], outline="")

        title_box = tk.Frame(header, bg=PALETTE["bg"])
        title_box.pack(side="left", padx=(12, 0))
        tk.Label(
            title_box, text="APK-RECON", bg=PALETTE["bg"], fg=PALETTE["text_bright"],
            font=self.f_title,
        ).pack(anchor="w")
        tk.Label(
            title_box, text="apk endpoint · secret · indicator extractor",
            bg=PALETTE["bg"], fg=PALETTE["muted"], font=self.f_xs,
        ).pack(anchor="w")

        self.state_pill = tk.Label(
            header, text="● READY", bg=PALETTE["surface_alt"],
            fg=PALETTE["accent"], font=self.f_bold,
            padx=14, pady=6, highlightthickness=1,
            highlightbackground=PALETTE["border"],
        )
        self.state_pill.pack(side="right", pady=4)
        self._button(header, "CONFIG", self.open_settings).pack(
            side="right", padx=(0, 8), pady=4,
        )
        self._button(header, "?", self.open_help).pack(
            side="right", padx=(0, 8), pady=4,
        )
        self._button(
            header,
            "LIGHT" if self.theme_name == "dark" else "DARK",
            self.toggle_theme,
        ).pack(side="right", padx=(0, 8), pady=4)
        tk.Label(
            header, text="LOCAL · OFFLINE", bg=PALETTE["bg"],
            fg=PALETTE["muted"], font=self.f_xs,
        ).pack(side="right", padx=(0, 14))

        tk.Frame(self.root, bg=PALETTE["border"], height=1).pack(fill="x")

    def _build_sidebar(self, parent):
        side = tk.Frame(parent, bg=PALETTE["surface"], width=218)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Frame(side, bg=PALETTE["border"], width=1).pack(side="right", fill="y")

        canvas = tk.Canvas(
            side, bg=PALETTE["surface"], highlightthickness=0, bd=0,
            width=216,
        )
        self.side_canvas = canvas
        side_bar = ttk.Scrollbar(
            side, orient="vertical", command=canvas.yview,
            style="Dark.Vertical.TScrollbar",
        )
        canvas.configure(yscrollcommand=side_bar.set)
        side_bar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=PALETTE["surface"])
        window = canvas.create_window((0, 0), window=inner, anchor="nw")

        inner.bind("<Configure>",
                   lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind(
            "<Configure>",
            lambda event: canvas.itemconfigure(window, width=event.width),
        )
        self.root.bind_all("<MouseWheel>", self._sidebar_wheel, add="+")

        for index, (group, items) in enumerate(self.NAV):
            if index:
                tk.Frame(inner, bg=PALETTE["border_soft"], height=1).pack(
                    fill="x", padx=14, pady=(8, 0),
                )
            marker = tk.Frame(inner, bg=PALETTE["surface"])
            marker.pack(fill="x", pady=(10, 4))
            tk.Label(
                marker, text="▸", bg=PALETTE["surface"], fg=PALETTE["accent"],
                font=self.f_xs, padx=0,
            ).pack(side="left", padx=(16, 5))
            tk.Label(
                marker, text=group, bg=PALETTE["surface"], fg=PALETTE["accent_soft"],
                font=self.f_bold, anchor="w",
            ).pack(side="left")
            for key, label in items:
                self._nav_row(inner, key, label)

        legend = tk.Frame(inner, bg=PALETTE["surface"])
        legend.pack(fill="x", padx=20, pady=(12, 14))
        tk.Frame(legend, bg=PALETTE["border_soft"], height=1).pack(fill="x", pady=(0, 10))
        for color, text in (
            (PALETTE["accent"], "endpoint / secure scheme"),
            (PALETTE["amber"], "cleartext / review"),
            (PALETTE["critical"], "critical severity"),
            (PALETTE["muted"], "reference / file path"),
        ):
            row = tk.Frame(legend, bg=PALETTE["surface"])
            row.pack(fill="x", pady=2)
            tk.Label(row, text="■", bg=PALETTE["surface"], fg=color, font=self.f_xs).pack(side="left")
            tk.Label(
                row, text=text, bg=PALETTE["surface"], fg=PALETTE["muted"],
                font=self.f_xs, anchor="w",
            ).pack(side="left", padx=(6, 0))

    def _sidebar_wheel(self, event):
        try:
            widget = self.root.winfo_containing(event.x_root, event.y_root)
        except tk.TclError:
            return
        while widget is not None and widget is not self.side_canvas:
            widget = getattr(widget, "master", None)
        if widget is self.side_canvas:
            self.side_canvas.yview_scroll(int(-event.delta / 120), "units")

    def _nav_row(self, parent, key, label):
        row = tk.Frame(parent, bg=PALETTE["surface"], cursor="hand2")
        row.pack(fill="x")
        bar = tk.Frame(row, bg=PALETTE["surface"], width=2)
        bar.pack(side="left", fill="y")
        name = tk.Label(
            row, text=label, bg=PALETTE["surface"], fg=PALETTE["muted"],
            font=self.f_sm, anchor="w", padx=10, pady=6,
        )
        name.pack(side="left", fill="x", expand=True)
        count = tk.Label(
            row, text="", bg=PALETTE["surface"], fg=PALETTE["border"],
            font=self.f_xs, padx=10,
        )
        count.pack(side="right")

        self.nav_rows[key] = (row, bar, name, count)

        for widget in (row, name, count, bar):
            widget.bind("<Button-1>", lambda _e, k=key: self._switch_tab(k))
            widget.bind("<Enter>", lambda _e, k=key: self._nav_hover(k, True))
            widget.bind("<Leave>", lambda _e, k=key: self._nav_hover(k, False))

    def _nav_hover(self, key, entering):
        if key == self.active_tab:
            return
        row, bar, name, count = self.nav_rows[key]
        if entering:
            for w in (row, name, count):
                w.configure(bg=PALETTE["surface_alt"])
            name.configure(fg=PALETTE["text_bright"])
        else:
            self._paint_nav()

    def _paint_nav(self):
        for key, (row, bar, name, count) in self.nav_rows.items():
            active = key == self.active_tab
            bg = PALETTE["active"] if active else PALETTE["surface"]
            for w in (row, name, count):
                w.configure(bg=bg)
            bar.configure(bg=PALETTE["accent"] if active else bg)
            name.configure(fg=PALETTE["text_bright"] if active else PALETTE["muted"])
            has_value = count.cget("text") not in ("", "0")
            count.configure(
                fg=PALETTE["accent"] if active
                else (PALETTE["muted"] if has_value else PALETTE["border"])
            )

    def _build_target(self, parent):
        border, panel = self._panel(parent, fill="x")
        box = tk.Frame(panel, bg=PALETTE["surface"], padx=14, pady=12)
        box.pack(fill="x")

        head = tk.Frame(box, bg=PALETTE["surface"])
        head.pack(fill="x", pady=(0, 8))
        tk.Label(
            head, text="TARGET PACKAGE", bg=PALETTE["surface"],
            fg=PALETTE["text_bright"], font=self.f_bold_md,
        ).pack(side="left")
        tk.Label(
            head, text="android package archive · .apk", bg=PALETTE["surface"],
            fg=PALETTE["muted"], font=self.f_xs,
        ).pack(side="left", padx=10)

        picker = tk.Frame(box, bg=PALETTE["surface"])
        picker.pack(fill="x")
        tk.Label(
            picker, text="❯", bg=PALETTE["surface"], fg=PALETTE["accent"],
            font=self.f_bold_md,
        ).pack(side="left", padx=(0, 8))
        if not hasattr(self, "path_var"):
            self.path_var = tk.StringVar()
        self.path_entry = self._entry(picker, self.path_var)
        self.path_entry.pack(side="left", fill="x", expand=True, ipady=6)
        self.btn_browse = self._button(picker, "BROWSE", self.browse_apk, danger=True)
        self.btn_browse.pack(side="left", padx=(8, 0))
        self._button(picker, "COMPARE", self.compare_baseline).pack(side="left", padx=(6, 0))
        self._button(picker, "EXPORT", self.export_results).pack(side="left", padx=(6, 0))
        self._button(picker, "HTML", self.open_html_report).pack(side="left", padx=(6, 0))

        actions = tk.Frame(box, bg=PALETTE["surface"])
        actions.pack(fill="x", pady=(10, 0))

        self.btn_analyze = self._button(actions, "ANALYZE", self.start_analysis, danger=True)
        self.btn_analyze.pack(side="right", padx=(8, 0))
        self.btn_cancel = self._button(actions, "CANCEL", self.cancel_analysis)
        self.btn_cancel.pack(side="right", padx=(8, 0))
        self._sync_buttons()

        opts = tk.Frame(actions, bg=PALETTE["surface"])
        opts.pack(side="left")
        for text, var in (("Fast mode", self.fast_mode_var),
                          ("Reuse cache", self.reuse_var),
                          ("Auto HTML", self.auto_html_var)):
            tk.Checkbutton(
                opts, text=text, variable=var, bg=PALETTE["surface"],
                fg=PALETTE["text"], activebackground=PALETTE["surface"],
                activeforeground=PALETTE["accent"], selectcolor=PALETTE["input"],
                font=self.f_sm, bd=0, highlightthickness=0, cursor="hand2",
            ).pack(side="left", padx=(0, 14))

        tk.Label(
            opts, text="ENGINE", bg=PALETTE["surface"], fg=PALETTE["muted"],
            font=self.f_xs,
        ).pack(side="left", padx=(6, 6))
        ttk.Combobox(
            opts, textvariable=self.engine_var,
            values=["auto", "dex-only", "jadx", "apktool"],
            width=9, state="readonly", style="Dark.TCombobox",
            font=self.f_sm,
        ).pack(side="left")

        tk.Label(
            opts, text="WORKERS", bg=PALETTE["surface"], fg=PALETTE["muted"],
            font=self.f_xs,
        ).pack(side="left", padx=(14, 6))
        ttk.Spinbox(
            opts, from_=1, to=64, textvariable=self.workers_var,
            width=4, style="Dark.TSpinbox", font=self.f_sm,
        ).pack(side="left")

    def _build_kpi(self, parent):
        row = tk.Frame(parent, bg=PALETTE["bg"])
        row.pack(fill="x", pady=(12, 0))
        row.columnconfigure((0, 1, 2, 3, 4), weight=1, uniform="kpi")

        cards = (
            ("urls",     "ENDPOINTS", "urls"),
            ("domains",  "DOMAINS",   "domains"),
            ("secrets",  "SECRETS",   "secrets"),
            ("findings", "FINDINGS",  "findings"),
            ("risk",     "RISK",      "findings"),
        )
        for col, (key, title, target) in enumerate(cards):
            border = tk.Frame(row, bg=PALETTE["border"], cursor="hand2")
            border.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 8, 0))
            inner = tk.Frame(border, bg=PALETTE["surface"], height=78)
            inner.pack(fill="both", expand=True, padx=1, pady=1)
            inner.pack_propagate(False)

            head = tk.Frame(inner, bg=PALETTE["surface"])
            head.pack(fill="x", padx=14, pady=(10, 0))
            tk.Label(
                head, text="▪", bg=PALETTE["surface"], fg=PALETTE["accent"],
                font=self.f_xs,
            ).pack(side="left")
            tk.Label(
                head, text=title, bg=PALETTE["surface"], fg=PALETTE["muted"],
                font=self.f_xs,
            ).pack(side="left", padx=(6, 0))

            value = tk.Label(
                inner, text="—" if key == "risk" else "0",
                bg=PALETTE["surface"], fg=PALETTE["text_bright"],
                font=self.f_kpi, anchor="w",
            )
            value.pack(fill="x", padx=12, pady=(0, 4))
            self.kpi_values[key] = value

            for widget in (border, inner, head, value):
                widget.bind("<Button-1>", lambda _e, t=target: self._switch_tab(t))
                widget.bind("<Enter>", lambda _e, b=border: b.configure(bg=PALETTE["accent_soft"]))
                widget.bind("<Leave>", lambda _e, b=border: b.configure(bg=PALETTE["border"]))

    def _build_results(self, parent):
        border, panel = self._panel(parent, fill="both", expand=True, pady=(12, 0))
        box = tk.Frame(panel, bg=PALETTE["surface"])
        box.pack(fill="both", expand=True, padx=14, pady=(12, 12))

        head = tk.Frame(box, bg=PALETTE["surface"])
        head.pack(fill="x", pady=(0, 10))

        self.view_title = tk.Label(
            head, text="DASHBOARD", bg=PALETTE["surface"],
            fg=PALETTE["text_bright"], font=self.f_bold_md,
        )
        self.view_title.pack(side="left")
        self.view_count = tk.Label(
            head, text="0", bg=PALETTE["surface_alt"], fg=PALETTE["accent"],
            font=self.f_xs, padx=8, pady=3,
        )
        self.view_count.pack(side="left", padx=8)

        self._button(head, "COPY", self.copy_current).pack(side="right")
        self._button(head, "CLEAR", self.clear_filter).pack(side="right", padx=(8, 0))
        self.filter_entry = self._entry(head, self.search_var, width=24)
        self.filter_entry.pack(side="right", ipady=4, padx=(0, 8))
        tk.Checkbutton(
            head, text=".*", variable=self.regex_var, command=self._apply_filter,
            indicatoron=False, bg=PALETTE["surface_alt"], fg=PALETTE["muted"],
            activebackground=PALETTE["border"], activeforeground=PALETTE["text_bright"],
            selectcolor=PALETTE["accent_dim"], font=self.f_bold,
            padx=8, pady=3, bd=0, highlightthickness=1,
            highlightbackground=PALETTE["border"], cursor="hand2",
        ).pack(side="right", padx=(0, 8))
        tk.Label(
            head, text="FILTER", bg=PALETTE["surface"], fg=PALETTE["muted"],
            font=self.f_xs,
        ).pack(side="right", padx=(0, 8))

        self.stack = tk.Frame(box, bg=PALETTE["surface"])
        self.stack.pack(fill="both", expand=True)
        self.pages = {}

        for key, _title in self.TABS:
            page = tk.Frame(self.stack, bg=PALETTE["surface"])
            page.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.pages[key] = page

            if key == "dashboard":
                self.dash_canvas = tk.Canvas(
                    page, bg=PALETTE["surface"], highlightthickness=0, bd=0,
                )
                self.dash_canvas.pack(fill="both", expand=True)
                self.dash_canvas.bind("<Configure>", self._schedule_dashboard)
                continue

            wrap = tk.Frame(page, bg=PALETTE["surface"])
            wrap.pack(fill="both", expand=True)
            wrap.rowconfigure(0, weight=1)
            wrap.columnconfigure(0, weight=1)

            text = tk.Text(
                wrap, wrap="none", bd=0, highlightthickness=0,
                bg=PALETTE["input"], fg=PALETTE["text"],
                insertbackground=PALETTE["accent"],
                selectbackground=PALETTE["accent_dim"],
                selectforeground=PALETTE["text_bright"],
                font=self.f_md, padx=14, pady=10,
                spacing1=1, spacing3=1,
                cursor="xterm",
            )
            vbar = ttk.Scrollbar(
                wrap, orient="vertical", command=text.yview,
                style="Dark.Vertical.TScrollbar",
            )
            hbar = ttk.Scrollbar(
                wrap, orient="horizontal", command=text.xview,
                style="Dark.Horizontal.TScrollbar",
            )
            text.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
            text.grid(row=0, column=0, sticky="nsew")
            vbar.grid(row=0, column=1, sticky="ns")
            hbar.grid(row=1, column=0, sticky="ew")

            for tag, cfg in (
                ("norm",   {"foreground": PALETTE["text"]}),
                ("bright", {"foreground": PALETTE["text_bright"]}),
                ("accent", {"foreground": PALETTE["accent"]}),
                ("warn",   {"foreground": PALETTE["amber"]}),
                ("muted",  {"foreground": PALETTE["muted"]}),
                ("pass",   {"foreground": PALETTE["accent"]}),
                ("review", {"foreground": PALETTE["amber"]}),
                ("crit",   {"foreground": PALETTE["critical"]}),
                ("high",   {"foreground": PALETTE["high"]}),
                ("med",    {"foreground": PALETTE["medium"]}),
                ("low",    {"foreground": PALETTE["low"]}),
                ("info",   {"foreground": PALETTE["muted"]}),
                ("plus",   {"foreground": PALETTE["accent"]}),
                ("minus",  {"foreground": PALETTE["critical"]}),
                ("link",   {"foreground": PALETTE["accent"], "underline": True}),
                ("evid",   {"foreground": PALETTE["evidence"]}),
                ("hdr",    {"foreground": PALETTE["accent"],
                            "font": self.f_bold_md, "spacing1": 12, "spacing3": 4}),
                ("empty",  {"foreground": PALETTE["muted"], "font": self.f_sm}),
            ):
                text.tag_configure(tag, **cfg)

            text.bind("<Double-Button-1>", lambda _e, w=text: self.copy_line(w))
            self.text_widgets[key] = text

        self.pages["dashboard"].tkraise()
        self._paint_nav()

    def _build_status(self, parent):
        frame = tk.Frame(parent, bg=PALETTE["bg"])
        frame.pack(fill="x", pady=(10, 0))

        self.progress = ttk.Progressbar(
            frame, mode="determinate", style="Line.Horizontal.TProgressbar",
        )
        self.progress.pack(fill="x", pady=(0, 8))

        bar = tk.Frame(frame, bg=PALETTE["bg"])
        bar.pack(fill="x")
        tk.Label(
            bar, text="❯", bg=PALETTE["bg"], fg=PALETTE["accent"],
            font=self.f_bold_md,
        ).pack(side="left", padx=(0, 8))
        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(
            bar, textvariable=self.status_var, bg=PALETTE["bg"],
            fg=PALETTE["muted"], font=self.f_sm, anchor="w",
        ).pack(side="left")
        tk.Label(
            bar, text="Ctrl+O open · F5 scan · Ctrl+F filter · Ctrl+E export",
            bg=PALETTE["bg"], fg=PALETTE["border"], font=self.f_xs,
        ).pack(side="right")

    def _bind_shortcuts(self):
        self.root.bind("<Control-o>", lambda _e: self.browse_apk())
        self.root.bind("<F5>", lambda _e: self.start_analysis())
        self.root.bind("<Control-f>", lambda _e: self._focus_filter())
        self.root.bind("<Control-e>", lambda _e: self.export_results())
        self.root.bind("<Control-b>", lambda _e: self.compare_baseline())
        self.root.bind("<Control-l>", lambda _e: self.clear_filter())
        self.root.bind("<Control-d>", lambda _e: self._switch_tab("dashboard"))
        self.root.bind("<Control-h>", lambda _e: self.open_html_report())
        self.root.bind("<Control-t>", lambda _e: self.toggle_theme())
        self.root.bind("<F1>", lambda _e: self.open_help())

    def _focus_filter(self):
        self.filter_entry.focus_set()
        self.filter_entry.select_range(0, tk.END)

    # ---------------- State / navigation ----------------
    def _set_state(self, text, color):
        self._state_label = text
        self._state_color = color
        self.state_pill.configure(text=f"● {text}", fg=color)

    def _sync_buttons(self):
        has_apk = bool(self.current_apk_path)
        if self.running:
            self.btn_browse.configure(
                state="disabled", bg=PALETTE["surface_alt"], fg=PALETTE["muted"],
            )
            self.btn_analyze.configure(
                state="disabled", text="ANALYZING…",
                bg=PALETTE["danger_active"], fg=PALETTE["on_danger_active"],
                disabledforeground=PALETTE["on_danger_active"],
            )
            self.btn_cancel.configure(
                state="normal", bg=PALETTE["surface_alt"], fg=PALETTE["text"],
            )
        else:
            self.btn_browse.configure(
                state="normal",
                bg=PALETTE["surface_alt"] if has_apk else PALETTE["danger"],
                fg=PALETTE["text"] if has_apk else PALETTE["on_danger"],
            )
            if has_apk:
                self.btn_analyze.configure(
                    state="normal", text="ANALYZE",
                    bg=PALETTE["danger"], fg=PALETTE["on_danger"],
                    disabledforeground=PALETTE["on_danger"],
                )
            else:
                self.btn_analyze.configure(
                    state="disabled", text="ANALYZE",
                    bg=PALETTE["surface_alt"], fg=PALETTE["muted"],
                    disabledforeground=PALETTE["muted"],
                )
            self.btn_cancel.configure(
                state="disabled", bg=PALETTE["surface_alt"], fg=PALETTE["muted"],
            )

    def _switch_tab(self, key):
        page = self.pages.get(key)
        if not page:
            return
        self.active_tab = key
        page.tkraise()
        self.view_title.configure(text=dict(self.TABS)[key])
        self.view_count.configure(text=str(self._counts.get(key, 0)))
        self._paint_nav()
        if key == "dashboard":
            self._draw_dashboard()
        elif key == "environment":
            self._raw["environment"] = self._environment_items()
            self._apply_filter()

    # ---------------- Actions ----------------
    def browse_apk(self):
        p = filedialog.askopenfilename(
            filetypes=[("APK", "*.apk")],
            initialdir=self.last_dir or os.getcwd(),
        )
        if p:
            self.last_dir = os.path.dirname(p)
            self.path_var.set(p)
            self.current_apk_path = p
            self.root.title(f"APK-Recon — {os.path.basename(p)}")
            self._sync_buttons()
            self._log(f"target loaded: {os.path.basename(p)}", "muted")
            self._status(f"Target loaded: {os.path.basename(p)}")


    def compare_baseline(self):
        r = self.result
        if not (r.urls or r.domains or r.permissions):
            messagebox.showinfo("Nothing to compare", "Run a scan first.")
            return
        path = filedialog.askopenfilename(
            title="Select a previous APK-Recon JSON export",
            initialdir=self.last_dir or os.getcwd(),
            filetypes=[("JSON", "*.json")],
        )
        if not path:
            return
        self.last_dir = os.path.dirname(path)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                baseline = json.load(fh)
        except (OSError, ValueError) as e:
            self._error("Compare failed", str(e))
            return
        self._apply_baseline(baseline, os.path.basename(path))

    def _apply_baseline(self, baseline, baseline_name="baseline"):
        r = self.result
        if not (r.urls or r.domains or r.permissions):
            messagebox.showinfo("Nothing to compare", "Run a scan first.")
            return

        def to_set(values):
            return set(values or [])

        base_urls = to_set(baseline.get("urls"))
        cur_urls = set(r.urls)
        base_domains = to_set(baseline.get("domains"))
        cur_domains = set(r.domains)
        base_perms = to_set(baseline.get("permissions"))
        cur_perms = r.permissions
        base_comps = to_set(baseline.get("components"))
        cur_comps = set(r.components)
        base_sdks = set((baseline.get("sdks") or {}).keys())
        cur_sdks = set(r.sdks)
        base_secrets = {
            (item.get("type"), item.get("value"))
            for item in baseline.get("secrets") or []
            if isinstance(item, dict)
        }
        cur_secrets = {(cat, val) for cat, val, _ in r.secrets}

        lines = [("▸ BASELINE COMPARISON", "hdr", None)]
        lines.append((f"Baseline: {baseline_name}", "kv", None))
        lines.append((f"Current: {os.path.basename(self.current_apk_path or '')}", "kv", None))

        total = 0

        def section(title, added, removed, formatter=str):
            nonlocal total
            total += len(added) + len(removed)
            lines.append((f"▸ {title}   +{len(added)} / -{len(removed)}", "hdr", None))
            if not added and not removed:
                lines.append(("no changes", "note", None))
                return
            for item in sorted(added):
                lines.append(("+ " + formatter(item), "plus", None))
            for item in sorted(removed):
                lines.append(("- " + formatter(item), "minus", None))

        section("ENDPOINTS", cur_urls - base_urls, base_urls - cur_urls)
        section("DOMAINS", cur_domains - base_domains, base_domains - cur_domains)
        section("PERMISSIONS", cur_perms - base_perms, base_perms - cur_perms)
        section("COMPONENTS", cur_comps - base_comps, base_comps - cur_comps)
        section("SDKS", cur_sdks - base_sdks, base_sdks - cur_sdks)
        section(
            "SECRETS", cur_secrets - base_secrets, base_secrets - cur_secrets,
            formatter=lambda pair: f"{pair[0]}: {pair[1]}",
        )

        base_meta = baseline.get("metadata") or {}
        changes = [
            (key, base_meta.get(key), r.metadata.get(key))
            for key in sorted(set(base_meta) | set(r.metadata))
            if base_meta.get(key) != r.metadata.get(key)
        ]
        lines.append((f"▸ METADATA   {len(changes)} change(s)", "hdr", None))
        for key, old, new in changes:
            total += 1
            lines.append((f"~ {key}: {old or '—'} → {new or '—'}", "warn", None))
        if not changes:
            lines.append(("no changes", "note", None))

        lines.append(("▸ SUMMARY", "hdr", None))
        lines.append((f"Total changes: {total}", "kv", None))
        self.diff_summary = {"lines": lines, "total": total}
        self._counts["diff"] = total
        self._raw["diff"] = list(lines)
        if "diff" in self.nav_rows:
            self.nav_rows["diff"][3].configure(text=str(total))
        self._switch_tab("diff")
        self._apply_filter()
        self._status(f"Baseline diff: {total} change(s)")
        self._log(f"baseline diff vs {baseline_name}: {total} change(s)", "accent")

    # ---------------- Activity log ----------------
    def _log(self, message, tag="muted"):
        widget = self.text_widgets.get("log")
        if widget is None:
            return
        stamp = datetime.datetime.now().strftime("%H:%M:%S")

        def do():
            widget.insert(tk.END, f"{stamp}  ", "muted")
            widget.insert(tk.END, message + "\n", tag)
            self._log_entries.append((stamp, message, tag))
            del self._log_entries[:-500]
            self.log_lines += 1
            if self.log_lines > 1500:
                widget.delete("1.0", "300.0")
                self.log_lines -= 299
            widget.see(tk.END)
            if "log" in self.nav_rows:
                self.nav_rows["log"][3].configure(text=str(self.log_lines))
                self._paint_nav()

        if threading.current_thread() is threading.main_thread():
            do()
        else:
            self.root.after(0, do)

    # ---------------- thread-safe UI ----------------
    def _status(self, m):  self.root.after(0, lambda: self.status_var.set(m))
    def _error(self, t, m): self.root.after(0, lambda: messagebox.showerror(t, m))
    def _indeterminate(self, on):
        def do():
            if on:
                self.progress.config(mode="indeterminate"); self.progress.start(10)
