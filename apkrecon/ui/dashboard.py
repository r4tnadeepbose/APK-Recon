"""Canvas dashboard: risk gauge, severity donut, bars and scan pipeline."""

import datetime
import tkinter as tk

from ..config import PALETTE, SEVERITY_COLORS, SEVERITY_ORDER
from ..scanner import fmt_eta


class DashboardMixin:
    # ---------------- Live scan dashboard ----------------
    def _schedule_dashboard(self, _event=None):
        if self._dash_job is not None:
            try:
                self.root.after_cancel(self._dash_job)
            except tk.TclError:
                pass
        self._dash_job = self.root.after(80, self._draw_dashboard)

    def _card(self, canvas, x, y, w, h, title, subtitle=""):
        canvas.create_rectangle(x, y, x + w, y + h,
                                fill=PALETTE["surface"], outline=PALETTE["border"])
        canvas.create_line(x, y + 30, x + w, y + 30, fill=PALETTE["border"])
        canvas.create_text(x + 12, y + 15, text=title, anchor="w",
                           fill=PALETTE["text"], font=self.f_xs)
        if subtitle:
            canvas.create_text(x + w - 12, y + 15, text=subtitle, anchor="e",
                               fill=PALETTE["muted"], font=self.f_xs)

    def _draw_dashboard(self):
        canvas = getattr(self, "dash_canvas", None)
        if canvas is None or not canvas.winfo_ismapped():
            return
        width = canvas.winfo_width()
        height = canvas.winfo_height()
        if width < 200 or height < 200:
            return
        canvas.delete("all")

        compact = height < 520
        margin, gap = 16, 12
        target_h = 50 if compact else 58
        strip_h = 80

        self._draw_target_strip(canvas, margin, margin,
                                width - 2 * margin, target_h)
        phase_y = margin + target_h + gap
        self._draw_phase_strip(canvas, margin, phase_y,
                               width - 2 * margin, strip_h)

        top = phase_y + strip_h + gap
        available = height - top - margin
        if available < 70:
            return

        left_w = int((width - 2 * margin - gap) * 0.44)
        row1_h = int(available * 0.54)
        show_second_row = available - row1_h - gap >= 78
        if not show_second_row:
            row1_h = available
        self._draw_gauge(canvas, margin, top, left_w, row1_h)
        self._draw_severity(canvas, margin + left_w + gap, top,
                            width - 2 * margin - left_w - gap, row1_h)

        if not show_second_row:
            return
        row2 = top + row1_h + gap
        row2_h = height - row2 - margin
        columns = 3 if width >= 1000 else 2
        usable = width - 2 * margin - gap * (columns - 1)
        card_w = usable // columns
        self._draw_bars(canvas, margin, row2, card_w, row2_h, "TOP HOSTS",
                        self.chart_data.get("hosts", []), PALETTE["accent"])
        secret_rows = [
            (f"{cat}", count, SEVERITY_COLORS.get(sev, PALETTE["text"]))
            for cat, count, sev in self.chart_data.get("secrets", [])
        ]
        self._draw_bars(canvas, margin + card_w + gap, row2, card_w, row2_h,
                        "SECRET CATEGORIES", secret_rows, colored=True)
        if columns == 3:
            self._draw_findings_card(canvas, margin + 2 * (card_w + gap), row2,
                                     card_w, row2_h)

    def _chip(self, canvas, right_x, y, text, color):
        width = max(34, len(text) * 7 + 16)
        left = right_x - width
        canvas.create_rectangle(left, y - 9, right_x, y + 9,
                                outline=PALETTE["border"], fill=PALETTE["surface_alt"])
        canvas.create_text((left + right_x) / 2, y, text=text,
                           fill=color, font=self.f_xs)
        return left - 8

    def _draw_target_strip(self, canvas, x, y, w, h):
        target = self.chart_data.get("target") or {}
        canvas.create_rectangle(x, y, x + w, y + h,
                                fill=PALETTE["surface"], outline=PALETTE["border"])

        name = target.get("name") or "no target loaded"
        canvas.create_text(x + 14, y + 17, text=name, anchor="w",
                           fill=PALETTE["text_bright"], font=self.f_bold_md)
        subtitle = (f"{target.get('package', '—')} · v{target.get('version', '—')} · "
                    f"SDK {target.get('min_sdk', '?')} → {target.get('target_sdk', '?')}")
        canvas.create_text(x + 14, y + h - 18, text=subtitle, anchor="w",
                           fill=PALETTE["muted"], font=self.f_xs)

        signed_color = (PALETTE["amber"] if target.get("debug")
                        else PALETTE["accent"] if target.get("signed")
                        else PALETTE["critical"])
        chips = (
            (target.get("signed_label", "UNSIGNED"), signed_color),
            (str(target.get("engine", "auto")).upper(), PALETTE["accent"]),
            (str(target.get("size", "—")), PALETTE["text"]),
            (f"{target.get('libs', 0)} libs", PALETTE["muted"]),
            (f"{target.get('dex', 0)} dex", PALETTE["muted"]),
            (f"{target.get('files', 0)} files", PALETTE["muted"]),
        )
        right = x + w - 12
        for text, color in chips:
            right = self._chip(canvas, right, y + h / 2, text, color)

    def _draw_phase_strip(self, canvas, x, y, w, h):
        canvas.create_rectangle(x, y, x + w, y + h,
                                fill=PALETTE["surface"], outline=PALETTE["border"])
        done = sum(1 for status in self.phase_status.values() if status in ("done", "skip"))
        if self.running and self.progress_max:
            fraction = min(1.0, self.progress_value / self.progress_max)
        elif not self.running and done == len(self.PHASES):
            fraction = 1.0
        else:
            fraction = 0.0

        canvas.create_text(x + 12, y + 12, text="SCAN PIPELINE", anchor="w",
                           fill=PALETTE["text"], font=self.f_xs)
        caption = self.eta_text if self.running else (
            "complete" if done == len(self.PHASES) else "idle — load an apk and analyze"
        )
        canvas.create_text(x + w - 12, y + 12, text=caption, anchor="e",
                           fill=PALETTE["muted"], font=self.f_xs)

        colors = {
            "pending": PALETTE["border"], "active": PALETTE["amber"],
            "done": PALETTE["accent"], "skip": PALETTE["muted"],
            "failed": PALETTE["critical"],
        }
        column = w / len(self.PHASES)
        for index, (key, label) in enumerate(self.PHASES):
            center = x + column * (index + 0.5)
            status = self.phase_status.get(key, "pending")
            color = colors.get(status, PALETTE["muted"])
            if index:
                canvas.create_line(center - column / 2, y + 28,
                                   center - column / 2, y + h - 8,
                                   fill=PALETTE["border_soft"])
            canvas.create_oval(center - 4, y + 32, center + 4, y + 40,
                               fill=color, outline="")
            if status == "active" and self.running:
                canvas.create_arc(center - 10, y + 26, center + 10, y + 46,
                                  start=self.spin_angle, extent=250, style="arc",
                                  outline=PALETTE["amber"], width=2)
            canvas.create_text(center, y + 54, text=label,
                               fill=PALETTE["text"] if status != "pending" else PALETTE["muted"],
                               font=self.f_xs)
            canvas.create_text(center, y + 70, text=status.upper(), fill=color,
                               font=self.f_xs)

        canvas.create_rectangle(x, y + h - 3, x + w, y + h,
                                fill=PALETTE["input"], outline="")
        if fraction > 0:
            canvas.create_rectangle(x, y + h - 3, x + w * fraction, y + h,
                                    fill=PALETTE["accent"], outline="")

    def _draw_gauge(self, canvas, x, y, w, h):
        self._card(canvas, x, y, w, h, "RISK SCORE",
                   f"GRADE {self.risk_grade}")
        score = self.risk_score
        color = (PALETTE["accent"] if score >= 75
                 else PALETTE["amber"] if score >= 50 else PALETTE["critical"])
        cx = x + w * 0.26
        cy = y + h * 0.60
        radius = min(w * 0.19, (h - 44) * 0.42)
        if radius < 16:
            return
        canvas.create_arc(cx - radius, cy - radius, cx + radius, cy + radius,
                          start=225, extent=-270, style="arc",
                          outline=PALETTE["border"], width=8)
        if score > 0:
            canvas.create_arc(cx - radius, cy - radius, cx + radius, cy + radius,
                              start=225, extent=-270 * min(100, score) / 100,
                              style="arc", outline=color, width=8)
        canvas.create_text(cx, cy - 6, text=str(score), fill=color, font=self.f_kpi)
        canvas.create_text(cx, cy + 20, text="OF 100", fill=PALETTE["muted"],
                           font=self.f_xs)

        counts = self.chart_data.get("counts", {})
        stats = (
            ("ENDPOINTS", counts.get("endpoints", 0)),
            ("HOSTS", counts.get("hosts", 0)),
            ("SECRETS", counts.get("secrets", 0)),
            ("SDKS", counts.get("sdks", 0)),
            ("ENTROPY", counts.get("entropy", 0)),
        )
        spacing = 21 if h >= 150 else 17
        max_rows = max(2, int((h - 52) / spacing))
        sx = x + w * 0.54
        sy = y + 52
        for label, value in stats[:max_rows]:
            canvas.create_text(sx, sy, text=label, anchor="w",
                               fill=PALETTE["muted"], font=self.f_xs)
            canvas.create_text(x + w - 14, sy, text=str(value), anchor="e",
                               fill=PALETTE["text_bright"], font=self.f_bold)
            sy += spacing

    def _draw_severity(self, canvas, x, y, w, h):
        data = self.chart_data.get("severity", {})
        total = sum(data.values())
        self._card(canvas, x, y, w, h, "FINDINGS BY SEVERITY", f"{total} total")
        radius = min((h - 50) * 0.36, w * 0.18)
        cx = x + 24 + radius
        cy = y + 34 + (h - 34) / 2
        if radius < 16:
            return
        if total == 0:
            canvas.create_oval(cx - radius, cy - radius, cx + radius, cy + radius,
                               outline=PALETTE["border"], width=12)
            canvas.create_text(cx, cy, text="0", fill=PALETTE["muted"],
                               font=self.f_kpi)
        else:
            start = 90
            for severity in SEVERITY_ORDER:
                count = data.get(severity, 0)
                if not count:
                    continue
                extent = -360 * count / total
                canvas.create_arc(cx - radius, cy - radius,
                                  cx + radius, cy + radius,
                                  start=start, extent=extent, style="arc",
                                  outline=SEVERITY_COLORS[severity], width=14)
                start += extent
            canvas.create_text(cx, cy, text=str(total), fill=PALETTE["text_bright"],
                               font=self.f_kpi)

        legend_x = cx + radius + 26
        spacing = 20 if h >= 160 else 15
        legend_y = cy - (len(SEVERITY_ORDER) - 1) * spacing / 2
        for severity in SEVERITY_ORDER:
            count = data.get(severity, 0)
            canvas.create_rectangle(legend_x, legend_y - 5, legend_x + 8, legend_y + 3,
                                    fill=SEVERITY_COLORS[severity], outline="")
            canvas.create_text(legend_x + 16, legend_y, text=severity, anchor="w",
                               fill=PALETTE["muted"], font=self.f_xs)
            canvas.create_text(x + w - 14, legend_y, text=str(count), anchor="e",
                               fill=PALETTE["text_bright"], font=self.f_bold)
            legend_y += spacing

        masvs = self.chart_data.get("masvs") or []
        if masvs and h >= 188:
            chip_w = 30
            right = x + w - 14
            chip_y = y + h - 17
            for code, status in reversed(masvs):
                color = {"PASS": PALETTE["accent"], "REVIEW": PALETTE["high"],
                         "WARN": PALETTE["critical"]}.get(status, PALETTE["muted"])
                left = right - chip_w
                canvas.create_rectangle(left, chip_y - 8, right - 3, chip_y + 8,
                                        outline=color)
                canvas.create_text((left + right - 3) / 2, chip_y, text=code[:2],
                                   fill=color, font=self.f_xs)
                right = left - 4

    def _draw_findings_card(self, canvas, x, y, w, h):
        findings = self.chart_data.get("top_findings", [])
        self._card(canvas, x, y, w, h, "TOP FINDINGS",
                   f"{self.chart_data.get('counts', {}).get('findings', 0)} total")
        if not findings:
            canvas.create_text(x + 14, y + 50, text="// no findings", anchor="w",
                               fill=PALETTE["muted"], font=self.f_sm)
            return
        top = y + 44
        area = h - 58
        if area < 30:
            return
        row_capacity = max(1, int(area / 20))
        shown = min(len(findings), 6, row_capacity)
        row_h = area / shown
        chars = max(10, int((w - 96) / 6.6))
        for index, (title, severity) in enumerate(findings[:shown]):
            color = SEVERITY_COLORS.get(severity, PALETTE["text"])
            line_y = top + row_h * (index + 0.5)
            canvas.create_text(x + 14, line_y, text=severity[:4], anchor="w",
                               fill=color, font=self.f_bold)
            shown = title if len(title) <= chars else title[:chars - 1] + "…"
            canvas.create_text(x + 62, line_y, text=shown, anchor="w",
                               fill=PALETTE["text"], font=self.f_sm)

    def _draw_bars(self, canvas, x, y, w, h, title, items, color=None, colored=False):
        self._card(canvas, x, y, w, h, title, f"{len(items)} listed")
        if not items:
            canvas.create_text(x + 14, y + 50, text="// no data yet", anchor="w",
                               fill=PALETTE["muted"], font=self.f_sm)
            return
        top = y + 44
        area = h - 58
        if area < 40:
            return
        row_capacity = max(1, int(area / 24))
        shown = min(len(items), 7, row_capacity)
        row_h = area / shown
        max_value = max(item[1] for item in items) or 1
        chars = max(8, int((w - 90) / 7))
        for index, item in enumerate(items[:shown]):
            label, value = item[0], item[1]
            row_color = item[2] if colored and len(item) > 2 else (color or PALETTE["accent"])
            line_y = top + row_h * (index + 0.5)
            shown = label if len(label) <= chars else label[:chars - 1] + "…"
            canvas.create_text(x + 14, line_y - 4, text=shown, anchor="w",
                               fill=PALETTE["text"], font=self.f_sm)
            canvas.create_text(x + w - 14, line_y - 4, text=str(value), anchor="e",
                               fill=PALETTE["text_bright"], font=self.f_sm)
            bar_left = x + 14
            bar_right = x + w - 14
            canvas.create_rectangle(bar_left, line_y + 5, bar_right, line_y + 8,
                                    fill=PALETTE["input"], outline="")
            length = (bar_right - bar_left) * (value / max_value)
            canvas.create_rectangle(bar_left, line_y + 5, bar_left + length, line_y + 8,
                                    fill=row_color, outline="")

    def _start_spinner(self):
        if self._anim_job is not None:
            return

        def tick():
            self.spin_angle = (self.spin_angle + 26) % 360
            if self.active_tab == "dashboard" and self.running:
                self._draw_dashboard()
            self._anim_job = self.root.after(80, tick) if self.running else None

        self._anim_job = self.root.after(80, tick)

    # ---------------- Scan phases ----------------
    def _reset_phases(self):
        self.phase_status = {key: "pending" for key, _ in self.PHASES}
        self.progress_value = 0
        self.progress_max = 0
        self.eta_text = ""
        self.scan_started = datetime.datetime.now()

    def _set_phase(self, key, status):
        def do():
            self.phase_status[key] = status
            if self.active_tab == "dashboard":
                self._draw_dashboard()

        self.root.after(0, do)

    def _progress_update(self, done, total):
        if total <= 0:
            return
        started = self.scan_started or datetime.datetime.now()
        elapsed = max(0.0, (datetime.datetime.now() - started).total_seconds())
        fraction = min(1.0, done / total)
        eta = (elapsed / fraction - elapsed) if fraction > 0.02 else None
        self.progress_value = done
        self.progress_max = total
        self.eta_text = f"{done}/{total} · {fraction * 100:.0f}% · ETA {fmt_eta(eta)}"

        def do():
            self.progress.config(mode="determinate", maximum=max(1, total), value=done)
            if self.active_tab == "dashboard":
                self._draw_dashboard()

        self.root.after(0, do)
