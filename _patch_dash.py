p = "apkrecon/ui/dashboard.py"
s = open(p, encoding="utf-8").read()

old = '''        margin, gap, strip_h = 16, 12, 86
        self._draw_phase_strip(canvas, margin, margin, width - 2 * margin, strip_h)

        top = margin + strip_h + gap
        available = height - top - margin
        if available < 70:
            return

        left_w = int((width - 2 * margin - gap) * 0.44)
        row1_h = int(available * 0.52)
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
        half = int((width - 2 * margin - gap) / 2)
        self._draw_bars(canvas, margin, row2, half, row2_h, "TOP HOSTS",
                        self.chart_data.get("hosts", []), PALETTE["accent"])
        secret_rows = [
            (f"{cat}", count, SEVERITY_COLORS.get(sev, PALETTE["text"]))
            for cat, count, sev in self.chart_data.get("secrets", [])
        ]
        self._draw_bars(canvas, margin + half + gap, row2,
                        width - 2 * margin - half - gap, row2_h,
                        "SECRET CATEGORIES", secret_rows, colored=True)'''

new = '''        compact = height < 520
        margin, gap = 16, 12
        target_h = 46 if compact else 58
        strip_h = 70 if compact else 82

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
        columns = 3 if width >= 1180 else 2
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
            right = self._chip(canvas, right, y + h / 2, text, color)'''

if old not in s:
    raise SystemExit("layout block not found")
s = s.replace(old, new)

old_sev = '''        legend_x = cx + radius + 26
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
            legend_y += spacing'''

new_sev = old_sev + '''

        masvs = self.chart_data.get("masvs") or []
        if masvs and h >= 200:
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
                right = left - 4'''

if old_sev not in s:
    raise SystemExit("severity block not found")
s = s.replace(old_sev, new_sev)

marker = "    def _draw_bars(self, canvas, x, y, w, h, title, items, color=None, colored=False):"
findings_card = '''    def _draw_findings_card(self, canvas, x, y, w, h):
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
        row_h = area / min(len(findings), 6)
        chars = max(10, int((w - 96) / 6.6))
        for index, (title, severity) in enumerate(findings[:6]):
            color = SEVERITY_COLORS.get(severity, PALETTE["text"])
            line_y = top + row_h * (index + 0.5)
            canvas.create_text(x + 14, line_y, text=severity[:4], anchor="w",
                               fill=color, font=self.f_bold)
            shown = title if len(title) <= chars else title[:chars - 1] + "…"
            canvas.create_text(x + 62, line_y, text=shown, anchor="w",
                               fill=PALETTE["text"], font=self.f_sm)

'''
s = s.replace(marker, findings_card + marker, 1)
open(p, "w", encoding="utf-8").write(s)
print("dashboard patched")
