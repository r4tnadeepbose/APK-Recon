p = "apkrecon/ui/dashboard.py"
s = open(p, encoding="utf-8").read()

s = s.replace(
'''        compact = height < 520
        margin, gap = 16, 12
        target_h = 46 if compact else 58
        strip_h = 70 if compact else 82''',
'''        compact = height < 520
        margin, gap = 16, 12
        target_h = 50 if compact else 58
        strip_h = 80''')

s = s.replace("        columns = 3 if width >= 1180 else 2",
              "        columns = 3 if width >= 1000 else 2")

old_bars = '''        top = y + 44
        area = h - 58
        if area < 40:
            return
        row_h = area / min(len(items), 7)
        max_value = max(item[1] for item in items) or 1
        chars = max(8, int((w - 90) / 7))
        for index, item in enumerate(items[:7]):'''
new_bars = '''        top = y + 44
        area = h - 58
        if area < 40:
            return
        row_capacity = max(1, int(area / 24))
        shown = min(len(items), 7, row_capacity)
        row_h = area / shown
        max_value = max(item[1] for item in items) or 1
        chars = max(8, int((w - 90) / 7))
        for index, item in enumerate(items[:shown]):'''
if old_bars not in s:
    raise SystemExit("bars block not found")
s = s.replace(old_bars, new_bars)

old_find = '''        top = y + 44
        area = h - 58
        if area < 30:
            return
        row_h = area / min(len(findings), 6)
        chars = max(10, int((w - 96) / 6.6))
        for index, (title, severity) in enumerate(findings[:6]):'''
new_find = '''        top = y + 44
        area = h - 58
        if area < 30:
            return
        row_capacity = max(1, int(area / 20))
        shown = min(len(findings), 6, row_capacity)
        row_h = area / shown
        chars = max(10, int((w - 96) / 6.6))
        for index, (title, severity) in enumerate(findings[:shown]):'''
if old_find not in s:
    raise SystemExit("findings block not found")
s = s.replace(old_find, new_find)

open(p, "w", encoding="utf-8").write(s)
print("dashboard adjusted")
