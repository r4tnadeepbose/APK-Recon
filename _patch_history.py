p = "apkrecon/ui/render.py"
s = open(p, encoding="utf-8").read()
addition = '''
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
'''
if "def _history_items" in s:
    raise SystemExit("already present")
s = s.rstrip() + "\n" + addition
open(p, "w", encoding="utf-8").write(s)
print("history items method appended")
