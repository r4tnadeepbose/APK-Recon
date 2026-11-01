# Architecture

APK-Recon is a small layered desktop app. `main.py` is only a launcher; everything else lives in
the `apkrecon` package.

```
main.py                     launcher (Tk root + APKReconGUI)
└── apkrecon/
    ├── config.py           palette, severity model, catalogs, paths
    ├── regexes.py          compiled patterns + marker lookups
    ├── scanner.py          ScanResult, extraction pass, inventory, helpers
    ├── findings.py         risk scoring + MASVS mapping
    ├── androguard_support.py  optional androguard import
    ├── templates_loader.py    reads files under templates/
    ├── templates/
    │   ├── report.css      HTML report stylesheet
    │   └── report.html     HTML report shell
    └── ui/
        ├── app.py          composition, window, actions, diff, log
        ├── theme.py        button/entry/panel factories
        ├── scan.py         scan orchestration + decompilers
        ├── render.py       ScanResult → raw item lists for every view
        ├── dashboard.py    canvas charts + scan pipeline + phases
        ├── textviews.py    text insertion/filter/copy + reference pages
        ├── dialogs.py      configuration, scan setup + how-to dialogs
        └── reports.py      JSON / CSV / TXT / Markdown / HTML export
```

## Layers

| Layer | Modules | Responsibility |
| --- | --- | --- |
| Static data | `config`, `regexes` | Everything that never mutates: theme, severity weights, marker catalogs, endpoint/secret regexes, paths. |
| Analysis | `scanner`, `findings` | Pure functions over strings and archives. No Tk imports, easy to test or reuse headless. |
| UI | `ui/*` | Tkinter mixins. `app` composes them into one class via multiple inheritance. |
| Reporting | `ui/reports` + `templates/` | Serialises the session; the HTML shell and CSS are plain files. |

`scanner` and `findings` do not import Tk, so they can be exercised from scripts:

```python
from apkrecon.scanner import ScanResult, scan_text, collect_apk_inventory
from apkrecon.findings import compute_findings

result = scan_text(open("strings.xml", encoding="utf-8").read(), "res/values/strings.xml")
findings, score, grade = compute_findings(result)
```

## Data flow

```
APK ──► scan.py ──► ScanResult ──► render.py ──► raw item lists
                        │                              │
                        │                              ├──► text views (filterable)
                        │                              ├──► dashboard charts
                        │                              └──► log / counts / KPIs
                        └──► findings.py ──► findings + score + grade + MASVS
                                                  │
                                                  └──► reports.py ──► HTML / MD / JSON / CSV / TXT
```

A raw item is a `(text, kind, extra)` tuple. `render` produces them for every tab; `textviews`
knows how to colour each `kind` (`hdr`, `kv`, `finding`, `evidence`, `secret`, `link`, `entropy`,
`perm`, `comp`, `bullet`, …). Filtering and omni-search operate on the same tuples, so a new view
gets the filter for free.

## Scanning pipeline

`ui/scan.py` runs five phases on a worker thread. Before starting, `ask_scan_setup()` (in
`ui/dialogs.py`) optionally presents the engine chooser with live availability and scan options;
`scan_text(..., deep=False)` skips the entropy pass for a faster run.

1. **ARCHIVE** — zip central directory (`collect_apk_inventory`)
2. **MANIFEST** — androguard metadata, manifest flags, exported components, signing
3. **EXTRACT** — DEX blobs or jadx/apktool output (cached in `decompiled_apk_temp/`)
4. **SCAN** — parallel `scan_text()` over DEX blobs or decompiled files
5. **RISK** — `compute_findings()` + `compute_masvs()` + dashboard charts

UI updates from the worker always go through `root.after(...)`. Progress, ETA and phase state are
stored as plain attributes and rendered by `dashboard.py`; the spinner is an `after()` loop that
stops when `self.running` becomes false.

## Extension points

- **New indicator regex** → add the pattern in `regexes.py`; add a severity in `config.py`
  (`SECRET_SEVERITY`) if it should produce findings.
- **New SDK/tracker** → add markers to `config.SDK_MARKERS`; no other change needed.
- **New finding rule** → add a rule in `findings.compute_findings` (with optional evidence
  samples) and, if relevant, a MASVS mapping in `compute_masvs`.
- **New view** → add a key/label to `TABS` and `NAV` in `ui/app.py`; add its raw items in
  `ui/render.py`; pick existing insertion kinds or extend `_insert_item` in `ui/textviews.py`.
- **New chart** → extend `chart_data` in `ui/render.py` and draw it in `ui/dashboard.py`.
- **New export format** → add a filetype and branch in `ui/reports.py::export_results`.
- **HTML layout change** → edit `apkrecon/templates/report.css` / `report.html`; no Python edit
  needed for styling.

## Runtime files

| Path | Created when | Purpose |
| --- | --- | --- |
| `apk_recon_settings.json` | first save/close | engine, workers, tool paths, auto HTML, last directory |
| `decompiled_apk_temp/` | first decompiled scan | jadx/apktool output + engine marker |
| `apk_recon_history.json` | after the first successful scan | last 100 scans: time, apk, engine, duration, counts, risk, report path |
| `reports/` | first HTML report | timestamped `<apk>-YYYYMMDD-HHMMSS.html` |

Paths are derived from the package location (`config.APP_DIR`), so launching `main.py` from any
working directory still writes next to the project.

## History and performance

- `_record_history()` (in `ui/app.py`) appends a compact session record after each successful
  scan and refreshes the History view; the file is capped at 100 entries.
- Filter changes are debounced (120 ms) through `_schedule_filter`; clearing the filter applies
  immediately.
- `render` keeps each view's raw items so filtering and omni-search never re-scan the APK.

## Manual test checklist

1. `python main.py` opens with BROWSE red and ANALYZE disabled.
2. Select an APK → BROWSE returns to neutral, ANALYZE turns red.
3. Run a scan → pipeline animates, log streams, dashboard fills.
4. Check findings evidence, MASVS report, inventory, hosts, entropy, signals.
5. Export HTML/Markdown/JSON; toggle Auto HTML off/on.
6. Export JSON, rescan, use COMPARE for a baseline diff.
7. Filter (plain + regex) on a few views; open `?` and CONFIG dialogs.
