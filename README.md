# APK-Recon

**Local-first Android reconnaissance.** Point APK-Recon at an `.apk` and it turns the package into
a reviewable security picture — endpoints and hosts, deep links, hardcoded secrets, SDKs, risky
permissions, exported components, signing details, archive inventory and more — with graded,
evidence-backed findings and a report you can hand over.

Everything runs on your machine. No uploads, no telemetry, no network access.

---

## What it does

APK-Recon performs static analysis of an Android package and collects the things a security review
actually needs:

- **Endpoints & infrastructure** — URLs, hosts, domains, IPs, emails, file extensions, deep links,
  query parameters and path prefixes.
- **Secrets & indicators** — a ~40-category regex catalog (cloud keys, payment keys, tokens,
  webhooks, private keys, wallets, generic credentials) plus high-entropy string candidates.
- **App surface** — manifest flags, exported activities/services/receivers/providers, deep-link
  routes, SDK/tracker fingerprints and platform hardening signals.
- **Build facts** — APK inventory (DEX, native ABIs, assets, resources, largest entries), signing
  schemes, certificate subject/issuer/SHA-256/expiry.
- **Judgement** — severity-rated findings with evidence samples, a 0–100 risk score, an OWASP MASVS
  posture report, a security checklist, and repeatable build-to-build diffs.

Results are searchable in the app and exportable as **HTML**, **Markdown**, **JSON**, **CSV** or
plain text.

---

## The problem it solves

Reviewing an APK manually is slow and easy to do inconsistently: unzip it, decompile it, grep
through thousands of files, collect keys by hand, remember which manifest flags matter, translate
all of that into MASVS language, and then write a report.

APK-Recon compresses that into a single pass with a consistent method:

1. **Find** everything in one scan.
2. **Triage** it with severity, risk and MASVS mapping.
3. **Prove** it with evidence — the actual value, file, component or manifest attribute.
4. **Report** it as a styled HTML page or Markdown, and **compare** it with the next build.

It is designed for authorized security testing, app hardening reviews, due diligence and CI-style
regression checks — not for inspecting apps you do not have permission to assess.

---

## Why it is useful

- **One window, no tool juggling** — inventory, decompile, pattern scan, manifest/signing checks
  and reporting are already wired together.
- **Evidence-first findings** — every CRITICAL/HIGH/MEDIUM finding shows the value or attribute
  that triggered it, plus its source file.
- **Prioritisation, not noise** — weighted scoring, severity caps and MASVS coverage tell you what
  matters first; entropy and informational items are clearly separated.
- **Repeatable across releases** — local scan history plus baseline diff show exactly what changed
  between builds.
- **Offline by design** — nothing leaves the machine; no API keys, no cloud account, no telemetry.
- **Report-ready** — a self-contained HTML report opens automatically after a scan (toggleable) and
  can be regenerated at any time.
- **Fast and configurable** — choose androguard/DEX-only, jadx or apktool; enable deep strings or
  skip them; tune workers; reuse decompiled output.
- **Comfortable UI** — dark and light themes, monospace layout, keyboard shortcuts, full-row
  checkbox engine selection, instant search across every view.

---

## Screenshots

These four views show the core workflow without duplicating every navigation tab. They are captured
from the real desktop UI and the generated report using the synthetic demo dataset.

![Dashboard](docs/screenshots/dashboard.png)

![Findings](docs/screenshots/findings.png)

![Scan setup](docs/screenshots/setup.png)

![HTML report](docs/screenshots/html-report.png)

---

## Download & install

APK-Recon is a self-contained Python/Tk application: no server, no build step, and **no required
pip packages**.

### Get the files

If you received a `.zip`, extract it. Otherwise clone the repository:

```bash
git clone https://github.com/r4tnadeepbose/APK-Recon.git
cd APK-Recon
```

No Git installed? Use GitHub's **Code → Download ZIP**, or copy the folder you already have. Keep
the layout intact — `main.py` must sit next to the `apkrecon/` package:

```
APK-Recon/
├─ main.py
├─ apkrecon/
├─ docs/
└─ requirements.txt
```

Update later with `cd APK-Recon && git pull`.

### Windows 10 / 11

1. **Install Python 3.10+** from [python.org](https://www.python.org/downloads/) and tick
   **"Add python.exe to PATH"**. Tkinter is included. Verify:
   ```powershell
   py -3 --version
   ```
2. **Optional, recommended — androguard** (fast DEX engine, manifest and signing analysis):
   ```powershell
   py -3 -m pip install --upgrade androguard
   ```
3. **Optional decompilers** — auto-detected, or set custom paths in **CONFIG**:
   - **jadx** — `bin\jadx.bat` in `C:\jadx`, Program Files, Scoop/Chocolatey or on PATH. A
     `jadx-gui-*-with-jre-win` bundle in Downloads is detected automatically and runs through its
     bundled JRE (no separate Java install needed).
   - **apktool** — place `apktool.jar` and `apktool.bat` in `C:\apktool`.
4. **Run** — double-click `main.py`, or:
   ```powershell
   cd C:\path\to\APK-Recon
   py -3 main.py
   ```

### Kali Linux

1. **Base packages** (Python + Tk + Java for the decompilers):
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-tk python3-venv openjdk-17-jre-headless
   ```
2. **Optional decompilers** (when available in your Kali release):
   ```bash
   sudo apt install -y jadx apktool
   ```
   Otherwise download the upstream releases and point **CONFIG** at them.
3. **Get the app and install androguard in a venv**:
   ```bash
   mkdir -p ~/tools && cd ~/tools
   git clone https://github.com/r4tnadeepbose/APK-Recon.git
   cd APK-Recon
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install --upgrade pip
   python -m pip install --upgrade androguard
   ```
   No venv? Kali marks Python as externally managed:
   ```bash
   python3 -m pip install --user androguard
   ```
   Only use `--break-system-packages` if you understand your distribution's policy.
4. **Run** as your desktop user — not `sudo`, so Tk can open a window:
   ```bash
   chmod +x main.py
   ./main.py
   # or
   python3 main.py
   ```
   Works on the Kali XFCE desktop (X11/Wayland + XWayland). A headless SSH session needs X/VNC.

### Requirements at a glance

| Component | Needed for | Windows | Kali |
| --- | --- | --- | --- |
| Python 3.10+ with Tk | the app itself | python.org installer (Tk included) | `python3 python3-tk` |
| [androguard](https://github.com/androguard/androguard) | fast DEX engine, manifest & signing | `py -3 -m pip install androguard` | `pip install androguard` in a venv |
| [jadx](https://github.com/skylot/jadx) | Java/Kotlin decompilation | auto-detect / `C:\jadx` | `apt install jadx` |
| [apktool](https://apktool.org/) | smali / resource decompilation | `C:\apktool` | `apt install apktool` |

Without androguard, inventory/endpoint/secret extraction and reports still work from decompiled
output; APK metadata and signing data stay empty.

> On both platforms `main.py` is the entry point. Settings, history, reports and the decompile
> cache are written next to it. Nothing is uploaded; the app opens no network sockets.

---

## Using APK-Recon

1. **BROWSE** and pick an `.apk`.
2. Click **ANALYZE**; choose an engine in **SCAN SETUP** (auto / dex-only / jadx / apktool), then
   **START SCAN**. Untick “Don’t show this again” to skip the dialog later.
3. Watch the pipeline (`ARCHIVE → MANIFEST → EXTRACT → SCAN → RISK`) or the Activity log.
4. Review **Findings**, **MASVS**, **Hosts**, **Entropy**, **Signals** and the package views.
5. Export **HTML / Markdown / JSON / CSV / TXT**; scan a newer build and use **COMPARE** for a diff.

`main.py` can be double-clicked from Explorer or launched from any directory.

---

## How the analysis works

- **Pipeline** — inventory → manifest/signing → extract (DEX or decompile) → parallel pattern scan →
  scoring. UI updates are marshalled through `after()`; ETA is derived from completed work.
- **Extraction** — URL schemes, domains, IPv4/IPv6, emails, extensions and a ~40-category secret
  catalog, all compiled into `regexes.py`.
- **Entropy** — tokens ≥ 24 chars with Shannon entropy ≥ 4.3, mixed letters/digits and ≥ 8 unique
  characters; capped and deduped. Can be disabled (“Deep strings”) for speed.
- **Fingerprints** — single-pass alternation regexes for 30+ SDK/tracker markers, weak crypto
  markers and platform signals.
- **Manifest & signing** — androguard reads flags, exported components and certificates
  (subject/issuer/SHA-256/expiry, debug key detection, v1/v2/v3 presence).
- **Risk score** — 100 minus weighted findings (`CRITICAL 28, HIGH 14, MEDIUM 6, LOW 2`), with
  secret penalties capped at 45 and permission penalties at 25; grades A–F.
- **MASVS mapping** — each category is scored from findings, manifest flags, signing data and
  signals, with evidence bullets and official links.
- **Diff** — set comparisons across URLs, domains, permissions, components, SDKs, secrets and
  metadata.
- **History** — last 100 scans stored in `apk_recon_history.json`; clearable from CONFIG.
- **Theming** — two palettes (`DARK`, `LIGHT`); switching rebuilds the widget layer while keeping
  the scan result, history, diff and filter intact.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the module map and extension points.

---

## Keyboard shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl+O` | open APK |
| `F5` | run analysis |
| `Ctrl+F` | focus filter |
| `Ctrl+E` | export |
| `Ctrl+B` | compare baseline |
| `Ctrl+D` | dashboard |
| `Ctrl+H` | HTML report |
| `Ctrl+L` | clear filter |
| `Ctrl+T` | light / dark theme |
| `F1` | how-to guide |

Double-click any result line to copy it. `COPY` copies the visible view (the dashboard copies a
risk/findings summary).

---

## Output formats

| Format | Contents |
| --- | --- |
| HTML | styled, self-contained report with risk ring, findings + evidence, MASVS, inventory |
| Markdown | same report as tables/lists, good for tickets and PRs |
| JSON | full machine-readable result — also the baseline for diffs |
| CSV | category / value / file rows |
| TXT | raw grouped lists |

Auto HTML files land in `reports/` as `<apk>-YYYYMMDD-HHMMSS.html`.

---

## Configuration and runtime files

Saved to `apk_recon_settings.json` next to `main.py`:

- engine (`auto`, `dex-only`, `jadx`, `apktool`), fast mode, cache reuse, workers
- deep string scan, Auto HTML report
- jadx / apktool path overrides
- theme (`dark` / `light`) and last used directory

| Path | Created when | Purpose |
| --- | --- | --- |
| `apk_recon_settings.json` | first save/close | persisted preferences |
| `apk_recon_history.json` | after the first scan | last 100 scans (time, engine, counts, risk, report) |
| `decompiled_apk_temp/` | first decompiled scan | jadx/apktool output cache |
| `reports/` | first HTML report | timestamped self-contained reports |

---

## Project layout

`main.py` is a small launcher; the application is split into focused modules:

```
main.py                        launcher (Tk root + APKReconGUI)
apkrecon/
  config.py                    palettes, severity model, catalogs, paths
  regexes.py                   endpoint / secret / fingerprint patterns
  scanner.py                   ScanResult, extraction pass, inventory, JADX discovery
  findings.py                  risk scoring + MASVS mapping
  androguard_support.py        optional androguard import
  templates_loader.py          template reader
  templates/report.css         HTML report stylesheet
  templates/report.html        HTML report shell
  ui/
    app.py                     composition, window, actions, diff, log, theme switch
    theme.py                   widget factories
    scan.py                    scan orchestration + decompilers
    render.py                  ScanResult → per-view item lists
    dashboard.py               canvas charts + pipeline + phases
    textviews.py               insertion, filtering, reference pages
    dialogs.py                 configuration, scan setup, how-to
    reports.py                 JSON / CSV / TXT / Markdown / HTML export
requirements.txt               optional dependencies
docs/ARCHITECTURE.md           module map, data flow, extension points
docs/screenshots/              screenshots used in this README
```

---

## Limits and responsible use

- Static analysis only: obfuscated, packed or dynamically loaded code can hide data.
- Secrets are regex/heuristic leads — **verify before reporting or acting on them**.
- Entropy candidates are noisy by design; treat them as leads.
- APK metadata, signing and manifest flags require `androguard`.
- Use APK-Recon only on applications you own or are authorised to assess.
