import os
import time
import tkinter as tk

from apkrecon import config
from apkrecon.scanner import ScanResult, scan_text
from apkrecon.ui.app import APKReconGUI

# deep flag
sample = "Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZmdoaWo md5"
assert scan_text(sample, "x", deep=True).entropy
assert not scan_text(sample, "x", deep=False).entropy

if os.path.isfile(config.HISTORY_PATH):
    os.remove(config.HISTORY_PATH)

root = tk.Tk()
app = APKReconGUI(root)
root.geometry("1320x900+40+20")
root.update()

r = ScanResult()
r.urls |= {"https://api.example.com/v1/login", "http://legacy.example.org/track?id=1",
           "myapp://open/detail?id=42"}
r.domains |= {"api.example.com", "legacy.example.org"}
r.secrets = [("AWS Access Key", "AKIAIOSFODNN7EXAMPLE", "assets/config.json"),
             ("JWT Token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.demo", "Auth.smali")]
r.metadata = {"Package": "com.example.app", "Version": "1.2.3",
              "Min SDK": "24", "Target SDK": "34"}
r.permissions = {"android.permission.INTERNET", "android.permission.READ_SMS"}
r.files_scanned = 800
r.entropy = {"Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZg": (4.61, "classes.dex")}
r.sdks = {"Firebase": {"firebaseio.com"}}
r.security = {"debuggable": False, "allow_backup": True, "cleartext": True,
              "components": [], "exported": [],
              "signature": {"available": True, "v1_meta": True, "v2": True, "v3": True,
                            "debug": False,
                            "certs": [{"sha256": "ab" * 32, "subject": "CN=Demo",
                                       "issuer": "CN=Demo", "not_after": "2031-01-01",
                                       "expired": False}]}}
r.inventory = {"apk_size": 5_000_000, "entries": 500, "uncompressed": 12_000_000,
               "dex_count": 2, "dex_bytes": 4_000_000, "so_count": 3,
               "abis": ["arm64-v8a"], "so_sample": ["lib/arm64-v8a/libapp.so"],
               "assets": 50, "res": 220, "signature_files": ["META-INF/CERT.RSA"],
               "largest": [(2_000_000, "classes.dex")]}
app.current_apk_path = "C:/samples/example.apk"
app.path_var.set(app.current_apk_path)
app._sync_buttons()
app.result = r
app.phase_status = {key: "done" for key, _ in app.PHASES}
app.eta_text = "complete"
app._render()
root.update()

assert app.chart_data["target"]["package"] == "com.example.app"
assert app.chart_data["target"]["signed"] is True
assert app.chart_data["target"]["engine"]
assert app.chart_data["top_findings"]
assert len(app.chart_data["masvs"]) == 8

app._switch_tab("dashboard")
root.update()
assert len(app.dash_canvas.find_all()) > 60

# history
app.last_engine = "dex-only"
app.last_duration = 4.2
app._record_history()
root.update()
assert len(app.history) == 1
assert os.path.isfile(config.HISTORY_PATH)
app._switch_tab("history")
history_text = app.text_widgets["history"].get("1.0", "end")
assert "RECENT SCANS" in history_text and "example.apk" in history_text
assert "dex-only" in history_text

# debounced filter
app._switch_tab("urls")
app.search_var.set("api.example.com")
root.update()
assert app._filter_job is not None
deadline = time.time() + 1.2
while time.time() < deadline:
    root.update()
    time.sleep(0.05)
urls_text = app.text_widgets["urls"].get("1.0", "end")
assert "api.example.com" in urls_text and "legacy.example.org" not in urls_text
app.clear_filter()
root.update()
assert app._filter_job is None

# clear history
import apkrecon.ui.app as app_module
app_module.messagebox.askyesno = lambda *args, **kwargs: True
app.clear_history()
root.update()
assert app.history == []
app._switch_tab("history")
assert "no earlier scans" in app.text_widgets["history"].get("1.0", "end")

root.after(50, root.destroy)
root.mainloop()
if os.path.isfile(config.HISTORY_PATH):
    os.remove(config.HISTORY_PATH)
print("SMOKE2 OK")
