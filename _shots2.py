import sys
import tkinter as tk

from apkrecon.scanner import ScanResult
from apkrecon.ui.app import APKReconGUI

MODE = sys.argv[1] if len(sys.argv) > 1 else "dashboard"

root = tk.Tk()
app = APKReconGUI(root)
root.state("normal")
root.geometry("1600x1000+30+20" if MODE in ("dashboard", "initial") else "1320x900+40+20")
root.update()

if MODE != "initial":
    app.current_apk_path = "C:/samples/zepto-demo-3.1.0.apk"
    app.path_var.set(app.current_apk_path)
    app._sync_buttons()
    r = ScanResult()
    r.urls |= {
        "https://api.zepto.example/v2/cart?limit=20&page=1",
        "https://api.zepto.example/v2/checkout",
        "https://api.zepto.example/v2/profile/me",
        "https://cdn.zepto.example/assets/app.bundle.js",
        "https://track.thirdparty.example/collect?uid=abc123",
        "http://legacy.zepto.example:8080/redirect?id=1",
        "wss://socket.zepto.example/live?token=abc",
        "myapp://open/product/123",
    }
    r.domains |= {"api.zepto.example", "cdn.zepto.example", "legacy.zepto.example",
                  "socket.zepto.example", "firebaseio.com", "sentry.io"}
    r.ips |= {"10.0.0.7", "192.168.29.4"}
    r.emails |= {"dev@zepto.example"}
    r.exts |= {".json", ".so", ".xml", ".dex"}
    r.secrets = [
        ("AWS Access Key", "AKIAIOSFODNN7EXAMPLE", "assets/config.json"),
        ("Google API Key", "AIzaSyD3xAmP1eK3yF0rD3m0PuRp0s3sAbCdEfG", "res/values/strings.xml"),
        ("JWT Token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.demo", "Auth.smali"),
        ("Basic Auth", "Basic ZGVtbzpwYXNzd29yZDEyMw==", "strings.xml"),
    ]
    r.entropy = {"Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZmdoaWo": (4.71, "classes.dex"),
                 "QWxhZGRpbjpvcGVuIHNlc2FtZQ": (4.52, "strings.xml")}
    r.crypto = {"MD5": 12, "AES/ECB mode": 3}
    r.signals = {"Certificate pinning": 6, "Root detection": 2, "WebView bridge": 3}
    r.sdks = {"Firebase": {"firebaseio.com"}, "AppsFlyer": {"com.appsflyer"},
              "Sentry": {"io.sentry"}, "OkHttp": {"okhttp3"}, "Retrofit": {"retrofit2"}}
    r.files_scanned = 1842
    r.metadata = {"Package": "com.zepto.demo", "App name": "Zepto Demo",
                  "Version": "3.1.0", "Min SDK": "24", "Target SDK": "34"}
    r.permissions = {"android.permission.INTERNET", "android.permission.CAMERA",
                     "android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_SMS",
                     "android.permission.RECEIVE_BOOT_COMPLETED"}
    r.components = ["Activities: com.zepto.demo.MainActivity",
                    "Providers: com.zepto.demo.DataProvider"]
    r.inventory = {"apk_size": 18_923_520, "entries": 2210, "uncompressed": 52_331_776,
                   "dex_count": 3, "dex_bytes": 24_117_248, "so_count": 14,
                   "abis": ["arm64-v8a", "armeabi-v7a"], "so_sample": ["lib/arm64-v8a/libapp.so"],
                   "assets": 260, "res": 1204,
                   "signature_files": ["META-INF/CERT.RSA"],
                   "largest": [(7_340_032, "classes2.dex")]}
    r.security = {"debuggable": True, "allow_backup": True, "cleartext": True,
                  "components": [], "exported": [],
                  "signature": {"available": True, "v1_meta": True, "v2": True,
                                "v3": True, "debug": False,
                                "certs": [{"sha256": "ab" * 32, "subject": "CN=Zepto Release",
                                           "issuer": "CN=Zepto Release",
                                           "not_after": "2031-06-01", "expired": False}]}}
    app.result = r
    app.last_engine = "dex-only"
    app.phase_status = {key: "done" for key, _ in app.PHASES}
    app.progress_value = 1842
    app.progress_max = 1842
    app.eta_text = "complete"
    app._render()
    for line, tag in (
        ("inventory: 2210 entries / 3 dex / 14 libs", "muted"),
        ("manifest: debug=True backup=True exported=4", "muted"),
        ("engine=dex-only workers=16 deep=on", "muted"),
        ("complete in 8.4s · urls=8 secrets=4 sdks=5", "accent"),
    ):
        app._log(line, tag)

    if MODE == "history":
        import datetime
        now = datetime.datetime.now()
        samples = [
            ("zepto-demo-3.1.0.apk", "3.1.0", 34, "F", 18, 5, 8, 4, 1842, 8.4, "dex-only"),
            ("zepto-demo-2.9.4.apk", "2.9.4", 62, "C", 9, 2, 6, 2, 1790, 9.1, "jadx"),
            ("partner-debug.apk", "0.9.1", 12, "F", 24, 7, 12, 3, 2010, 4.8, "apktool"),
        ]
        app.history = []
        for index, (apk, version, risk, grade, findings, secrets, urls, sdks,
                    files, duration, engine) in enumerate(samples):
            app.history.append({
                "time": (now - datetime.timedelta(days=index, hours=2)).isoformat(timespec="seconds"),
                "apk": apk, "path": "C:/samples/" + apk, "package": "com.zepto.demo",
                "version": version, "engine": engine, "duration": duration,
                "files": files, "urls": urls, "domains": 8, "secrets": secrets,
                "findings": findings, "risk": risk, "grade": grade, "report": "",
            })
        app._refresh_history_views()
        app._switch_tab("history")
    elif MODE in ("help", "settings"):
        app._switch_tab("dashboard")
        opener = app.open_help if MODE == "help" else app.open_settings
        root.after(500, opener)
    elif MODE == "setup":
        app._switch_tab("dashboard")
        root.after(500, app.ask_scan_setup)
    else:
        app._switch_tab("dashboard")
else:
    app._switch_tab("dashboard")

root.update()
root.lift()
root.focus_force()
root.mainloop()
