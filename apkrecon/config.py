"""Static configuration: palette, severity model, catalogs and paths."""

import os

# ---------------------------------------------------------------------------
# Paths (resolved from the package location so double-clicking main.py works)
# ---------------------------------------------------------------------------

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DECOMPILE_DIR = os.path.join(APP_DIR, "decompiled_apk_temp")
REPORTS_DIR = os.path.join(APP_DIR, "reports")
SETTINGS_PATH = os.path.join(APP_DIR, "apk_recon_settings.json")
HISTORY_PATH = os.path.join(APP_DIR, "apk_recon_history.json")
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
ENGINE_MARKER = ".apkrecon-engine"

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

DARK = {
    "bg":           "#0a0b0a",
    "surface":      "#111312",
    "surface_alt":  "#171a18",
    "active":       "#16211a",
    "input":        "#0d0f0e",
    "border":       "#242824",
    "border_soft":  "#1b1e1b",
    "text":         "#c9cec8",
    "text_bright":  "#eef2ec",
    "muted":        "#767d77",
    "accent":       "#54e08a",
    "accent_active": "#63f29b",
    "accent_dim":   "#1c4a32",
    "accent_soft":  "#2f8a5c",
    "on_accent":    "#04170d",
    "amber":        "#d8a75a",
    "red":          "#e06c6c",
    "danger":       "#e0383f",
    "danger_active": "#e8737a",
    "danger_dim":   "#3a1518",
    "on_danger":    "#ffffff",
    "on_danger_active": "#2b0709",
    "evidence":     "#9aa39a",
    "critical":     "#ef5f6b",
    "high":         "#e0a35a",
    "medium":       "#d6c76a",
    "low":          "#8b958c",
    "ok":           "#54e08a",
}

LIGHT = {
    "bg":           "#f2f4f1",
    "surface":      "#ffffff",
    "surface_alt":  "#f0f2ef",
    "active":       "#e3f2e9",
    "input":        "#fafbf9",
    "border":       "#d7dbd4",
    "border_soft":  "#e7eae4",
    "text":         "#3a403a",
    "text_bright":  "#121612",
    "muted":        "#6d756d",
    "accent":       "#1b8a50",
    "accent_active": "#146e40",
    "accent_dim":   "#c5e9d6",
    "accent_soft":  "#2f8a5c",
    "on_accent":    "#ffffff",
    "amber":        "#96620f",
    "red":          "#c0393f",
    "danger":       "#c92f36",
    "danger_active": "#ef8a8f",
    "danger_dim":   "#f7dcdd",
    "on_danger":    "#ffffff",
    "on_danger_active": "#3a0a0c",
    "evidence":     "#5f675f",
    "critical":     "#b8232b",
    "high":         "#96620f",
    "medium":       "#7a6a12",
    "low":          "#5f6a60",
    "ok":           "#1b8a50",
}

THEMES = {"dark": DARK, "light": LIGHT}
PALETTE = dict(DARK)


SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

SEVERITY_COLORS = {
    "CRITICAL": PALETTE["critical"],
    "HIGH":     PALETTE["high"],
    "MEDIUM":   PALETTE["medium"],
    "LOW":      PALETTE["low"],
    "INFO":     PALETTE["muted"],
}

SEVERITY_WEIGHT = {
    "CRITICAL": 28, "HIGH": 14, "MEDIUM": 6, "LOW": 2, "INFO": 0,
}


def apply_theme(name):
    """Switch the shared palette in place so every import sees the change."""
    palette = THEMES.get(name, DARK)
    PALETTE.clear()
    PALETTE.update(palette)
    SEVERITY_COLORS.update({
        "CRITICAL": PALETTE["critical"],
        "HIGH": PALETTE["high"],
        "MEDIUM": PALETTE["medium"],
        "LOW": PALETTE["low"],
        "INFO": PALETTE["muted"],
    })

SECRET_SEVERITY = {
    "AWS Access Key": "CRITICAL",
    "AWS Secret (heuristic)": "CRITICAL",
    "Azure Storage Key": "CRITICAL",
    "GCP Service Account": "CRITICAL",
    "Private Key Block": "CRITICAL",
    "Private key (generic)": "CRITICAL",
    "Stripe Live Secret": "CRITICAL",
    "Mnemonic (heuristic)": "CRITICAL",
    "Firebase Server Key": "HIGH",
    "Google API Key": "MEDIUM",
    "Slack Token": "HIGH",
    "Slack Webhook": "HIGH",
    "Discord Webhook": "HIGH",
    "Telegram Bot Token": "HIGH",
    "SendGrid Key": "HIGH",
    "Mailgun Key": "HIGH",
    "GitHub Token": "CRITICAL",
    "GitLab Token": "CRITICAL",
    "npm Token": "HIGH",
    "PyPI Token": "HIGH",
    "Twilio SID": "MEDIUM",
    "Stripe Test Secret": "MEDIUM",
    "Mapbox Token": "MEDIUM",
    "JWT Token": "MEDIUM",
    "Generic Bearer": "MEDIUM",
    "Basic Auth": "HIGH",
    "Password (heuristic)": "HIGH",
    "API Key (heuristic)": "MEDIUM",
    "Bitcoin Address": "LOW",
    "Ethereum Address": "LOW",
    "Google OAuth Client": "LOW",
    "Firebase URL": "LOW",
    "Firebase Storage": "LOW",
    "S3 Bucket URL": "MEDIUM",
    "S3 Bucket (bare)": "MEDIUM",
    "GCS Bucket": "MEDIUM",
    "PayPal Client ID": "LOW",
    "Facebook App ID": "LOW",
    "Deep Link": "LOW",
}

# last path segment -> (severity, label)
DANGEROUS_PERMISSIONS = {
    "READ_SMS":                   ("HIGH", "reads SMS"),
    "SEND_SMS":                   ("HIGH", "sends SMS"),
    "RECEIVE_SMS":                ("HIGH", "receives SMS"),
    "READ_CALL_LOG":              ("HIGH", "reads call log"),
    "WRITE_CALL_LOG":             ("HIGH", "writes call log"),
    "READ_CONTACTS":              ("HIGH", "reads contacts"),
    "WRITE_CONTACTS":             ("HIGH", "writes contacts"),
    "RECORD_AUDIO":               ("HIGH", "microphone"),
    "ACCESS_FINE_LOCATION":       ("HIGH", "precise location"),
    "ACCESS_BACKGROUND_LOCATION": ("HIGH", "background location"),
    "ACCESS_COARSE_LOCATION":     ("MEDIUM", "coarse location"),
    "CAMERA":                     ("MEDIUM", "camera"),
    "SYSTEM_ALERT_WINDOW":        ("HIGH", "overlay window"),
    "REQUEST_INSTALL_PACKAGES":   ("HIGH", "installs packages"),
    "BIND_ACCESSIBILITY_SERVICE": ("CRITICAL", "accessibility service"),
    "READ_PHONE_STATE":           ("MEDIUM", "phone state"),
    "READ_EXTERNAL_STORAGE":      ("MEDIUM", "external storage"),
    "WRITE_EXTERNAL_STORAGE":     ("MEDIUM", "external storage"),
    "MANAGE_EXTERNAL_STORAGE":    ("HIGH", "all-files access"),
    "QUERY_ALL_PACKAGES":         ("MEDIUM", "queries all packages"),
    "RECEIVE_BOOT_COMPLETED":     ("LOW", "autostart"),
    "POST_NOTIFICATIONS":         ("LOW", "notifications"),
}

# ---------------------------------------------------------------------------
# Fingerprint catalogs
# ---------------------------------------------------------------------------

SDK_MARKERS = {
    "Firebase":             ("firebaseio.com", "com.google.firebase", "firebasemessaging"),
    "Google Play Services": ("com.google.android.gms",),
    "AdMob":                ("com.google.android.gms.ads",),
    "Google Maps":          ("com.google.android.gms.maps",),
    "Facebook SDK":         ("com.facebook.android", "com.facebook.login", "facebook_app_id"),
    "Crashlytics":          ("com.crashlytics", "firebase-crashlytics"),
    "Sentry":               ("io.sentry", "sentry.io"),
    "Adjust":               ("com.adjust.sdk",),
    "AppsFlyer":            ("com.appsflyer",),
    "Amplitude":            ("com.amplitude",),
    "Mixpanel":             ("com.mixpanel",),
    "OneSignal":            ("onesignal",),
    "Branch":               ("io.branch",),
    "Braze":                ("com.appboy", "com.braze"),
    "Segment":              ("com.segment.analytics",),
    "Flurry":               ("com.flurry",),
    "Unity":                ("com.unity3d",),
    "Flutter":              ("io.flutter", "flutter."),
    "React Native":         ("com.facebook.react",),
    "Cordova":              ("org.apache.cordova",),
    "Xamarin":              ("mono.android", "xamarin"),
    "Stripe":               ("com.stripe",),
    "Braintree":            ("com.braintreepayments",),
    "Razorpay":             ("com.razorpay",),
    "Intercom":             ("io.intercom",),
    "Zendesk":              ("com.zendesk",),
    "Mapbox":               ("com.mapbox",),
    "OkHttp":               ("okhttp3",),
    "Retrofit":             ("retrofit2",),
    "Socket.IO":            ("socket.io",),
    "AWS Mobile":           ("com.amazonaws.mobile",),
    "Twilio":               ("com.twilio",),
}

CRYPTO_MARKERS = {
    "AES/ECB mode":  ("aes/ecb", "ecbencrypt", "aes/ecb/pkcs5"),
    "DES / 3DES":    ("desede", "des/ecb", "des/cbc", "tripledes"),
    "RC4":           ("rc4",),
    "MD5":           ("md5",),
    "SHA-1":         ("sha-1", "sha1"),
}

SIGNAL_MARKERS = {
    "Certificate pinning":   ("certificatepinner", "network_security_config", "<pin-set>",
                              "x509trustmanager"),
    "Root detection":        ("rootbeer", "isrooted", "/system/xbin/su", "superuser"),
    "Attestation":           ("safetynet", "playintegrity", "attest"),
    "Biometric auth":        ("biometricprompt", "fingerprintmanager", "androidx.biometric"),
    "WebView bridge":        ("addjavascriptinterface",),
    "Dynamic code loading":  ("dexclassloader", "inmemorydexclassloader", "pathclassloader"),
    "Reflection":            ("java.lang.reflect", "class.forname"),
    "Native bridge":         ("system.loadlibrary", "loadlibrary"),
}

ENTROPY_THRESHOLD = 4.3

# ---------------------------------------------------------------------------
# External references and MASVS
# ---------------------------------------------------------------------------

REFERENCE_LINKS = {
    "MASVS":                 "https://mas.owasp.org/MASVS/",
    "MASTG":                 "https://mas.owasp.org/MASTG/",
    "OWASP Mobile Top 10":   "https://owasp.org/www-project-mobile-top-10/",
    "Android security tips": "https://developer.android.com/privacy-and-security/security-tips",
    "Network security config": "https://developer.android.com/privacy-and-security/security-config",
    "Play Integrity API":    "https://developer.android.com/google/play/integrity",
    "APK signature scheme":  "https://source.android.com/docs/security/features/apksigning",
    "jadx":                  "https://github.com/skylot/jadx",
    "apktool":               "https://apktool.org/",
    "androguard":            "https://github.com/androguard/androguard",
}

MASVS_CATEGORIES = [
    ("MASVS-STORAGE", "Storage & data protection",
     "Secrets, backups and local storage of sensitive data."),
    ("MASVS-CRYPTO", "Cryptography",
     "Correct use of cryptography and secure random sources."),
    ("MASVS-AUTH", "Authentication & authorization",
     "Authentication material and session handling."),
    ("MASVS-NETWORK", "Network communication",
     "Transport security, cleartext traffic and endpoint hygiene."),
    ("MASVS-PLATFORM", "Platform interaction",
     "Exported components, deep links and IPC surface."),
    ("MASVS-CODE", "Code quality & build settings",
     "Debug flags, build hardening and platform versions."),
    ("MASVS-RESILIENCE", "Resilience against reverse engineering",
     "Signing strength, tamper detection, obfuscation."),
    ("MASVS-PRIVACY", "Privacy",
     "Tracking SDKs, sensitive permissions and data collection."),
]

# ---------------------------------------------------------------------------
# Tooling and scan defaults
# ---------------------------------------------------------------------------

APKTOOL_CANDIDATES = [
    r"C:\apktool\apktool.bat",
    r"C:\apktool\apktool.jar",
    "apktool",
]
JADX_CANDIDATES = [
    r"C:\jadx\bin\jadx.bat",
    r"C:\jadx\bin\jadx",
    r"C:\Program Files\jadx\bin\jadx.bat",
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\jadx\bin\jadx.bat"),
    os.path.expandvars(r"%USERPROFILE%\scoop\apps\jadx\current\bin\jadx.bat"),
    r"C:\ProgramData\chocolatey\bin\jadx.exe",
    "jadx",
]

SCAN_EXTS = (
    '.smali', '.xml', '.json', '.txt', '.js', '.html', '.htm', '.css',
    '.properties', '.java', '.kt', '.yaml', '.yml', '.gradle', '.pro',
    '.cfg', '.conf', '.ini', '.env', '.plist', '.strings',
)
