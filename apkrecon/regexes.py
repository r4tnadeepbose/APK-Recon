"""Compiled regex catalogs used by the scanner."""

import re

from .config import CRYPTO_MARKERS, SDK_MARKERS, SIGNAL_MARKERS

# ---- Endpoint / indicator patterns ---------------------------------------

URL_SCHEMES = (
    r'(?:https?|ftp|ftps|sftp|ws|wss|file|content|android|market|tel|mailto|'
    r'sms|smsto|mms|geo|whatsapp|tg|slack|intent|javascript|data|blob|'
    r'rtsp|rtmp|sip|telnet|ssh|ldap|ldaps|git|svn|nfs|smb|'
    r'oauth|openid|urn|chrome|firefox|app|fb|twitter|skype)'
)

URL_RE = re.compile(
    rf'\b{URL_SCHEMES}://[^\s"\'<>\)\]\}},;]+',
    re.IGNORECASE
)

DOMAIN_RE = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
    r'(?:com|net|org|io|co|app|dev|ai|cloud|tech|me|info|biz|xyz|site|'
    r'online|store|shop|api|gov|edu|mil|int|ru|cn|in|uk|de|jp|br|au|'
    r'ca|fr|nl|es|it|kr|sg|hk|tw|us|tv|fm|gg|to)\b',
    re.IGNORECASE
)

IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b'
)

IPV6_RE = re.compile(
    r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|'
    r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b|'
    r'\b::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}\b'
)

EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)

EXT_RE = re.compile(
    r'\.(apk|dex|jar|so|aar|zip|tar|gz|7z|rar|'
    r'json|xml|yaml|yml|toml|ini|conf|cfg|prop|properties|env|'
    r'html?|css|js|jsx|ts|tsx|vue|svelte|php|asp|aspx|jsp|'
    r'png|jpg|jpeg|gif|bmp|webp|svg|ico|tiff|heic|'
    r'mp3|mp4|wav|ogg|flac|avi|mkv|mov|webm|'
    r'pdf|doc|docx|xls|xlsx|ppt|pptx|csv|txt|md|log|'
    r'sql|db|sqlite|sqlite3|realm|'
    r'ttf|otf|woff|woff2|eot|'
    r'pem|crt|cer|key|p12|pfx|jks|keystore|'
    r'bin|dat|bak|tmp|lock|'
    r'wasm|class|kt|java|smali)\b',
    re.IGNORECASE
)

SECRET_PATTERNS = {
    # Cloud
    "Google API Key":        re.compile(r'AIza[0-9A-Za-z_\-]{35}'),
    "Google OAuth Client":   re.compile(r'\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com'),
    "Firebase Server Key":   re.compile(r'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}'),
    "AWS Access Key":        re.compile(r'AKIA[0-9A-Z]{16}'),
    "AWS Secret (heuristic)":re.compile(r'(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})'),
    "Azure Storage Key":     re.compile(r'AccountKey=[A-Za-z0-9+/=]{88}'),
    "GCP Service Account":   re.compile(r'"type"\s*:\s*"service_account"'),

    # Payments
    "Stripe Live Secret":    re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
    "Stripe Test Secret":    re.compile(r'sk_test_[0-9a-zA-Z]{24,}'),
    "PayPal Client ID":      re.compile(r'A[A-Za-z0-9_\-]{79,}'),

    # Auth / tokens
    "JWT Token":             re.compile(r'eyJ[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+\.?[A-Za-z0-9\-_.+/=]*'),
    "Generic Bearer":        re.compile(r'(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}=*'),
    "Basic Auth":            re.compile(r'(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}'),

    # Communication
    "Slack Token":           re.compile(r'xox[baprs]-[A-Za-z0-9\-]{10,72}'),
    "Slack Webhook":         re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+'),
    "Discord Webhook":       re.compile(r'https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+'),
    "Telegram Bot Token":    re.compile(r'\b\d{8,10}:[A-Za-z0-9_\-]{35}\b'),
    "Twilio SID":            re.compile(r'\bAC[a-f0-9]{32}\b'),
    "SendGrid Key":          re.compile(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
    "Mailgun Key":           re.compile(r'key-[a-f0-9]{32}'),

    # Code hosting / CI
    "GitHub Token":          re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}'),
    "GitLab Token":          re.compile(r'glpat-[A-Za-z0-9_\-]{20,}'),
    "npm Token":             re.compile(r'npm_[A-Za-z0-9]{36}'),
    "PyPI Token":            re.compile(r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{70,}'),

    # Crypto / wallet
    "Bitcoin Address":       re.compile(r'\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b'),
    "Ethereum Address":      re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
    "Private Key Block":     re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----'),
    "Mnemonic (heuristic)":  re.compile(r'(?i)\b(?:mnemonic|seed\s*phrase)\s*[=:]\s*["\'][a-z ]{40,}["\']'),

    # Generic auth
    "Password (heuristic)":  re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']'),
    "API Key (heuristic)":   re.compile(r'(?i)(?:api[_\-]?key|apikey|access[_\-]?token|secret[_\-]?key)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']'),
    "Private key (generic)": re.compile(r'(?i)private[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9+/=]{32,})["\']'),

    # Android specific
    "Firebase URL":          re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com'),
    "Firebase Storage":      re.compile(r'https://firebasestorage\.googleapis\.com/[^\s"\']+'),
    "S3 Bucket URL":         re.compile(r'https?://[a-z0-9.\-]+\.s3[.\-][a-z0-9\-]*\.?amazonaws\.com[^\s"\']*'),
    "S3 Bucket (bare)":      re.compile(r'\bs3://[a-z0-9.\-]+'),
    "GCS Bucket":            re.compile(r'https?://storage\.googleapis\.com/[^\s"\']+'),
    "Mapbox Token":          re.compile(r'pk\.[A-Za-z0-9_\-]{60,}\.[A-Za-z0-9_\-]{20,}'),
    "Facebook App ID":       re.compile(r'(?i)facebook_app_id["\']?\s*[=:]\s*["\']?(\d{10,17})'),
    "Deep Link":             re.compile(r'\b[a-z][a-z0-9+.\-]{2,}://[^\s"\'<>\)\]\}},;]+', re.IGNORECASE),
}

# ---- Fingerprint lookups --------------------------------------------------

SDK_LOOKUP = {
    marker.lower(): sdk
    for sdk, markers in SDK_MARKERS.items()
    for marker in markers
}
SDK_RE = re.compile(
    "|".join(re.escape(marker) for marker in sorted(SDK_LOOKUP, key=len, reverse=True)),
    re.IGNORECASE,
)

CRYPTO_LOOKUP = {
    marker: name for name, markers in CRYPTO_MARKERS.items() for marker in markers
}
CRYPTO_RE = re.compile(
    "|".join(re.escape(marker) for marker in sorted(CRYPTO_LOOKUP, key=len, reverse=True)),
    re.IGNORECASE,
)

SIGNAL_LOOKUP = {
    marker: name for name, markers in SIGNAL_MARKERS.items() for marker in markers
}
SIGNAL_RE = re.compile(
    "|".join(re.escape(marker) for marker in sorted(SIGNAL_LOOKUP, key=len, reverse=True)),
    re.IGNORECASE,
)

ENTROPY_RE = re.compile(r'[A-Za-z0-9+/=_-]{24,}')
