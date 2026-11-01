"""Optional androguard import, isolated so the app runs without it."""

try:
    from androguard.core.apk import APK as AG_APK  # androguard >= 4
    HAS_ANDROGUARD = True
except Exception:
    try:
        from androguard.core.bytecodes.apk import APK as AG_APK  # androguard 3.x
        HAS_ANDROGUARD = True
    except Exception:
        AG_APK = None
        HAS_ANDROGUARD = False

__all__ = ["AG_APK", "HAS_ANDROGUARD"]
