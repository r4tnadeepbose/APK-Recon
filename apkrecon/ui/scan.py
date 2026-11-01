"""Scan orchestration: metadata, inventory, decompilation and extraction."""

import datetime
import hashlib
import os
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..androguard_support import AG_APK, HAS_ANDROGUARD
from ..config import (
    APKTOOL_CANDIDATES, DECOMPILE_DIR, ENGINE_MARKER, JADX_CANDIDATES, PALETTE,
    SCAN_EXTS,
)
from ..scanner import (
    ScanResult, collect_apk_inventory, find_jadx, find_tool, scan_text,
)


class ScanMixin:
    def start_analysis(self):
        if not self.current_apk_path or self.running:
            return
        if self.ask_scan_var.get() and not self.ask_scan_setup():
            self._status("Scan setup cancelled.")
            return
        self.cancel_event.clear()
        self.result = ScanResult()
        self.diff_summary = None
        self.running = True
        self._reset_phases()
        self._save_settings()
        self._set_state("RUNNING", PALETTE["amber"])
        self._sync_buttons()
        self._raw = {key: [] for key, _ in self.TABS}
        self._counts = {}
        self._apply_filter()
        self._start_spinner()
        self._switch_tab("dashboard")
        self._log(f"analyze {os.path.basename(self.current_apk_path)}", "accent")
        threading.Thread(target=self._worker, daemon=True).start()

    def cancel_analysis(self):
        self.cancel_event.set()
        self._status("Cancelling…")
        self._log("cancel requested", "review")

    # ---------------- Worker ----------------
    def _worker(self):
        ok = False
        try:
            self._set_phase("inventory", "active")
            self._log("reading archive inventory", "muted")
            self._collect_inventory()
            self._set_phase("inventory", "done")

            self._set_phase("manifest", "active")
            self._log("reading manifest / signing data", "muted")
            self._collect_apk_metadata()
            self._set_phase("manifest", "done")

            engine = self.engine_var.get()
            if engine == "auto":
                if HAS_ANDROGUARD:
                    engine = "dex-only"
                elif find_jadx()[0]:
                    engine = "jadx"
                else:
                    engine = "apktool"
            self.last_engine = engine
            self._log(
                f"engine={engine} workers={self.workers_var.get()} "
                f"deep={'on' if self.deep_var.get() else 'off'}",
                "muted",
            )

            self._set_phase("extract", "active")
            if engine == "dex-only":
                ok = self._scan_dex_only()
            else:
                ok = self._decompile(engine) and self._scan_files()
            if ok:
                self._set_phase("extract", "done")

            self._set_phase("score", "active" if ok else "skip")
            if ok and not self.cancel_event.is_set():
                self._status(f"DONE. {len(self.result.urls)} URLs, "
                             f"{len(self.result.domains)} domains, "
                             f"{len(self.result.ips)} IPs, "
                             f"{len(self.result.emails)} emails, "
                             f"{len(self.result.exts)} exts, "
                             f"{len(self.result.secrets)} secrets")
                elapsed = (
                    (datetime.datetime.now() - self.scan_started).total_seconds()
                    if self.scan_started else 0
                )
                self.last_duration = elapsed
                self._log(
                    f"complete in {elapsed:.1f}s · urls={len(self.result.urls)} "
                    f"secrets={len(self.result.secrets)} sdks={len(self.result.sdks)} "
                    f"entropy={len(self.result.entropy)}",
                    "accent",
                )
            elif self.cancel_event.is_set():
                self._log("scan cancelled", "review")
            else:
                self._log("scan failed", "crit")
        except Exception as e:
            self._error("Error", str(e))
        finally:
            cancelled = self.cancel_event.is_set()
            self.running = False
            self._set_phase("score", "done" if ok and not cancelled else "skip")
            self.root.after(0, self._sync_buttons)

            def finish():
                self._render()
                if ok and not cancelled:
                    self._maybe_auto_report()
                    self._record_history()

            self.root.after(0, finish)
            if ok and not cancelled:
                self.root.after(0, lambda: self._set_state("COMPLETE", PALETTE["accent"]))
            elif cancelled:
                self.root.after(0, lambda: self._set_state("READY", PALETTE["accent"]))
            else:
                self.root.after(0, lambda: self._set_state("READY", PALETTE["accent"]))

    def _collect_apk_metadata(self):
        if not HAS_ANDROGUARD:
            self._status("Androguard unavailable; continuing without APK metadata.")
            return

        try:
            apk = AG_APK(self.current_apk_path)
            package_name = self._ag_value(apk, "get_package")
            app_name = self._ag_value(apk, "get_app_name")
            version_name = self._ag_value(apk, "get_androidversion_name")
            version_code = self._ag_value(apk, "get_androidversion_code")
            min_sdk = self._ag_value(apk, "get_min_sdk_version")
            target_sdk = self._ag_value(apk, "get_target_sdk_version")

            self.result.metadata = {
                "File size": f"{os.path.getsize(self.current_apk_path):,} bytes",
                "SHA-256": self._sha256_file(self.current_apk_path),
                "Package": package_name or "Unknown",
                "App name": app_name or "Unknown",
                "Version": version_name or "Unknown",
                "Version code": version_code or "Unknown",
                "Min SDK": min_sdk or "Unknown",
                "Target SDK": target_sdk or "Unknown",
            }
            self.result.permissions = {
                str(permission) for permission in (apk.get_permissions() or [])
            }
            component_types = (
                ("Activities", apk.get_activities),
                ("Services", apk.get_services),
                ("Receivers", apk.get_receivers),
                ("Providers", apk.get_providers),
            )
            self.result.components = [
                f"{kind}: {name}"
                for kind, getter in component_types
                for name in (getter() or [])
            ]

            security = self._collect_manifest_security(apk)
            security["signature"] = self._collect_signature(apk)
            self.result.security = security
            self._log(
                f"manifest: debug={security.get('debuggable')} "
                f"backup={security.get('allow_backup')} "
                f"exported={len(security.get('exported') or [])}",
                "muted",
            )
        except Exception as e:
            self._status(f"APK metadata unavailable: {e}")
            self._log(f"metadata error: {e}", "review")

    def _collect_inventory(self):
        if not self.current_apk_path:
            return
        try:
            self.result.inventory = collect_apk_inventory(self.current_apk_path)
            inv = self.result.inventory
            self._log(
                f"inventory: {inv['entries']} entries / {inv['dex_count']} dex / "
                f"{inv['so_count']} native libs / {inv['assets']} assets",
                "muted",
            )
        except Exception as e:
            self._status(f"Inventory unavailable: {e}")
            self._log(f"inventory error: {e}", "review")

    @staticmethod
    def _local_name(tag):
        return str(tag).rsplit("}", 1)[-1]

    @classmethod
    def _attr(cls, element, name):
        for key, value in element.attrib.items():
            if cls._local_name(key) == name:
                return value
        return None

    def _collect_manifest_security(self, apk):
        security = {}
        try:
            manifest = apk.get_android_manifest_xml()
        except Exception:
            return security
        if manifest is None:
            return security

        application = next(
            (child for child in manifest if self._local_name(child.tag) == "application"),
            None,
        )
        if application is None:
            return security

        for attribute, key in (
            ("debuggable", "debuggable"),
            ("allowBackup", "allow_backup"),
            ("usesCleartextTraffic", "cleartext"),
            ("testOnly", "test_only"),
        ):
            raw = self._attr(application, attribute)
            if raw is not None:
                security[key] = str(raw).strip().lower() == "true"
        if "allow_backup" not in security:
            security["allow_backup"] = True

        network_config = self._attr(application, "networkSecurityConfig")
        if network_config:
            security["network_config"] = network_config

        components = []
        for child in application:
            kind = self._local_name(child.tag)
            if kind not in ("activity", "activity-alias", "service", "receiver", "provider"):
                continue
            name = self._attr(child, "name") or "?"
            exported_raw = self._attr(child, "exported")
            has_filter = any(
                self._local_name(grandchild.tag) == "intent-filter"
                for grandchild in child
            )
            if exported_raw is not None:
                exported = str(exported_raw).strip().lower() == "true"
            else:
                exported = has_filter and kind in ("activity", "activity-alias", "receiver", "service")
            components.append({
                "kind": "activity" if kind == "activity-alias" else kind,
                "name": name,
                "exported": exported,
                "permission": self._attr(child, "permission"),
                "intent_filter": has_filter,
            })
        security["components"] = components
        security["exported"] = [c for c in components if c["exported"]]
        return security

    def _collect_signature(self, apk):
        signature = {"available": True}
        signature["v1_meta"] = bool(self.result.inventory.get("signature_files"))
        try:
            certificates = []
            for certificate in apk.get_certificates() or []:
                info = {}
                try:
                    info["sha256"] = str(certificate.sha256_fingerprint).replace(":", "").lower()
                except Exception:
                    try:
                        info["sha256"] = hashlib.sha256(certificate.dump()).hexdigest()
                    except Exception:
                        info["sha256"] = ""
                try:
                    info["subject"] = certificate.subject.human_friendly
                except Exception:
                    info["subject"] = ""
                try:
                    info["issuer"] = certificate.issuer.human_friendly
                except Exception:
                    info["issuer"] = ""
                try:
                    not_after = certificate.not_valid_after
                    info["not_after"] = not_after.strftime("%Y-%m-%d")
                    info["expired"] = not_after < datetime.datetime.now()
                except Exception:
                    pass
                certificates.append(info)
            signature["certs"] = certificates
            signature["debug"] = any(
                "Android Debug" in (info.get("subject", "") + " " + info.get("issuer", ""))
                for info in certificates
            )
        except Exception:
            signature["certs"] = []
        for method_name, key in (("is_signed_v2", "v2"), ("is_signed_v3", "v3")):
            try:
                signature[key] = bool(getattr(apk, method_name)())
            except Exception:
                signature[key] = False
        return signature

    @staticmethod
    def _ag_value(apk, method_name):
        method = getattr(apk, method_name, None)
        if not callable(method):
            return ""
        try:
            return str(method() or "")
        except Exception:
            return ""

    @staticmethod
    def _sha256_file(path):
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    # ---- DEX-only engine (fastest, parallel) ----
    def _scan_dex_only(self):
        if not HAS_ANDROGUARD:
            self._error("androguard missing", "pip install androguard")
            return False

        self._status("Reading DEX with androguard (fast engine)...")
        self._indeterminate(True)

        a = AG_APK(self.current_apk_path)

        try:
            dex_blobs = list(a.get_all_dex())
        except AttributeError:
            try:
                dex_blobs = list(a.get_dex())
            except Exception:
                dex_blobs = []

        if not dex_blobs:
            self._indeterminate(False)
            self._status("No DEX blobs found.")
            return False

        total = len(dex_blobs)
        self._status(f"Decoding {total} DEX file(s)...")

        blobs = []
        for i, dex in enumerate(dex_blobs):
            try:
                if isinstance(dex, (bytes, bytearray)):
                    blob = bytes(dex)
                elif isinstance(dex, str) and os.path.exists(dex):
                    with open(dex, "rb") as f:
                        blob = f.read()
                else:
                    blob = bytes(dex)
                blobs.append((i, blob))
            except Exception:
                continue

        self._indeterminate(False)
        self._set_phase("extract", "done")
        self._set_phase("scan", "active")
        self._status(f"Scanning {total} DEX file(s) in parallel…")
        self.root.after(0, lambda: self.progress.config(mode="determinate",
                                                        maximum=total, value=0))
        self._progress_update(0, total)

        done = 0

        def scan_one(item):
            idx, blob = item
            text = blob.decode("latin-1", errors="ignore")
            return scan_text(text, f"<DEX#{idx}>", deep=self.deep_var.get())

        with ThreadPoolExecutor(max_workers=max(1, self.workers_var.get())) as ex:
            futures = {ex.submit(scan_one, b): b for b in blobs}
            for fut in as_completed(futures):
                if self.cancel_event.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    self._status("Scan cancelled.")
                    return False
                try:
                    self.result.merge(fut.result())
                except Exception:
                    pass
                done += 1
                self._progress_update(done, total)
                self._status(f"SCAN · DEX {done}/{total} · {self.eta_text}")

        self._set_phase("scan", "done")
        return True

    # ---- apktool / jadx decompile ----
    def _decompile(self, engine):
        if engine not in ("jadx", "apktool"):
            self._error("Unknown engine", f"Unsupported decompiler: {engine}")
            return False

        marker_path = os.path.join(self.decompile_dir, ENGINE_MARKER)
        if self.reuse_var.get() and os.path.isdir(self.decompile_dir):
            try:
                with open(marker_path, "r", encoding="utf-8") as marker:
                    cached_engine = marker.read().strip()
            except OSError:
                cached_engine = ""

            entries = set(os.listdir(self.decompile_dir))
            expected_entries = (
                {"sources", "AndroidManifest.xml"}
                if engine == "jadx"
                else {"smali", "res", "AndroidManifest.xml"}
            )
            if cached_engine == engine and entries & expected_entries:
                self._status(f"Reusing existing {engine} output...")
                return True

        if os.path.isdir(self.decompile_dir):
            shutil.rmtree(self.decompile_dir, ignore_errors=True)
        os.makedirs(self.decompile_dir, exist_ok=True)

        if engine == "jadx":
            prefix, label = find_jadx(self.tool_paths.get("jadx_path"))
            if not prefix:
                self._error(
                    "jadx not found",
                    "Install jadx (CLI or jadx-gui-with-JRE) or switch engine.",
                )
                return False
            cmd = prefix + ["-d", self.decompile_dir]
            if self.fast_mode_var.get():
                cmd.append("--no-res")
            cmd.append(self.current_apk_path)
        else:
            candidates = (([self.tool_paths["apktool_path"]]
                           if self.tool_paths.get("apktool_path") else []) + APKTOOL_CANDIDATES)
            prefix, label = find_tool(candidates)
            if not prefix:
                self._error("apktool not found", "Check APKTOOL_CANDIDATES.")
                return False
            cmd = prefix + ["d", self.current_apk_path, "-o", self.decompile_dir, "-f"]
            if self.fast_mode_var.get():
                cmd.append("-r")

        self._status(f"Decompiling with {label}…")
        self._log(" ".join(cmd), "muted")
        self._indeterminate(True)
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", shell=False,
            )
        except OSError as e:
            self._indeterminate(False)
            self._error("Launch failed", str(e))
            return False

        tail = []
        shown = 0
        while True:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
            if line:
                line = line.rstrip()
                if line:
                    tail.append(line)
                    if len(tail) > 300:
                        tail.pop(0)
                    if shown < 250:
                        self._log(f"{label}: {line[:280]}", "muted")
                        shown += 1
            if self.cancel_event.is_set():
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
                self._indeterminate(False)
                self._status("Decompile cancelled.")
                return False
        self._indeterminate(False)

        if proc.returncode != 0:
            err = "\n".join(tail)[-2000:]
            self._error(f"{label} error", err)
            self._log(f"{label} exited {proc.returncode}", "crit")
            return False
        self._log(f"{label} finished", "accent")

        try:
            with open(marker_path, "w", encoding="utf-8") as marker:
                marker.write(engine)
        except OSError as e:
            self._error("Decompile failed", f"Could not record {engine} output: {e}")
            return False
        return True

    # ---- parallel file scan ----
    def _scan_files(self):
        files = []
        for root_dir, _, names in os.walk(self.decompile_dir):
            for n in names:
                if n.lower().endswith(SCAN_EXTS):
                    files.append(os.path.join(root_dir, n))

        total = len(files)
        if total == 0:
            self._status("No files to scan.")
            return True

        self._set_phase("extract", "done")
        self._set_phase("scan", "active")
        self._status(f"Scanning {total} files with {self.workers_var.get()} workers…")
        self.root.after(0, lambda: self.progress.config(maximum=total, value=0))
        self._progress_update(0, total)

        done = 0
        with ThreadPoolExecutor(max_workers=self.workers_var.get()) as ex:
            futures = {ex.submit(self._scan_one, f): f for f in files}
            for fut in as_completed(futures):
                if self.cancel_event.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    self._status("Scan cancelled.")
                    return False
                try:
                    r = fut.result()
                    self.result.merge(r)
                except Exception:
                    pass
                done += 1
                if done % 25 == 0 or done == total:
                    self._progress_update(done, total)
                    self._status(f"SCAN · {done}/{total} files · {self.eta_text}")
        self._set_phase("scan", "done")
        return True

    def _scan_one(self, path):
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except OSError:
            return ScanResult()
        rel = os.path.relpath(path, self.decompile_dir)
        return scan_text(content, rel, deep=self.deep_var.get())

