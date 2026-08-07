import logging
import os
import re
import time
import threading
import json
from datetime import datetime
from collections import defaultdict

from agent.core.collector import BaseCollector
from agent.platforms import is_windows, is_linux, is_macos

logger = logging.getLogger("AEGIS.collector.ransomware")

try:
    import psutil as _psutil_mod
    _has_psutil = True
except ImportError:
    _psutil_mod = None
    _has_psutil = False

_RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".lock", ".crypt", ".aaa", ".micro", ".ttt", ".xyz",
    ".zzz", ".xxx", ".enc", ".crypted", ".cry", ".locky", ".locked",
    ".aes", ".rc4", ".vault", ".pays", ".sage", ".exx", ".ezz",
    ".ecc", ".exotic", ".arena", ".preta", ".crpt", ".crypte",
    ".cryptolocker", ".cryptotor", ".crypt0", ".crypttt", ".crypz",
    ".cryp1", ".cerber", ".cerber2", ".cerber3", ".osiris", ".zepto",
    ".lock93", ".lokf", ".lukitus", ".thor", ".odin", ".aesir",
    ".shit", ".paym", ".payms", ".paymst", ".paymts", ".paybtcs",
    ".btc", ".fun", ".good", ".LOL!", ".OMG!", ".RYK", ".RYK2",
    ".spora", ".wallet", ".wallets", ".onion", ".encrypt", ".ENCRYPTED",
    ".dharma", ".walletx", ".zzzzz", ".pzdc", ".id_[", ".id-",
    ".id.", ".arrow", ".bart", ".zorro", ".combo", ".brrr",
    ".adobe", ".adobee", ".aol", ".nano", ".puma", ".phobos",
    ".eking", ".mado", ".prolock", ".pandora", ".lalo", ".galaxy55",
    ".rugi", ".reco", ".stop", ".peta", ".cosacos", ".neer",
    ".mich", ".meka", ".medusaLocker", ".MedusaLocker", ".medusa",
    ".conti", ".mount", ".lol", ".nols", ".paymen", ".helps",
    ".deuce", ".carote", ".netfilm", ".skymap", ".mbed", ".kr3",
    ".m3g4c0rt3x", ".ransom", ".rans0m", ".RmD", ".payfornature",
    ".p5tkjw", ".bip", ".kraken", ".C1Xx", ".non",
}

_RANSOM_NOTE_NAMES = [
    "README_TO_DECRYPT", "HOW_TO_DECRYPT", "DECRYPT_INSTRUCTIONS",
    "YOUR_FILES_ARE_ENCRYPTED", "RECOVERY_INSTRUCTIONS", "DECRYPT_FILES",
    "HELP_DECRYPT", "HELP_YOUR_FILES", "READ_THIS", "IMPORTANT_READ_ME",
    "RESTORE_FILES", "RECOVER_FILES", "DECRYPT_README", "FILES_ENCRYPTED",
    "HOW_TO_RESTORE", "HOWTO_RESTORE", "HOWTO_DECRYPT", "HOW_TO_RECOVER",
    "RECOVERY_INFO", "RECOVERY_KEY", "UNLOCK_FILES", "UNLOCK_INSTRUCTIONS",
    "READ_ME", "READ_IT", "READ_NOW", "OPEN_ME", "OPEN_THIS",
    "ATTENTION", "WARNING", "ALERT", "NOTICE",
    "_Locky_recover_instructions", "_HELP_instructions",
    "DECRYPT_INFO", "!#_READ_ME_#!", "about_files",
    "restore_files", "recovery+", "help_restore",
]


class RansomwareMonitor(BaseCollector):
    def __init__(self, config=None):
        super().__init__(config)
        self._ransomware_config = (config or {}).get("ransomware", {})
        self._watch_paths = self._ransomware_config.get("watch_paths", [])
        self._monitor_active = False
        self._monitor_thread = None
        self._alerts: list = []
        self._max_alerts = self._ransomware_config.get("max_alerts", 500)

        self._file_change_tracker: dict = defaultdict(list)
        self._file_change_window = self._ransomware_config.get("change_window_seconds", 10)
        self._file_change_threshold = self._ransomware_config.get("change_threshold", 50)

        self._process_io_snapshot: dict = {}
        self._high_io_threshold = self._ransomware_config.get("high_io_threshold_mb_per_sec", 50)
        self._high_cpu_threshold = self._ransomware_config.get("high_cpu_threshold_percent", 60)
        self._high_handles_threshold = self._ransomware_config.get("high_handles_threshold", 500)

        self._known_safe_extensions = {
            ".tmp", ".log", ".cache", ".dat", ".db", ".sqlite", ".sqlite3",
            ".journal", ".wal", ".shm", ".idx", ".lock", ".part", ".crdownload",
            ".download", ".opdownload", ".bak", ".old", ".swp", ".swo",
        }

        if not self._watch_paths:
            if is_windows():
                import ctypes
                try:
                    buf = ctypes.create_unicode_buffer(512)
                    ctypes.windll.shell32.SHGetFolderPathW(None, 5, None, 0, buf)
                    docs = buf.value
                    if docs:
                        self._watch_paths.append(os.path.normpath(docs))
                except Exception:
                    docs = os.path.expandvars("%USERPROFILE%\\Documents")
                    if os.path.isdir(docs):
                        self._watch_paths.append(docs)
                desktop = os.path.expandvars("%USERPROFILE%\\Desktop")
                if os.path.isdir(desktop):
                    self._watch_paths.append(desktop)
            else:
                home = os.path.expanduser("~")
                for sub in ["Documents", "Desktop", "Downloads", "Pictures"]:
                    p = os.path.join(home, sub)
                    if os.path.isdir(p):
                        self._watch_paths.append(p)

        logger.info(f"Ransomware monitor watching paths: {self._watch_paths}")

    async def collect(self) -> dict:
        result = {
            "alerts": list(self._alerts[-50:]),
            "total_alerts": len(self._alerts),
            "shadow_copy_status": self._check_shadow_copy(),
            "ransomware_indicators": self._scan_for_indicators(),
            "active_monitoring": self._monitor_active,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        return result

    def start_monitoring(self):
        if self._monitor_active:
            return
        self._monitor_active = True
        self._monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True, name="ransomware-monitor")
        self._monitor_thread.start()
        logger.info("Ransomware monitoring started")

    def stop_monitoring(self):
        self._monitor_active = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        logger.info("Ransomware monitoring stopped")

    def _monitoring_loop(self):
        scan_interval = self._ransomware_config.get("scan_interval_seconds", 5)
        while self._monitor_active:
            try:
                self._scan_filesystem_changes()
                self._scan_for_ransom_notes()
                self._scan_process_behavior()
            except Exception as e:
                logger.debug(f"Ransomware monitor loop error: {e}")
            time.sleep(scan_interval)

    def _scan_filesystem_changes(self):
        now = time.time()
        cutoff = now - self._file_change_window

        stale_keys = [ts for ts in self._file_change_tracker if ts < cutoff]
        for ts in stale_keys:
            del self._file_change_tracker[ts]

        changes_count = sum(len(v) for v in self._file_change_tracker.values())
        if changes_count >= self._file_change_threshold:
            alert = {
                "type": "rapid_file_changes",
                "severity": "high",
                "message": f"Detected {changes_count} file modifications within {self._file_change_window}s",
                "threshold": self._file_change_threshold,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
            self._add_alert(alert)

    def _scan_for_ransom_notes(self):
        note_names_lower = [n.lower() for n in _RANSOM_NOTE_NAMES]
        for watch_path in self._watch_paths:
            if not os.path.isdir(watch_path):
                continue
            try:
                for entry in os.listdir(watch_path):
                    entry_lower = entry.lower()
                    for note_name in note_names_lower:
                        if note_name in entry_lower:
                            full_path = os.path.join(watch_path, entry)
                            if os.path.isfile(full_path):
                                size = os.path.getsize(full_path)
                                if size < 100_000:
                                    alert = {
                                        "type": "ransom_note_detected",
                                        "severity": "critical",
                                        "message": f"Potential ransom note found: {full_path}",
                                        "file": full_path,
                                        "size_bytes": size,
                                        "timestamp": datetime.utcnow().isoformat() + "Z",
                                    }
                                    self._add_alert(alert)
            except (PermissionError, OSError):
                pass

    def _scan_for_indicators(self) -> dict:
        indicators = {
            "ransomware_extensions_found": [],
            "ransom_notes_found": [],
            "shadow_copy_deleted": False,
        }

        for watch_path in self._watch_paths:
            if not os.path.isdir(watch_path):
                continue
            try:
                for entry in os.listdir(watch_path):
                    entry_lower = entry.lower()
                    for ext in sorted(_RANSOMWARE_EXTENSIONS, key=len, reverse=True):
                        if entry_lower.endswith(ext.lower()):
                            file_path = os.path.join(watch_path, entry)
                            if os.path.isfile(file_path):
                                indicators["ransomware_extensions_found"].append({
                                    "file": file_path,
                                    "extension": ext,
                                    "size": os.path.getsize(file_path),
                                })
                                break

                    for note_name in [n.lower() for n in _RANSOM_NOTE_NAMES]:
                        if note_name in entry_lower:
                            file_path = os.path.join(watch_path, entry)
                            if os.path.isfile(file_path):
                                indicators["ransom_notes_found"].append(file_path)
                            break
            except (PermissionError, OSError):
                pass

        indicators["shadow_copy_deleted"] = self._check_shadow_copy()
        return indicators

    def _scan_process_behavior(self):
        if not _has_psutil:
            return

        try:
            current_snapshot = {}
            for proc in _psutil_mod.process_iter(["pid", "name", "cpu_percent", "num_handles"]):
                try:
                    p = proc.info
                    pid = p["pid"]
                    io_counters = None
                    try:
                        io = _psutil_mod.Process(pid).io_counters()
                        io_counters = {
                            "read_bytes": io.read_bytes,
                            "write_bytes": io.write_bytes,
                        }
                    except (Exception):
                        pass

                    current_snapshot[pid] = {
                        "name": p["name"],
                        "cpu_percent": p["cpu_percent"] or 0,
                        "num_handles": p.get("num_handles") or 0,
                        "io_counters": io_counters,
                        "timestamp": time.time(),
                    }
                except (_psutil_mod.NoSuchProcess, _psutil_mod.AccessDenied):
                    pass

            for pid, current in current_snapshot.items():
                if pid in self._process_io_snapshot:
                    prev = self._process_io_snapshot[pid]
                    if prev.get("io_counters") and current.get("io_counters"):
                        time_diff = current["timestamp"] - prev.get("timestamp", current["timestamp"])
                        if time_diff > 0:
                            write_diff = current["io_counters"]["write_bytes"] - prev["io_counters"]["write_bytes"]
                            write_rate_mb = (write_diff / time_diff) / (1024 * 1024)

                            cpu_high = current["cpu_percent"] >= self._high_cpu_threshold
                            io_high = write_rate_mb >= self._high_io_threshold
                            handles_high = current["num_handles"] >= self._high_handles_threshold

                            if (cpu_high and io_high) or (io_high and handles_high):
                                alert = {
                                    "type": "suspicious_process_behavior",
                                    "severity": "high",
                                    "message": f"Process {current['name']} (PID={pid}) shows ransomware-like behavior",
                                    "pid": pid,
                                    "process_name": current["name"],
                                    "cpu_percent": current["cpu_percent"],
                                    "io_write_rate_mb_per_sec": round(write_rate_mb, 2),
                                    "num_handles": current["num_handles"],
                                    "timestamp": datetime.utcnow().isoformat() + "Z",
                                }
                                self._add_alert(alert)

            self._process_io_snapshot = current_snapshot
        except Exception as e:
            logger.debug(f"Process behavior scan error: {e}")

    def _check_shadow_copy(self) -> bool:
        if is_windows():
            result = self._run_command(["vssadmin", "list", "shadows"], timeout=10)
            if result["returncode"] == 0 and "No items found" in result.get("stdout", ""):
                return True
            deleted_check = self._run_command(
                ["powershell", "-Command",
                 "Get-WinEvent -LogName 'System' -MaxEvents 50 -FilterXPath "
                 "'*[System[EventID=22 or EventID=524]]' -ErrorAction SilentlyContinue | "
                 "Measure-Object | Select-Object -ExpandProperty Count"],
                timeout=10,
            )
            if deleted_check["returncode"] == 0 and deleted_check["stdout"].strip():
                try:
                    if int(deleted_check["stdout"].strip()) > 0:
                        return True
                except ValueError:
                    pass
        return False

    def record_file_change(self, file_path: str, change_type: str = "modified"):
        if not hasattr(self, "_file_change_tracker"):
            return
        now = time.time()
        self._file_change_tracker[now].append({
            "path": file_path,
            "type": change_type,
        })

    def record_file_extension_alert(self, file_path: str, extension: str):
        ext_lower = extension.lower()
        if ext_lower in self._known_safe_extensions:
            return
        if ext_lower in _RANSOMWARE_EXTENSIONS:
            alert = {
                "type": "ransomware_extension_detected",
                "severity": "critical",
                "message": f"Ransomware extension file created: {file_path}",
                "file": file_path,
                "extension": extension,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
            self._add_alert(alert)

    def _add_alert(self, alert: dict):
        alert_key = f"{alert.get('type')}_{alert.get('file', '')}_{alert.get('pid', '')}"
        if not any(a.get("_key") == alert_key for a in self._alerts[-100:]):
            alert["_key"] = alert_key
            self._alerts.append(alert)
            if len(self._alerts) > self._max_alerts:
                self._alerts = self._alerts[-self._max_alerts:]
            logger.warning(f"RANSOMWARE ALERT: {alert.get('type')} - {alert.get('message', '')[:200]}")
        else:
            for existing in reversed(self._alerts):
                if existing.get("_key") == alert_key:
                    existing["last_seen"] = datetime.utcnow().isoformat() + "Z"
                    if "count" not in existing:
                        existing["count"] = 1
                    else:
                        existing["count"] += 1
                    break

    def get_alerts(self, severity: str = None, limit: int = 50) -> list:
        alerts = self._alerts
        if severity:
            alerts = [a for a in alerts if a.get("severity") == severity]
        return alerts[-limit:]

    def clear_alerts(self):
        self._alerts.clear()
