import logging
import os
import time
import threading
from datetime import datetime

from agent.core.collector import BaseCollector
from agent.platforms import is_windows, is_linux, is_macos

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

    _has_watchdog = True
except ImportError:
    _has_watchdog = False


logger = logging.getLogger("AEGIS.collector.logs")


class LogFileHandler(FileSystemEventHandler):
    def __init__(self, callback, source_name):
        self._callback = callback
        self._source_name = source_name
        self._position = 0
        self._file = None

    def on_modified(self, event):
        if event.is_directory:
            return
        self._read_new_lines(event.src_path)

    def on_created(self, event):
        self._read_new_lines(event.src_path)

    def set_file(self, path):
        self._file = path
        try:
            if os.path.isfile(path):
                self._position = os.path.getsize(path)
        except Exception:
            self._position = 0

    def _read_new_lines(self, path):
        if path != self._file:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._position)
                new_lines = f.readlines()
                self._position = f.tell()
                if new_lines:
                    for line in new_lines:
                        self._callback({
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "source": self._source_name,
                            "file": path,
                            "message": line.strip(),
                        })
        except Exception as e:
            logger.debug(f"Log read error ({path}): {e}")


class LogCollector(BaseCollector):
    def __init__(self, config=None):
        super().__init__(config)
        self._log_config = (config or {}).get("logs", {})
        self._sources = self._log_config.get("sources", {})
        self._severity_filter = self._log_config.get("severity_filter",
                                                      ["ERROR", "WARNING", "CRITICAL"])
        self._real_time = self._log_config.get("real_time", True)
        self._max_lines = self._log_config.get("max_lines", 1000)

        self._recent_entries: list = []
        self._observer: "Observer" = None
        self._handler = None
        self._rt_thread = None
        self._rt_active = False

    async def collect(self) -> dict:
        result = {
            "entries": self._collect_logs(),
            "recent_count": len(self._recent_entries),
        }
        return result

    def _collect_logs(self) -> list:
        entries = []

        if is_windows():
            entries = self._collect_windows_event_log()
        elif is_linux():
            entries = self._collect_linux_logs()
        elif is_macos():
            entries = self._collect_macos_logs()

        return entries[-self._max_lines:] if len(entries) > self._max_lines else entries

    def _collect_windows_event_log(self) -> list:
        entries = []
        sources = self._sources.get("windows", ["System", "Security", "Application"])

        for log_name in sources:
            try:
                filter_xml = f'*[System[({self._build_severity_filter()})]]'
                ps_cmd = (
                    f'Get-WinEvent -LogName "{log_name}" -MaxEvents {self._max_lines} '
                    f'-FilterXPath "{filter_xml}" -ErrorAction SilentlyContinue | '
                    f'Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | '
                    f'ConvertTo-Json -Compress -Depth 3'
                )
                result = self._run_command(["powershell", "-Command", ps_cmd], timeout=30)
                if result["returncode"] == 0 and result["stdout"]:
                    import json
                    try:
                        data = json.loads(result["stdout"])
                        if isinstance(data, dict):
                            data = [data]
                        for event in data:
                            entries.append({
                                "timestamp": str(event.get("TimeCreated", "")),
                                "source": log_name,
                                "event_id": event.get("Id", 0),
                                "level": event.get("LevelDisplayName", ""),
                                "provider": event.get("ProviderName", ""),
                                "message": str(event.get("Message", ""))[:5000],
                                "platform": "windows",
                            })
                    except json.JSONDecodeError:
                        logger.debug(f"Failed to parse Windows event log JSON for {log_name}")
            except Exception as e:
                logger.warning(f"Windows event log collection error ({log_name}): {e}")

        return entries

    def _collect_linux_logs(self) -> list:
        entries = []
        sources = self._sources.get("linux", ["/var/log/syslog", "/var/log/auth.log"])

        for log_file in sources:
            if not log_file or not os.path.isfile(log_file):
                continue
            try:
                with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                    lines = []
                    for line in f:
                        stripped = line.rstrip()
                        if stripped:
                            if any(sev.lower() in stripped.lower() for sev in self._severity_filter):
                                lines.append(stripped)
                    tail_lines = lines[-self._max_lines:]
                    for line in tail_lines:
                        entries.append({
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "source": log_file,
                            "message": line,
                            "platform": "linux",
                        })
            except PermissionError:
                entries.append({
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "source": log_file,
                    "message": "[Access denied - try running as root]",
                    "platform": "linux",
                    "level": "WARNING",
                })
            except Exception as e:
                logger.debug(f"Linux log read error ({log_file}): {e}")

        if not entries:
            result = self._run_command(["journalctl", "-n", str(self._max_lines), "-p", "err..emerg", "--no-pager"], timeout=15)
            if result["returncode"] == 0:
                for line in result["stdout"].split("\n"):
                    if line.strip():
                        entries.append({
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "source": "journalctl",
                            "message": line.strip(),
                            "platform": "linux",
                        })

        return entries

    def _collect_macos_logs(self) -> list:
        entries = []
        sources = self._sources.get("macos", ["/var/log/system.log"])

        for log_file in sources:
            if not log_file or not os.path.isfile(log_file):
                continue
            try:
                with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                    lines = []
                    for line in f:
                        stripped = line.rstrip()
                        if stripped:
                            if any(sev.lower() in stripped.lower() for sev in self._severity_filter):
                                lines.append(stripped)
                    tail_lines = lines[-self._max_lines:]
                    for line in tail_lines:
                        entries.append({
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "source": log_file,
                            "message": line,
                            "platform": "macos",
                        })
            except Exception as e:
                logger.debug(f"macOS log read error ({log_file}): {e}")

        if not entries:
            result = self._run_command(["log", "show", "--last", "1h", "--predicate",
                                        'eventMessage CONTAINS "error" OR eventMessage CONTAINS "fail"'],
                                       timeout=20)
            if result["returncode"] == 0:
                for line in result["stdout"].split("\n"):
                    if line.strip():
                        entries.append({
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "source": "unified_log",
                            "message": line.strip(),
                            "platform": "macos",
                        })

        return entries

    def _build_severity_filter(self) -> str:
        level_map = {
            "CRITICAL": "1",
            "ERROR": "2",
            "WARNING": "3",
        }
        levels = [level_map.get(sev.upper(), "2") for sev in self._severity_filter]
        return " or ".join([f"Level={lvl}" for lvl in set(levels)])

    def start_real_time(self):
        if not self._real_time:
            return
        if self._rt_active:
            return

        self._rt_active = True
        self._rt_thread = threading.Thread(target=self._rt_loop, daemon=True)
        self._rt_thread.start()
        logger.info("Real-time log tailing started")

    def stop_real_time(self):
        self._rt_active = False
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3)
            self._observer = None
        logger.info("Real-time log tailing stopped")

    def _rt_loop(self):
        if not _has_watchdog:
            logger.warning("watchdog not installed; real-time log tailing unavailable")
            return

        sources = []

        if is_linux():
            sources = [s for s in self._sources.get("linux", []) if s and os.path.isfile(s)]
        elif is_macos():
            sources = [s for s in self._sources.get("macos", []) if s and os.path.isfile(s)]

        if not sources:
            logger.info("No file-based log sources for real-time tailing")
            return

        self._observer = Observer()
        dirs = set(os.path.dirname(s) for s in sources if os.path.isfile(s))

        for d in dirs:
            self._handler = LogFileHandler(self._on_rt_entry, d)
            self._observer.schedule(self._handler, d, recursive=False)
            for s in sources:
                if os.path.dirname(s) == d:
                    self._handler.set_file(s)

        self._observer.start()
        logger.info(f"Watching {len(sources)} log files in real-time")

        while self._rt_active:
            time.sleep(1)

        if self._observer:
            self._observer.stop()
            self._observer.join()

    def _on_rt_entry(self, entry):
        self._recent_entries.append(entry)
        if len(self._recent_entries) > self._max_lines:
            self._recent_entries = self._recent_entries[-self._max_lines:]

    def get_recent_entries(self) -> list:
        return list(self._recent_entries)
