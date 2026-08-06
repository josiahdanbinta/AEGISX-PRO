import asyncio
import abc
import time
import socket
import platform
import os
import logging
from datetime import datetime


logger = logging.getLogger("aegisx.collector")


class BaseCollector(abc.ABC):
    def __init__(self, config=None):
        self._config = config or {}
        self._enabled = self._config.get("enabled", True)
        self._interval = self._config.get("interval", 30)
        self._last_collection = None
        self._last_error = None

    @property
    def name(self):
        return self.__class__.__name__

    @property
    def interval(self):
        return self._interval

    @interval.setter
    def interval(self, value):
        self._interval = value

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        self._enabled = value

    @abc.abstractmethod
    async def collect(self) -> dict:
        pass

    def get_system_info(self) -> dict:
        return {
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

    def get_uptime(self) -> float:
        try:
            import psutil
            return time.time() - psutil.boot_time()
        except Exception:
            if os.name == "nt":
                try:
                    import ctypes
                    return ctypes.windll.kernel32.GetTickCount64() / 1000.0
                except Exception:
                    pass
            try:
                with open("/proc/uptime") as f:
                    return float(f.read().split()[0])
            except Exception:
                return -1

    def get_boot_time(self) -> str:
        try:
            import psutil
            return datetime.fromtimestamp(psutil.boot_time()).isoformat() + "Z"
        except Exception:
            uptime = self.get_uptime()
            if uptime > 0:
                boot = time.time() - uptime
                return datetime.fromtimestamp(boot).isoformat() + "Z"
            return ""

    def get_load_average(self) -> dict:
        if os.name == "nt":
            return {"1min": None, "5min": None, "15min": None}
        try:
            load1, load5, load15 = os.getloadavg()
            return {"1min": load1, "5min": load5, "15min": load15}
        except (OSError, AttributeError):
            try:
                import psutil
                load1, load5, load15 = psutil.getloadavg()
                return {"1min": load1, "5min": load5, "15min": load15}
            except Exception:
                return {"1min": None, "5min": None, "15min": None}

    async def run(self) -> dict:
        if not self.enabled:
            return {"collector": self.name, "status": "disabled", "timestamp": datetime.utcnow().isoformat() + "Z"}
        try:
            start = time.monotonic()
            data = await self.collect()
            elapsed = time.monotonic() - start
            self._last_collection = datetime.utcnow().isoformat() + "Z"
            result = {
                "collector": self.name,
                "status": "success",
                "timestamp": self._last_collection,
                "duration_ms": round(elapsed * 1000, 2),
                "data": data,
            }
            if self._last_error:
                self._last_error = None
            return result
        except Exception as e:
            self._last_error = str(e)
            logger.error(f"Collector {self.name} failed: {e}", exc_info=True)
            return {
                "collector": self.name,
                "status": "error",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "error": str(e),
            }

    def _run_command(self, cmd: list, timeout: int = 10) -> dict:
        try:
            import subprocess
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return {
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "Command timed out", "returncode": -1}
        except FileNotFoundError:
            return {"stdout": "", "stderr": f"Command not found: {cmd[0]}", "returncode": -2}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "returncode": -3}
