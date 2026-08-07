import logging
import os
import re

from agent.core.collector import BaseCollector
from agent.platforms import is_windows


logger = logging.getLogger("AEGIS.collector.processes")


class ProcessCollector(BaseCollector):
    def __init__(self, config=None):
        super().__init__(config)
        try:
            import psutil
            self._psutil = psutil
            self._has_psutil = True
        except ImportError:
            self._has_psutil = False
            logger.warning("psutil not available; process collection will be limited")

        self._suspicious_config = (config or {}).get("suspicious_detection", {})
        self._check_unsigned = self._suspicious_config.get("unsigned_processes", True)
        self._check_temp = self._suspicious_config.get("temp_location_execution", True)
        self._check_parent = self._suspicious_config.get("unusual_parent_process", True)

        self._temp_patterns = [
            re.compile(r'[\\/]temp[\\/]', re.IGNORECASE),
            re.compile(r'[\\/]tmp[\\/]', re.IGNORECASE),
            re.compile(r'[\\/]AppData[\\/]Local[\\/]Temp[\\/]', re.IGNORECASE),
            re.compile(r'^/?tmp/', re.IGNORECASE),
        ]

    async def collect(self) -> dict:
        result = {
            "processes": self._collect_processes(),
            "listening_ports": self._collect_listening_ports(),
            "suspicious": [],
        }

        if self._check_unsigned or self._check_temp or self._check_parent:
            result["suspicious"] = self._detect_suspicious(result["processes"])

        return result

    def _collect_processes(self) -> list:
        if self._has_psutil:
            return self._collect_psutil()
        return self._collect_fallback()

    def _collect_psutil(self) -> list:
        processes = []
        try:
            for proc in self._psutil.process_iter(["pid", "name", "username", "cpu_percent",
                                                    "memory_percent", "cmdline", "exe",
                                                    "ppid", "create_time", "status"]):
                try:
                    info = proc.info
                    info["parent_pid"] = info.pop("ppid", None)
                    exe_path = info.get("exe")
                    info["exe_path"] = exe_path or ""

                    cmdline = info.get("cmdline")
                    if cmdline:
                        info["command_line"] = " ".join(cmdline)
                    else:
                        info["command_line"] = ""

                    info.pop("cmdline", None)

                    if exe_path and os.path.isfile(exe_path):
                        info["exe_size"] = os.path.getsize(exe_path)
                    else:
                        info["exe_size"] = 0

                    processes.append(info)
                except (self._psutil.NoSuchProcess, self._psutil.AccessDenied):
                    pass
                except Exception as e:
                    logger.debug(f"Process collection error (pid={proc.pid if hasattr(proc, 'pid') else '?'}): {e}")
        except Exception as e:
            logger.error(f"Process iteration error: {e}")

        return processes

    def _collect_fallback(self) -> list:
        processes = []

        if is_windows():
            result = self._run_command(
                ["powershell", "-Command",
                 "Get-Process | Select-Object Id,ProcessName,CPU,PM,StartTime | "
                 "ConvertTo-Json -Compress"],
                timeout=15,
            )
            if result["returncode"] == 0 and result["stdout"]:
                import json
                try:
                    data = json.loads(result["stdout"])
                    if isinstance(data, dict):
                        data = [data]
                    for p in data:
                        processes.append({
                            "pid": p.get("Id"),
                            "name": p.get("ProcessName", ""),
                            "cpu_percent": p.get("CPU", 0),
                            "memory_percent": 0,
                            "memory_bytes": p.get("PM", 0),
                            "username": "",
                            "exe_path": "",
                            "command_line": "",
                            "parent_pid": None,
                        })
                except json.JSONDecodeError:
                    pass
        else:
            result = self._run_command(["ps", "-eo", "pid,ppid,user,%cpu,%mem,rss,comm,args", "--no-headers"], timeout=15)
            if result["returncode"] == 0:
                for line in result["stdout"].split("\n"):
                    parts = line.strip().split(None, 7)
                    if len(parts) >= 5:
                        processes.append({
                            "pid": int(parts[0]) if parts[0].isdigit() else None,
                            "parent_pid": int(parts[1]) if parts[1].isdigit() else None,
                            "username": parts[2],
                            "cpu_percent": float(parts[3]) if parts[3].replace('.', '').isdigit() else 0,
                            "memory_percent": float(parts[4]) if parts[4].replace('.', '').isdigit() else 0,
                            "memory_bytes": int(parts[5]) * 1024 if parts[5].isdigit() else 0,
                            "name": parts[6] if len(parts) > 6 else "",
                            "command_line": parts[7] if len(parts) > 7 else "",
                            "exe_path": "",
                        })

        return processes

    def _collect_listening_ports(self) -> list:
        ports = []

        if self._has_psutil:
            try:
                connections = self._psutil.net_connections(kind="inet")
                for conn in connections:
                    if conn.status == "LISTEN":
                        port_info = {
                            "protocol": "tcp" if conn.family.name == "AF_INET" else "tcp6",
                            "local_ip": conn.laddr.ip if conn.laddr else "",
                            "local_port": conn.laddr.port if conn.laddr else 0,
                            "pid": conn.pid,
                        }
                        if conn.pid:
                            try:
                                proc = self._psutil.Process(conn.pid)
                                port_info["process_name"] = proc.name()
                            except (self._psutil.NoSuchProcess, self._psutil.AccessDenied):
                                port_info["process_name"] = ""
                        ports.append(port_info)
            except Exception as e:
                logger.warning(f"Port scanning error: {e}")
        else:
            if is_windows():
                result = self._run_command(["netstat", "-ano"], timeout=15)
                if result["returncode"] == 0:
                    for line in result["stdout"].split("\n"):
                        if "LISTENING" in line:
                            parts = line.split()
                            if len(parts) >= 5:
                                addr = parts[1]
                                if ":" in addr:
                                    local_ip, port = addr.rsplit(":", 1)
                                    ports.append({
                                        "protocol": parts[0].lower(),
                                        "local_ip": local_ip,
                                        "local_port": int(port) if port.isdigit() else 0,
                                        "pid": int(parts[-1]) if parts[-1].isdigit() else None,
                                    })
            else:
                result = self._run_command(["ss", "-tlnp"], timeout=15)
                if result["returncode"] != 0:
                    result = self._run_command(["netstat", "-tlnp"], timeout=15)
                if result["returncode"] == 0:
                    for line in result["stdout"].split("\n")[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and "LISTEN" in line:
                            addr = parts[3]
                            if ":" in addr:
                                local_ip, port = addr.rsplit(":", 1)
                                pid = None
                                for part in parts:
                                    if "pid=" in part:
                                        try:
                                            pid = int(part.split("=")[1].split("/")[0])
                                        except ValueError:
                                            pass
                                ports.append({
                                    "protocol": "tcp",
                                    "local_ip": local_ip,
                                    "local_port": int(port) if port.isdigit() else 0,
                                    "pid": pid,
                                })

        return ports

    def _detect_suspicious(self, processes: list) -> list:
        suspicious = []

        for proc in processes:
            flags = []
            pid = proc.get("pid")
            name = proc.get("name", "")
            exe_path = proc.get("exe_path", "")
            cmdline = proc.get("command_line", "")
            parent_pid = proc.get("parent_pid")

            if self._check_unsigned and is_windows():
                if exe_path and exe_path.lower().endswith(".exe"):
                    if self._is_unsigned_windows(exe_path):
                        flags.append("unsigned")

            if self._check_temp and exe_path:
                for pattern in self._temp_patterns:
                    if pattern.search(exe_path):
                        flags.append("executing_from_temp")
                        break
                if not flags:
                    for pattern in self._temp_patterns:
                        if pattern.search(cmdline):
                            flags.append("executing_from_temp")
                            break

            if self._check_parent and parent_pid is not None:
                if self._is_unusual_parent(name, parent_pid):
                    flags.append("unusual_parent")

            if flags:
                suspicious.append({
                    "pid": pid,
                    "name": name,
                    "exe_path": exe_path,
                    "command_line": cmdline,
                    "flags": flags,
                })

        return suspicious

    def _is_unsigned_windows(self, exe_path: str) -> bool:
        sigcheck = self._run_command(
            ["powershell", "-Command",
             f"(Get-AuthenticodeSignature -FilePath '{exe_path}' -ErrorAction SilentlyContinue).Status"],
            timeout=5,
        )
        if sigcheck["returncode"] == 0 and sigcheck["stdout"].strip():
            return sigcheck["stdout"].strip() == "NotSigned"
        return False

    def _is_unusual_parent(self, process_name: str, parent_pid: int) -> bool:
        if not self._has_psutil:
            return False

        unusual_parents = {
            "cmd.exe": ["winword.exe", "excel.exe", "outlook.exe", "acrobat.exe", "chrome.exe"],
            "powershell.exe": ["winword.exe", "excel.exe", "outlook.exe", "acrobat.exe"],
            "wscript.exe": ["*"],
            "cscript.exe": ["*"],
            "mshta.exe": ["*"],
            "rundll32.exe": ["*"],
        }

        try:
            parent = self._psutil.Process(parent_pid)
            parent_name = parent.name().lower()

            lower_name = process_name.lower()
            for suspicious_child, suspicious_parents in unusual_parents.items():
                if lower_name == suspicious_child:
                    if "*" in suspicious_parents:
                        return True
                    if parent_name in suspicious_parents:
                        return True
        except (self._psutil.NoSuchProcess, self._psutil.AccessDenied):
            pass
        except Exception:
            pass

        return False
