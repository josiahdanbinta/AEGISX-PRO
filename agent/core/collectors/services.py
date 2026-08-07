import logging
import os
import json
import re
from datetime import datetime

from agent.core.collector import BaseCollector
from agent.platforms import is_windows, is_linux, is_macos

logger = logging.getLogger("aegisx.collector.services")

# Outdated/vulnerable service versions with fix recommendations
_OUTDATED_SERVICES = {
    "sshd": {"min_version": "9.6", "fix": "Update OpenSSH: sudo apt install --only-upgrade openssh-server / brew upgrade openssh", "url": "https://www.openssh.com/"},
    "apache2": {"min_version": "2.4.62", "fix": "Update Apache: sudo apt install --only-upgrade apache2 / brew upgrade httpd", "url": "https://httpd.apache.org/"},
    "httpd": {"min_version": "2.4.62", "fix": "Update Apache: sudo yum update httpd / brew upgrade httpd", "url": "https://httpd.apache.org/"},
    "nginx": {"min_version": "1.26.2", "fix": "Update Nginx: sudo apt install --only-upgrade nginx / brew upgrade nginx", "url": "https://nginx.org/"},
    "mysqld": {"min_version": "8.0.40", "fix": "Update MySQL: sudo apt install --only-upgrade mysql-server", "url": "https://dev.mysql.com/downloads/mysql/"},
    "mariadb": {"min_version": "11.4.3", "fix": "Update MariaDB: sudo apt install --only-upgrade mariadb-server", "url": "https://mariadb.org/download/"},
    "postgresql": {"min_version": "16.4", "fix": "Update PostgreSQL: sudo apt install --only-upgrade postgresql", "url": "https://www.postgresql.org/download/"},
    "redis-server": {"min_version": "7.4.1", "fix": "Update Redis: sudo apt install --only-upgrade redis-server", "url": "https://redis.io/download/"},
    "docker": {"min_version": "27.3.0", "fix": "Update Docker: sudo apt install --only-upgrade docker-ce", "url": "https://docs.docker.com/engine/install/"},
    "containerd": {"min_version": "1.7.22", "fix": "Update containerd: sudo apt install --only-upgrade containerd.io", "url": "https://containerd.io/downloads/"},
    "cups": {"min_version": "2.4.10", "fix": "Update CUPS: sudo apt install --only-upgrade cups", "url": "https://openprinting.github.io/cups/"},
    "bind9": {"min_version": "9.18.28", "fix": "Update BIND DNS: sudo apt install --only-upgrade bind9", "url": "https://www.isc.org/download/"},
    "named": {"min_version": "9.18.28", "fix": "Update BIND DNS: sudo apt install --only-upgrade bind9", "url": "https://www.isc.org/download/"},
    "samba": {"min_version": "4.20.4", "fix": "Update Samba: sudo apt install --only-upgrade samba", "url": "https://www.samba.org/"},
    "smbd": {"min_version": "4.20.4", "fix": "Update Samba: sudo apt install --only-upgrade samba", "url": "https://www.samba.org/"},
    "vsftpd": {"min_version": "3.0.5", "fix": "Update vsftpd: sudo apt install --only-upgrade vsftpd", "url": "https://security.appspot.com/vsftpd.html"},
    "exim4": {"min_version": "4.98", "fix": "Update Exim: sudo apt install --only-upgrade exim4", "url": "https://www.exim.org/"},
    "postfix": {"min_version": "3.9.0", "fix": "Update Postfix: sudo apt install --only-upgrade postfix", "url": "http://www.postfix.org/"},
    "php": {"min_version": "8.3.12", "fix": "Update PHP: sudo apt install --only-upgrade php", "url": "https://www.php.net/downloads"},
    "php-fpm": {"min_version": "8.3.12", "fix": "Update PHP-FPM: sudo apt install --only-upgrade php-fpm", "url": "https://www.php.net/downloads"},
    "tomcat": {"min_version": "10.1.30", "fix": "Update Tomcat: Download from", "url": "https://tomcat.apache.org/download-10.cgi"},
    "jenkins": {"min_version": "2.479.1", "fix": "Update Jenkins: sudo apt install --only-upgrade jenkins", "url": "https://www.jenkins.io/download/"},
}

_CRYPTO_MINER_NAMES = [
    "xmrig", "xmr-stak", "ccminer", "ethminer", "phoenixminer", "lolminer",
    "nbminer", "t-rex", "gminer", "bminer", "cryptominer", "minergate",
    "nicehash", "cpuminer", "bfgminer", "cgminer", "sgminer", "claymore",
    "wildrig", "teamredminer", "kryptex", "srbminer", "kawpowminer",
    "nanominer", "damominer", "cryptodredge", "z-enemy", "finminer",
]

_UNUSUAL_SERVICE_PATHS = [
    re.compile(r'[\\/]temp[\\/]', re.IGNORECASE),
    re.compile(r'[\\/]tmp[\\/]', re.IGNORECASE),
    re.compile(r'[\\/]AppData[\\/]Local[\\/]Temp[\\/]', re.IGNORECASE),
    re.compile(r'[\\/]Downloads[\\/]', re.IGNORECASE),
    re.compile(r'[\\/]ProgramData[\\/]Updater', re.IGNORECASE),
    re.compile(r'^/tmp/', re.IGNORECASE),
    re.compile(r'\./\w+$', re.IGNORECASE),
]

_RENAMED_SYSTEM_SERVICE_PATTERNS = [
    re.compile(r'svch0st', re.IGNORECASE),
    re.compile(r'scvhost', re.IGNORECASE),
    re.compile(r'lssas', re.IGNORECASE),
    re.compile(r'lsass\.exe1', re.IGNORECASE),
    re.compile(r'csrsss', re.IGNORECASE),
    re.compile(r'winl0gon', re.IGNORECASE),
    re.compile(r'sp00lsv', re.IGNORECASE),
    re.compile(r'expl0rer', re.IGNORECASE),
    re.compile(r'iexpl0re', re.IGNORECASE),
    re.compile(r'cr0n', re.IGNORECASE),
    re.compile(r'ssh[dD]\d+', re.IGNORECASE),
    re.compile(r'\[kworker\]', re.IGNORECASE),
]

_HIGH_RISK_SERVICE_NAMES = [
    "vnc", "vncserver", "tightvnc", "ultravnc", "realvnc", "teamviewer",
    "anydesk", "logmein", "gotomypc", "splashtop", "ammyy", "supremo",
    "radmin", "dameware", "pcanywhere", "screenconnect", "connectwise",
]


class ServicesCollector(BaseCollector):
    def __init__(self, config=None):
        super().__init__(config)
        self._suspicious_config = (config or {}).get("suspicious_detection", {})

    async def collect(self) -> dict:
        platform_name = "windows" if is_windows() else "linux" if is_linux() else "macos"
        services = []

        if is_windows():
            services = self._collect_windows_services()
        elif is_linux():
            services = self._collect_linux_services()
        elif is_macos():
            services = self._collect_macos_services()

        for svc in services:
            svc["risk_flags"] = self._assess_service_risk(svc, platform_name)

        suspicious = [s for s in services if s.get("risk_flags")]
        return {
            "services": services,
            "total_count": len(services),
            "running_count": sum(1 for s in services if s.get("status", "").lower() == "running"),
            "suspicious_count": len(suspicious),
            "suspicious": suspicious,
            "platform": platform_name,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

    def _collect_windows_services(self) -> list:
        services = []

        ps_cmd = (
            "Get-CimInstance Win32_Service | "
            "Select-Object Name,DisplayName,State,StartMode,ProcessId,StartName,Description,PathName | "
            "Sort-Object Name | "
            "ConvertTo-Json -Compress -Depth 2"
        )
        result = self._run_command(["powershell", "-Command", ps_cmd], timeout=30)
        if result["returncode"] == 0 and result["stdout"]:
            try:
                data = json.loads(result["stdout"])
                if isinstance(data, dict):
                    data = [data]
                for svc in data:
                    exe_path = ""
                    path_name = svc.get("PathName", "") or ""
                    if path_name:
                        path_clean = path_name.strip('"\'')
                        exe_match = re.search(r'([a-zA-Z]:[\\/][^ "]+\.exe)', path_clean, re.IGNORECASE)
                        if exe_match:
                            exe_path = exe_match.group(1)
                        else:
                            first_part = path_clean.split()[0] if path_clean.split() else ""
                            if os.path.isfile(first_part):
                                exe_path = first_part
                            else:
                                exe_path = path_clean[:255]

                    services.append({
                        "name": svc.get("Name", ""),
                        "display_name": svc.get("DisplayName", ""),
                        "status": svc.get("State", "").lower(),
                        "startup_type": svc.get("StartMode", "").lower(),
                        "process_id": svc.get("ProcessId"),
                        "user_account": svc.get("StartName", ""),
                        "description": (svc.get("Description", "") or "")[:500],
                        "binary_path": path_name[:500] if path_name else "",
                        "exe_path": exe_path,
                        "platform": "windows",
                    })
            except json.JSONDecodeError:
                logger.warning("Failed to parse Windows services JSON from WMI")

        if not services:
            result = self._run_command(["sc", "query", "type=", "service", "state=", "all"], timeout=30)
            if result["returncode"] == 0:
                current = {}
                for line in result["stdout"].split("\n"):
                    line = line.strip()
                    if line.startswith("SERVICE_NAME:"):
                        if current.get("name"):
                            services.append(current)
                        current = {"name": line.split(":", 1)[1].strip(), "platform": "windows"}
                    elif "DISPLAY_NAME:" in line:
                        current["display_name"] = line.split(":", 1)[1].strip()
                    elif "STATE" in line and ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            state_val = parts[1].strip()
                            state_parts = state_val.split()
                            current["status"] = state_parts[0].lower() if state_parts else ""
                    elif "BINARY_PATH_NAME" in line:
                        current["binary_path"] = line.split(":", 1)[1].strip()
                if current.get("name"):
                    services.append(current)

        return services

    def _collect_linux_services(self) -> list:
        services = []

        result = self._run_command(
            ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend",
             "--output=json"],
            timeout=20,
        )
        if result["returncode"] == 0 and result["stdout"]:
            try:
                data = json.loads(result["stdout"])
                for unit in data:
                    unit_name = unit.get("unit", "")
                    services.append({
                        "name": unit_name.replace(".service", ""),
                        "display_name": unit.get("description", "") or unit_name,
                        "status": "running" if unit.get("sub") == "running" else "stopped",
                        "startup_type": unit.get("load", "").lower(),
                        "process_id": None,
                        "user_account": "",
                        "description": unit.get("description", "")[:500],
                        "binary_path": "",
                        "exe_path": "",
                        "platform": "linux",
                        "sub_state": unit.get("sub", ""),
                        "load_state": unit.get("load", ""),
                    })
            except json.JSONDecodeError:
                pass

        if not services:
            result = self._run_command(
                ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"],
                timeout=15,
            )
            if result["returncode"] == 0:
                for line in result["stdout"].split("\n"):
                    parts = line.split()
                    if len(parts) >= 4:
                        unit_name = parts[0]
                        is_running = "running" in parts[3].lower()
                        services.append({
                            "name": unit_name.replace(".service", ""),
                            "display_name": "",
                            "status": "running" if is_running else "stopped",
                            "startup_type": parts[1].lower(),
                            "process_id": None,
                            "user_account": "",
                            "description": " ".join(parts[4:]) if len(parts) > 4 else "",
                            "binary_path": "",
                            "exe_path": "",
                            "platform": "linux",
                            "sub_state": parts[3],
                            "load_state": parts[1],
                        })

        for svc in services:
            name = svc.get("name", "")
            pid_result = self._run_command(["systemctl", "show", f"{name}.service", "--property=MainPID,ExecMainPID"], timeout=5)
            if pid_result["returncode"] == 0:
                for line in pid_result["stdout"].split("\n"):
                    if "MainPID=" in line:
                        try:
                            svc["process_id"] = int(line.split("=")[1]) if line.split("=")[1].isdigit() else None
                        except (ValueError, IndexError):
                            pass
                    if "ExecMainPID=" in line:
                        try:
                            svc["exec_pid"] = int(line.split("=")[1]) if line.split("=")[1].isdigit() else None
                        except (ValueError, IndexError):
                            pass

            user_result = self._run_command(["systemctl", "show", f"{name}.service", "--property=User"], timeout=5)
            if user_result["returncode"] == 0:
                for line in user_result["stdout"].split("\n"):
                    if "User=" in line:
                        svc["user_account"] = line.split("=", 1)[1].strip()

            exec_result = self._run_command(
                ["systemctl", "show", f"{name}.service", "--property=ExecStart"], timeout=5
            )
            if exec_result["returncode"] == 0:
                for line in exec_result["stdout"].split("\n"):
                    if "ExecStart=" in line:
                        exec_start = line.split("=", 1)[1].strip()
                        svc["binary_path"] = exec_start[:500]
                        parts = exec_start.split()
                        if parts:
                            first = parts[0].lstrip("{").rstrip("}")
                            exe_path = first.split(";")[0]
                            if exe_path and os.path.isfile(exe_path):
                                svc["exe_path"] = exe_path
                        break

        if not services:
            init_scripts = ["/etc/init.d", "/etc/rc.d"]
            for init_dir in init_scripts:
                if os.path.isdir(init_dir):
                    for script in os.listdir(init_dir):
                        script_path = os.path.join(init_dir, script)
                        if os.access(script_path, os.X_OK):
                            services.append({
                                "name": script,
                                "display_name": script,
                                "status": "unknown",
                                "startup_type": "init",
                                "process_id": None,
                                "user_account": "",
                                "description": "",
                                "binary_path": script_path,
                                "exe_path": script_path,
                                "platform": "linux",
                            })

        return services

    def _collect_macos_services(self) -> list:
        services = []

        result = self._run_command(["launchctl", "list"], timeout=15)
        if result["returncode"] == 0:
            lines = result["stdout"].split("\n")
            for line in lines[1:]:
                parts = line.split("\t")
                if len(parts) >= 3:
                    pid = parts[0].strip()
                    status_code = parts[1].strip()
                    label = parts[2].strip()
                    if label and label != "-":
                        status = "running" if pid and pid != "-" and pid != "0" else "stopped"
                        process_id = None
                        try:
                            process_id = int(pid) if pid and pid != "-" else None
                        except (ValueError, TypeError):
                            process_id = None

                        services.append({
                            "name": label,
                            "display_name": label,
                            "status": status,
                            "startup_type": "launchd",
                            "process_id": process_id,
                            "user_account": "",
                            "description": "",
                            "binary_path": "",
                            "exe_path": "",
                            "platform": "macos",
                            "launchctl_status": status_code,
                        })

        for svc in services:
            label = svc.get("name", "")
            for plist_base in [f"/System/Library/LaunchDaemons/{label}.plist",
                               f"/Library/LaunchDaemons/{label}.plist",
                               os.path.expanduser(f"~/Library/LaunchAgents/{label}.plist")]:
                if os.path.isfile(plist_base):
                    plist_result = self._run_command(
                        ["plutil", "-convert", "json", "-o", "-", plist_base], timeout=5
                    )
                    if plist_result["returncode"] == 0 and plist_result["stdout"]:
                        try:
                            plist_data = json.loads(plist_result["stdout"])
                            svc["display_name"] = plist_data.get("Label", label)
                            svc["user_account"] = plist_data.get("UserName", "")
                            if "ProgramArguments" in plist_data:
                                args = plist_data["ProgramArguments"]
                                if isinstance(args, list) and args:
                                    svc["binary_path"] = args[0]
                                    if os.path.isfile(args[0]):
                                        svc["exe_path"] = args[0]
                            elif "Program" in plist_data:
                                svc["binary_path"] = plist_data["Program"]
                                if os.path.isfile(plist_data["Program"]):
                                    svc["exe_path"] = plist_data["Program"]
                        except (json.JSONDecodeError, Exception):
                            pass
                    break

        return services

    def _assess_service_risk(self, svc: dict, platform: str) -> list:
        flags = []
        name = svc.get("name", "").lower()
        display = svc.get("display_name", "").lower()
        exe_path = svc.get("exe_path", "")
        binary_path = svc.get("binary_path", "")
        description = svc.get("description", "").lower()
        combined = f"{name} {display} {description}"

        for keyword in _CRYPTO_MINER_NAMES:
            if keyword.lower() in combined:
                flags.append("crypto_miner_name")
                break

        suspicious_count = 0
        for keyword in _CRYPTO_MINER_NAMES:
            if keyword.lower() in name:
                suspicious_count += 1
            if keyword.lower() in display:
                suspicious_count += 1
        if suspicious_count >= 2:
            if "crypto_miner_name" not in flags:
                flags.append("crypto_miner_name")

        for pattern in _RENAMED_SYSTEM_SERVICE_PATTERNS:
            if pattern.search(name) or pattern.search(display):
                flags.append("renamed_system_service")
                break

        check_path = exe_path or binary_path
        if check_path:
            for pattern in _UNUSUAL_SERVICE_PATHS:
                if pattern.search(check_path):
                    flags.append("unusual_path")
                    break

        for high_risk in _HIGH_RISK_SERVICE_NAMES:
            if high_risk.lower() in name or high_risk.lower() in combined:
                flags.append("remote_access_tool")
                break

        if is_windows() and exe_path and exe_path.lower().endswith(".exe"):
            if self._is_unsigned_windows(exe_path):
                flags.append("unsigned")

        if svc.get("status") == "running":
            if name.startswith("kworker") and "[" in name and "]" in name:
                if "renamed_system_service" not in flags:
                    flags.append("suspicious_masked_process")

        # Check for outdated service versions
        for svc_name, svc_info in _OUTDATED_SERVICES.items():
            if svc_name in name or name == svc_name or svc_name in display:
                svc_version = svc.get("version", "")
                if svc_version and self._is_version_behind(svc_version, svc_info["min_version"]):
                    flags.append("outdated")
                    svc["latest_version"] = svc_info["min_version"]
                    svc["fix_action"] = svc_info["fix"]
                    svc["fix_url"] = svc_info["url"]
                    svc["current_version"] = svc_version
                elif not svc_version:
                    # Can't determine version — flag as needing verification
                    flags.append("version_unknown")
                    svc["fix_action"] = svc_info["fix"]
                    svc["fix_url"] = svc_info["url"]
                break

        return flags

    @staticmethod
    def _is_version_behind(current: str, minimum: str) -> bool:
        """Compare semantic versions. Returns True if current < minimum."""
        try:
            import re
            def parse(v):
                parts = []
                for seg in re.split(r'[.\-_]', str(v)):
                    try: parts.append(int(seg))
                    except: parts.append(0)
                return parts
            cp = parse(current)
            mp = parse(minimum)
            max_len = max(len(cp), len(mp))
            cp.extend([0] * (max_len - len(cp)))
            mp.extend([0] * (max_len - len(mp)))
            for c, m in zip(cp, mp):
                if c < m: return True
                if c > m: return False
            return False
        except:
            return False

    def _is_unsigned_windows(self, exe_path: str) -> bool:
        import subprocess
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "(Get-AuthenticodeSignature -LiteralPath $env:EXEPATH -ErrorAction SilentlyContinue).Status"],
                env={"EXEPATH": exe_path, **__import__('os').environ},
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip() == "NotSigned"
        except Exception:
            return False
        return False
