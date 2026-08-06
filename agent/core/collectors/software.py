import logging
import os
import json
import re
from datetime import datetime

from agent.core.collector import BaseCollector
from agent.platforms import is_windows, is_linux, is_macos


logger = logging.getLogger("aegisx.collector.software")

_LATEST_VERSIONS = {
    "google chrome": "131.0.6778.0",
    "microsoft edge": "131.0.2903.0",
    "mozilla firefox": "132.0",
    "firefox": "132.0",
    "adobe acrobat reader": "2024.003",
    "adobe acrobat": "2024.003",
    "adobe reader": "2024.003",
    "java 8": "1.8.0_431",
    "java runtime": "1.8.0_431",
    "jre": "1.8.0_431",
    "oracle java": "21.0.5",
    "openjdk": "21.0.5",
    "python": "3.13.0",
    "python 3": "3.13.0",
    "node.js": "22.11.0",
    "nodejs": "22.11.0",
    "git": "2.47.0",

# FIX RECOMMENDATIONS with download URLs for each outdated app
_FIX_RECOMMENDATIONS = {
    "google chrome": {"action": "Update via Chrome → Help → About Google Chrome, or download from", "url": "https://www.google.com/chrome/"},
    "microsoft edge": {"action": "Update via Edge → Help → About Microsoft Edge, or download from", "url": "https://www.microsoft.com/edge"},
    "mozilla firefox": {"action": "Update via Firefox → Help → About Firefox, or download from", "url": "https://www.mozilla.org/firefox/"},
    "firefox": {"action": "Update via Firefox → Help → About Firefox, or download from", "url": "https://www.mozilla.org/firefox/"},
    "adobe acrobat reader": {"action": "Update via Help → Check for Updates, or download from", "url": "https://get.adobe.com/reader/"},
    "adobe acrobat": {"action": "Update via Help → Check for Updates, or download from", "url": "https://acrobat.adobe.com/"},
    "adobe reader": {"action": "Update via Help → Check for Updates, or download from", "url": "https://get.adobe.com/reader/"},
    "java": {"action": "Download latest Java from", "url": "https://www.java.com/download/"},
    "oracle java": {"action": "Download latest JDK from", "url": "https://www.oracle.com/java/technologies/downloads/"},
    "openjdk": {"action": "Download latest OpenJDK from", "url": "https://adoptium.net/download/"},
    "python": {"action": "Download latest Python from", "url": "https://www.python.org/downloads/"},
    "node.js": {"action": "Download latest Node.js from", "url": "https://nodejs.org/"},
    "nodejs": {"action": "Download latest Node.js from", "url": "https://nodejs.org/"},
    "git": {"action": "Download latest Git from", "url": "https://git-scm.com/downloads"},
    "7-zip": {"action": "Download latest 7-Zip from", "url": "https://www.7-zip.org/download.html"},
    "vlc media player": {"action": "Download latest VLC from", "url": "https://www.videolan.org/vlc/"},
    "notepad++": {"action": "Download latest Notepad++ from", "url": "https://notepad-plus-plus.org/downloads/"},
    "putty": {"action": "Download latest PuTTY from", "url": "https://www.putty.org/"},
    "wireshark": {"action": "Download latest Wireshark from", "url": "https://www.wireshark.org/download.html"},
    "openssh": {"action": "Update via package manager: apt upgrade openssh-client / brew upgrade openssh", "url": "https://www.openssh.com/"},
    "curl": {"action": "Update via package manager: apt upgrade curl / brew upgrade curl", "url": "https://curl.se/download.html"},
    "openssl": {"action": "Update via package manager: apt upgrade openssl / brew upgrade openssl", "url": "https://www.openssl.org/source/"},
    "apache": {"action": "Update via package manager: apt upgrade apache2 / brew upgrade httpd", "url": "https://httpd.apache.org/download.cgi"},
    "nginx": {"action": "Update via package manager: apt upgrade nginx / brew upgrade nginx", "url": "https://nginx.org/en/download.html"},
    "mysql": {"action": "Download latest MySQL from", "url": "https://dev.mysql.com/downloads/"},
    "postgresql": {"action": "Update via package manager: apt upgrade postgresql", "url": "https://www.postgresql.org/download/"},
    "docker": {"action": "Download latest Docker from", "url": "https://www.docker.com/products/docker-desktop"},
    "virtualbox": {"action": "Download latest VirtualBox from", "url": "https://www.virtualbox.org/wiki/Downloads"},
    "winscp": {"action": "Download latest WinSCP from", "url": "https://winscp.net/eng/download.php"},
    "zoom": {"action": "Update via Zoom → Check for Updates, or download from", "url": "https://zoom.us/download"},
    "slack": {"action": "Update via Slack → Check for Updates, or download from", "url": "https://slack.com/downloads"},
    "discord": {"action": "Update via Discord → Check for Updates, or download from", "url": "https://discord.com/download"},
    "telegram": {"action": "Download latest Telegram from", "url": "https://desktop.telegram.org/"},
    "signal": {"action": "Download latest Signal from", "url": "https://signal.org/download/"},
    "teamviewer": {"action": "Download latest TeamViewer from", "url": "https://www.teamviewer.com/download/"},
    "anydesk": {"action": "Download latest AnyDesk from", "url": "https://anydesk.com/download"},
    "dropbox": {"action": "Download latest Dropbox from", "url": "https://www.dropbox.com/downloading"},
    "onedrive": {"action": "Update via Microsoft Store or download from", "url": "https://www.microsoft.com/en-us/microsoft-365/onedrive/download"},
    "powershell": {"action": "Download latest PowerShell from", "url": "https://github.com/PowerShell/PowerShell/releases"},
    "windows terminal": {"action": "Update via Microsoft Store or download from", "url": "https://github.com/microsoft/terminal/releases"},
    "vscode": {"action": "Update via VS Code → Check for Updates, or download from", "url": "https://code.visualstudio.com/download"},
    "visual studio code": {"action": "Update via VS Code → Check for Updates, or download from", "url": "https://code.visualstudio.com/download"},
}  
    "7-zip": "24.08",
    "7zip": "24.08",
    "notepad++": "8.7.1",
    "vscode": "1.95.0",
    "visual studio code": "1.95.0",
    "putty": "0.81",
    "wireshark": "4.4.0",
    "vlc media player": "3.0.21",
    "vlc": "3.0.21",
    "zoom": "6.2.0",
    "slack": "4.40.0",
    "discord": "1.0.9167",
    "telegram desktop": "5.8.0",
    "docker desktop": "4.35.0",
    "docker": "27.3.0",
    "openssh": "9.9",
    "libreoffice": "24.8.0",
    "apache": "2.4.62",
    "nginx": "1.27.0",
    "mysql": "9.1.0",
    "postgresql": "17.0",
    "microsoft teams": "24277.3506",
    "onedrive": "24.196.0923",
    "dropbox": "210.4.4854",
    "keepass": "2.57",
    "veracrypt": "1.26.7",
    "bitwarden": "2024.11.0",
    "tor browser": "14.0.0",
}

_EOL_OS_VERSIONS = {
    "windows": [
        {"name": "windows 7", "eol_date": "2020-01-14"},
        {"name": "windows 8", "eol_date": "2016-01-12"},
        {"name": "windows server 2008", "eol_date": "2020-01-14"},
        {"name": "windows server 2012", "eol_date": "2023-10-10"},
        {"name": "windows xp", "eol_date": "2014-04-08"},
        {"name": "windows vista", "eol_date": "2017-04-11"},
    ],
    "linux": [],
    "macos": [
        {"name": "10.13", "eol_date": "2020-12-01"},
        {"name": "10.14", "eol_date": "2021-10-01"},
        {"name": "10.15", "eol_date": "2022-09-01"},
    ],
}

_EOL_SOFTWARE = [
    {"name_pattern": re.compile(r"adobe flash", re.IGNORECASE), "eol_date": "2020-12-31"},
    {"name_pattern": re.compile(r"internet explorer", re.IGNORECASE), "eol_date": "2022-06-15"},
    {"name_pattern": re.compile(r"java\s+(6|7)\b", re.IGNORECASE), "eol_date": "2015-04-14"},
    {"name_pattern": re.compile(r"\.net framework\s+[1-3]\.", re.IGNORECASE), "eol_date": "2018-07-10"},
    {"name_pattern": re.compile(r"silverlight", re.IGNORECASE), "eol_date": "2021-10-12"},
    {"name_pattern": re.compile(r"python\s+2\.", re.IGNORECASE), "eol_date": "2020-01-01"},
    {"name_pattern": re.compile(r"openssl\s+1\.0\.", re.IGNORECASE), "eol_date": "2019-12-31"},
    {"name_pattern": re.compile(r"openssl\s+1\.1\.0", re.IGNORECASE), "eol_date": "2020-09-10"},
    {"name_pattern": re.compile(r"windows\s+live\s+essentials", re.IGNORECASE), "eol_date": "2017-01-10"},
    {"name_pattern": re.compile(r"quicktime", re.IGNORECASE), "eol_date": "2016-04-19"},
    {"name_pattern": re.compile(r"shockwave", re.IGNORECASE), "eol_date": "2019-04-09"},
    {"name_pattern": re.compile(r"realplayer", re.IGNORECASE), "eol_date": "2011-10-24"},
]

_KNOWN_CVE_SOFTWARE = [
    {"name_pattern": re.compile(r"log4j", re.IGNORECASE), "cve": "CVE-2021-44228", "severity": "critical"},
    {"name_pattern": re.compile(r"apache\s+struts", re.IGNORECASE), "cve": "CVE-2017-5638", "severity": "critical"},
    {"name_pattern": re.compile(r"apache\s+tomcat\s+[7-9]", re.IGNORECASE), "cve": "CVE-2024-xxxxx", "severity": "high"},
    {"name_pattern": re.compile(r"openssl\s+[0-1]\.", re.IGNORECASE), "cve": "CVE-2022-3786", "severity": "high"},
    {"name_pattern": re.compile(r"spring\s+framework", re.IGNORECASE), "cve": "CVE-2022-22965", "severity": "critical"},
    {"name_pattern": re.compile(r"php\s+[5-7]\.", re.IGNORECASE), "cve": "CVE-2021-21703", "severity": "high"},
    {"name_pattern": re.compile(r"drupal\s+[7-8]\.", re.IGNORECASE), "cve": "CVE-2018-7600", "severity": "critical"},
    {"name_pattern": re.compile(r"wordpress\s+[1-5]\.", re.IGNORECASE), "cve": "CVE-2022-21661", "severity": "critical"},
]


class SoftwareCollector(BaseCollector):
    def __init__(self, config=None):
        super().__init__(config)

    async def collect(self) -> dict:
        packages = self._collect_packages()
        apps_with_risk = self._assess_application_risk(packages)
        outdated = [a for a in apps_with_risk if a.get("risk_flags") and "outdated" in a["risk_flags"]]
        eol = [a for a in apps_with_risk if a.get("risk_flags") and "eol" in a["risk_flags"]]
        vulnerable = [a for a in apps_with_risk if a.get("risk_flags") and "vulnerable" in a["risk_flags"]]

        result = {
            "installed_packages": apps_with_risk,
            "total_packages": len(apps_with_risk),
            "outdated_count": len(outdated),
            "eol_count": len(eol),
            "vulnerable_count": len(vulnerable),
            "outdated_applications": outdated,
            "eol_software": eol,
            "vulnerable_software": vulnerable,
            "running_services": self._collect_services(),
            "startup_programs": self._collect_startup(),
            "browser_extensions": self._collect_browser_extensions(),
            "certificates": self._collect_certificates(),
            "os_build": self._collect_os_build(),
            "os_eol_check": self._check_os_eol(),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        return result

    def _collect_packages(self) -> list:
        if is_windows():
            return self._collect_packages_windows()
        elif is_linux():
            return self._collect_packages_linux()
        elif is_macos():
            return self._collect_packages_macos()
        return []

    def _collect_packages_windows(self) -> list:
        packages = []
        ps_cmd = (
            "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
            "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
            "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
            "| Where-Object { $_.DisplayName -ne $null } "
            "| Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation "
            "| Sort-Object DisplayName "
            "| ConvertTo-Json -Compress -Depth 2"
        )
        result = self._run_command(["powershell", "-Command", ps_cmd], timeout=30)
        if result["returncode"] == 0 and result["stdout"]:
            try:
                data = json.loads(result["stdout"])
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    install_location = item.get("InstallLocation", "") or ""
                    size_estimate = 0
                    if install_location and os.path.isdir(install_location):
                        try:
                            total_sz = 0
                            for dirpath, dirnames, filenames in os.walk(install_location):
                                for f in filenames:
                                    try:
                                        total_sz += os.path.getsize(os.path.join(dirpath, f))
                                    except OSError:
                                        pass
                                if total_sz > 5 * 1024 * 1024 * 1024:
                                    break
                            size_estimate = total_sz
                        except Exception:
                            size_estimate = 0

                    packages.append({
                        "name": item.get("DisplayName", ""),
                        "version": item.get("DisplayVersion", ""),
                        "publisher": item.get("Publisher", ""),
                        "install_date": item.get("InstallDate", ""),
                        "install_location": install_location,
                        "size_bytes": size_estimate,
                        "source": "windows_registry",
                    })
            except json.JSONDecodeError:
                logger.warning("Failed to parse Windows package JSON")

        if not packages:
            result = self._run_command(
                ["wmic", "product", "get", "Name,Version,Vendor,InstallDate", "/format:csv"],
                timeout=30,
            )
            if result["returncode"] == 0 and result["stdout"]:
                for line in result["stdout"].split("\n")[1:]:
                    parts = line.strip().split(",", 3)
                    if len(parts) >= 2 and parts[1]:
                        packages.append({
                            "name": parts[1] if len(parts) > 1 else "",
                            "version": parts[2] if len(parts) > 2 else "",
                            "publisher": parts[3] if len(parts) > 3 else "",
                            "source": "wmic",
                        })

        return packages

    def _collect_packages_linux(self) -> list:
        packages = []

        if os.path.exists("/usr/bin/dpkg"):
            result = self._run_command(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n"], timeout=20)
            if result["returncode"] == 0:
                for line in result["stdout"].split("\n"):
                    parts = line.split("\t", 2)
                    if len(parts) >= 2:
                        packages.append({
                            "name": parts[0],
                            "version": parts[1],
                            "publisher": parts[2] if len(parts) > 2 else "",
                            "source": "dpkg",
                        })

        elif os.path.exists("/usr/bin/rpm"):
            result = self._run_command(
                ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"],
                timeout=20,
            )
            if result["returncode"] == 0:
                for line in result["stdout"].split("\n"):
                    parts = line.split("\t", 2)
                    if len(parts) >= 2:
                        packages.append({
                            "name": parts[0],
                            "version": parts[1],
                            "publisher": parts[2] if len(parts) > 2 else "",
                            "source": "rpm",
                        })

        if not packages and os.path.exists("/usr/bin/pacman"):
            result = self._run_command(["pacman", "-Q"], timeout=20)
            if result["returncode"] == 0:
                for line in result["stdout"].split("\n"):
                    parts = line.strip().split(" ", 1)
                    if len(parts) == 2:
                        packages.append({
                            "name": parts[0],
                            "version": parts[1],
                            "source": "pacman",
                        })

        if not packages:
            result = self._run_command(["pip", "list", "--format=json"], timeout=15)
            if result["returncode"] == 0 and result["stdout"]:
                try:
                    for pkg in json.loads(result["stdout"]):
                        packages.append({
                            "name": pkg.get("name", ""),
                            "version": pkg.get("version", ""),
                            "source": "pip",
                        })
                except json.JSONDecodeError:
                    pass

        return packages

    def _collect_packages_macos(self) -> list:
        packages = []

        result = self._run_command(["system_profiler", "SPApplicationsDataType"], timeout=20)
        if result["returncode"] == 0:
            current = {}
            for line in result["stdout"].split("\n"):
                line = line.strip()
                if line and not line.startswith(" ") and line.endswith(":"):
                    if current.get("name"):
                        packages.append(current)
                    current = {"name": line.rstrip(":")}
                elif "Version:" in line:
                    current["version"] = line.split(":", 1)[1].strip()
                elif "Obtained from:" in line:
                    current["source"] = line.split(":", 1)[1].strip()
            if current.get("name"):
                packages.append(current)

        result = self._run_command(["brew", "list", "--versions"], timeout=15)
        if result["returncode"] == 0:
            for line in result["stdout"].split("\n"):
                parts = line.strip().split(" ", 1)
                if len(parts) >= 2:
                    packages.append({
                        "name": parts[0],
                        "version": parts[1],
                        "source": "homebrew",
                    })

        return packages

    def _collect_services(self) -> list:
        services = []

        if is_windows():
            result = self._run_command(
                ["powershell", "-Command",
                 "Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress"],
                timeout=15,
            )
            if result["returncode"] == 0 and result["stdout"]:
                try:
                    data = json.loads(result["stdout"])
                    if isinstance(data, dict):
                        data = [data]
                    for svc in data:
                        services.append({
                            "name": svc.get("Name", ""),
                            "display_name": svc.get("DisplayName", ""),
                            "status": svc.get("Status", ""),
                            "start_type": svc.get("StartType", ""),
                            "platform": "windows",
                        })
                except json.JSONDecodeError:
                    pass

        elif is_linux():
            if os.path.exists("/usr/bin/systemctl"):
                result = self._run_command(
                    ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"],
                    timeout=15,
                )
                if result["returncode"] == 0:
                    for line in result["stdout"].split("\n"):
                        parts = line.split()
                        if len(parts) >= 4:
                            services.append({
                                "name": parts[0].replace(".service", ""),
                                "loaded": parts[1],
                                "active": parts[2],
                                "sub": parts[3],
                                "platform": "linux",
                            })

        elif is_macos():
            result = self._run_command(["launchctl", "list"], timeout=15)
            if result["returncode"] == 0:
                for line in result["stdout"].split("\n")[1:]:
                    parts = line.split("\t")
                    if len(parts) >= 3:
                        services.append({
                            "pid": parts[0],
                            "status": parts[1],
                            "label": parts[2],
                            "platform": "macos",
                        })

        return services

    def _collect_startup(self) -> list:
        startup = []

        if is_windows():
            paths = [
                os.path.expandvars("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
                os.path.expandvars("%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            ]
            for startup_dir in paths:
                if os.path.isdir(startup_dir):
                    for entry in os.listdir(startup_dir):
                        startup.append({"name": entry, "location": startup_dir, "type": "shortcut"})

            result = self._run_command(
                ["powershell", "-Command",
                 "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Json -Compress"],
                timeout=10,
            )
            if result["returncode"] == 0 and result["stdout"]:
                try:
                    data = json.loads(result["stdout"])
                    if isinstance(data, dict):
                        data = [data]
                    for item in data:
                        startup.append({
                            "name": item.get("Name", ""),
                            "command": item.get("Command", ""),
                            "location": item.get("Location", ""),
                            "user": item.get("User", ""),
                            "type": "registry",
                        })
                except json.JSONDecodeError:
                    pass

        elif is_linux():
            autostart_dirs = [
                os.path.expanduser("~/.config/autostart"),
                "/etc/xdg/autostart",
            ]
            for d in autostart_dirs:
                if os.path.isdir(d):
                    for entry in os.listdir(d):
                        if entry.endswith(".desktop"):
                            startup.append({"name": entry, "location": d, "type": "desktop"})

            result = self._run_command(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-pager", "--no-legend"])
            if result["returncode"] == 0:
                for line in result["stdout"].split("\n"):
                    parts = line.split()
                    if parts:
                        startup.append({"name": parts[0], "state": "enabled", "type": "systemd"})

        elif is_macos():
            result = self._run_command(["osascript", "-e", "tell application \"System Events\" to get the name of every login item"], timeout=10)
            if result["returncode"] == 0:
                items = result["stdout"].strip().split(", ")
                for item in items:
                    if item:
                        startup.append({"name": item, "type": "login_item"})

            launch_agents_dir = os.path.expanduser("~/Library/LaunchAgents")
            if os.path.isdir(launch_agents_dir):
                for entry in os.listdir(launch_agents_dir):
                    if entry.endswith(".plist"):
                        startup.append({"name": entry, "location": launch_agents_dir, "type": "launch_agent"})

        return startup

    def _collect_browser_extensions(self) -> list:
        extensions = []

        browser_paths = {
            "chrome": {
                "windows": os.path.expandvars("%LOCALAPPDATA%\\Google\\Chrome\\User Data"),
                "linux": os.path.expanduser("~/.config/google-chrome"),
                "macos": os.path.expanduser("~/Library/Application Support/Google/Chrome"),
            },
            "edge": {
                "windows": os.path.expandvars("%LOCALAPPDATA%\\Microsoft\\Edge\\User Data"),
                "linux": os.path.expanduser("~/.config/microsoft-edge"),
                "macos": os.path.expanduser("~/Library/Application Support/Microsoft Edge"),
            },
            "firefox": {
                "windows": os.path.expandvars("%APPDATA%\\Mozilla\\Firefox\\Profiles"),
                "linux": os.path.expanduser("~/.mozilla/firefox"),
                "macos": os.path.expanduser("~/Library/Application Support/Firefox/Profiles"),
            },
        }

        plat = "windows" if is_windows() else "linux" if is_linux() else "macos"

        for browser, paths in browser_paths.items():
            base_path = paths.get(plat, "")
            if not base_path or not os.path.exists(base_path):
                continue

            try:
                if browser in ("chrome", "edge"):
                    ext_dir = os.path.join(base_path, "Default", "Extensions")
                    if not os.path.isdir(ext_dir):
                        for item in os.listdir(base_path):
                            p = os.path.join(base_path, item, "Extensions")
                            if os.path.isdir(p):
                                ext_dirs = [os.path.join(p, d) for d in os.listdir(p)]
                                for ext_id_path in ext_dirs:
                                    ext_id = os.path.basename(ext_id_path)
                                    extensions.append({"browser": browser, "id": ext_id, "type": "chrome_extension"})
                        continue
                    for ext_id in os.listdir(ext_dir):
                        extensions.append({"browser": browser, "id": ext_id, "type": "chrome_extension"})

                elif browser == "firefox":
                    for profile in os.listdir(base_path):
                        if profile.endswith(".default-release") or profile.endswith(".default"):
                            ext_file = os.path.join(base_path, profile, "extensions.json")
                            if os.path.isfile(ext_file):
                                try:
                                    with open(ext_file, "r", encoding="utf-8") as f:
                                        data = json.load(f)
                                    for addon in data.get("addons", []):
                                        extensions.append({
                                            "browser": "firefox",
                                            "name": addon.get("defaultLocale", {}).get("name", addon.get("id", "")),
                                            "id": addon.get("id", ""),
                                            "version": addon.get("version", ""),
                                            "type": "firefox_addon",
                                        })
                                except Exception:
                                    pass
            except Exception as e:
                logger.debug(f"Browser extension collection error ({browser}): {e}")

        return extensions

    def _collect_certificates(self) -> list:
        certs = []

        if is_windows():
            result = self._run_command(
                ["powershell", "-Command",
                 "Get-ChildItem Cert:\\CurrentUser\\Root, Cert:\\LocalMachine\\Root | "
                 "Select-Object Subject,Issuer,NotAfter,Thumbprint | "
                 "ConvertTo-Json -Compress"],
                timeout=15,
            )
            if result["returncode"] == 0 and result["stdout"]:
                try:
                    data = json.loads(result["stdout"])
                    if isinstance(data, dict):
                        data = [data]
                    for cert in data:
                        certs.append({
                            "subject": cert.get("Subject", ""),
                            "issuer": cert.get("Issuer", ""),
                            "not_after": cert.get("NotAfter", ""),
                            "thumbprint": cert.get("Thumbprint", ""),
                            "store": "root",
                        })
                except json.JSONDecodeError:
                    pass

        elif is_linux():
            cert_dirs = ["/etc/ssl/certs", "/usr/share/ca-certificates"]
            for cert_dir in cert_dirs:
                if os.path.isdir(cert_dir):
                    try:
                        for item in os.listdir(cert_dir)[:100]:
                            cert_path = os.path.join(cert_dir, item)
                            if os.path.isfile(cert_path) and any(item.endswith(ext) for ext in (".crt", ".pem", ".cer")):
                                certs.append({"file": item, "path": cert_path, "directory": cert_dir})
                    except PermissionError:
                        pass

        elif is_macos():
            result = self._run_command(
                ["security", "find-certificate", "-a", "-p", "/System/Library/Keychains/SystemRootCertificates.keychain"],
                timeout=15,
            )
            if result["returncode"] == 0 and result["stdout"]:
                count = result["stdout"].count("-----BEGIN CERTIFICATE-----")
                certs.append({"count": count, "store": "SystemRootCertificates", "extracted_count": count})

        return certs

    def _collect_os_build(self) -> dict:
        info = {"kernel_version": ""}

        try:
            import platform
            info["kernel_version"] = platform.version()
            info["system"] = platform.system()
            info["release"] = platform.release()
        except Exception:
            pass

        if is_windows():
            result = self._run_command(
                ["powershell", "-Command", "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').UBR"],
                timeout=10,
            )
            if result["returncode"] == 0:
                info["ubr"] = result["stdout"].strip()

            result = self._run_command(["powershell", "-Command", "(Get-WindowsEdition -Online).Edition"], timeout=15)
            if result["returncode"] == 0:
                info["edition"] = result["stdout"].strip()

        elif is_linux():
            result = self._run_command(["uname", "-r"])
            if result["returncode"] == 0:
                info["kernel_version"] = result["stdout"].strip()

            for distro_file in ["/etc/os-release", "/etc/lsb-release"]:
                if os.path.isfile(distro_file):
                    try:
                        with open(distro_file) as f:
                            for line in f:
                                line = line.strip()
                                if line.startswith("PRETTY_NAME="):
                                    info["distribution"] = line.split("=", 1)[1].strip('"')
                                elif line.startswith("VERSION_ID="):
                                    info["version_id"] = line.split("=", 1)[1].strip('"')
                    except Exception:
                        pass
                    if info.get("distribution"):
                        break

        elif is_macos():
            result = self._run_command(["sw_vers"])
            if result["returncode"] == 0:
                for line in result["stdout"].split("\n"):
                    if ":" in line:
                        key, val = line.split(":", 1)
                        key = key.strip().lower().replace(" ", "_")
                        info[key] = val.strip()

        return info

    def _check_os_eol(self) -> dict:
        info = self._collect_os_build()
        system = info.get("system", "").lower()
        release = info.get("release", "")
        distribution = info.get("distribution", "").lower()
        eol_result = {"eol": False, "eol_date": None, "os_name": "", "details": ""}

        if system == "windows":
            release_lower = release.lower()
            for eol_os in _EOL_OS_VERSIONS.get("windows", []):
                eol_name = eol_os["name"].lower()
                check_str = f"windows {release_lower}"
                if eol_name in check_str or release_lower in eol_name:
                    eol_result["eol"] = True
                    eol_result["eol_date"] = eol_os["eol_date"]
                    eol_result["os_name"] = eol_os["name"]
                    eol_result["details"] = f"Windows {release} is end-of-life since {eol_os['eol_date']}"
                    break

        elif system == "darwin":
            release_short = ".".join(release.split(".")[:2]) if release else ""
            for eol_os in _EOL_OS_VERSIONS.get("macos", []):
                if release_short in eol_os["name"] or eol_os["name"] in release_short:
                    eol_result["eol"] = True
                    eol_result["eol_date"] = eol_os["eol_date"]
                    eol_result["os_name"] = f"macOS {eol_os['name']}"
                    eol_result["details"] = f"macOS {release} is end-of-life since {eol_os['eol_date']}"
                    break

        elif system == "linux":
            kernel_version = info.get("kernel_version", "")
            if kernel_version:
                kernel_parts = kernel_version.split(".")
                if len(kernel_parts) >= 2:
                    try:
                        major = int(kernel_parts[0])
                        if major < 4:
                            eol_result["eol"] = True
                            eol_result["eol_date"] = "Unknown"
                            eol_result["os_name"] = f"Linux Kernel {kernel_version}"
                            eol_result["details"] = f"Linux kernel {kernel_version} is very old and likely EOL"
                    except (ValueError, IndexError):
                        pass

            if distribution and any(old_os in distribution for old_os in
                                     ["ubuntu 14", "ubuntu 16", "debian 8", "debian 9",
                                      "centos 6", "centos 7", "rhel 6", "rhel 7"]):
                eol_result["eol"] = True
                eol_result["eol_date"] = "Check distribution"
                eol_result["os_name"] = distribution
                eol_result["details"] = f"{distribution} appears to be an end-of-life distribution"

        return eol_result

    def _assess_application_risk(self, packages: list) -> list:
        for pkg in packages:
            flags = []
            pkg_name = (pkg.get("name", "") or "").lower().strip()
            pkg_version = (pkg.get("version", "") or "").lower().strip()

            for known_name, latest_ver in _LATEST_VERSIONS.items():
                if known_name in pkg_name or pkg_name == known_name:
                    if pkg_version and self._version_behind(pkg_version, latest_ver):
                        flags.append("outdated")
                        pkg["latest_version"] = latest_ver
                        # Add fix recommendation
                        fix = _FIX_RECOMMENDATIONS.get(known_name)
                        if fix:
                            pkg["fix_action"] = fix["action"]
                            pkg["fix_url"] = fix["url"]
                        else:
                            pkg["fix_action"] = f"Update {pkg.get('name', 'this application')} to version {latest_ver} via your package manager or vendor website"
                            pkg["fix_url"] = ""
                    break

            for eol_sw in _EOL_SOFTWARE:
                if (eol_sw["name_pattern"].search(pkg_name) or
                        eol_sw["name_pattern"].search(pkg.get("publisher", "") or "")):
                    flags.append("eol")
                    pkg["eol_date"] = eol_sw["eol_date"]
                    pkg["fix_action"] = f"Uninstall {pkg.get('name', 'this software')} and upgrade to a supported version immediately. No security patches available."
                    pkg["fix_url"] = ""
                    break

            for cve_sw in _KNOWN_CVE_SOFTWARE:
                if (cve_sw["name_pattern"].search(pkg_name) or
                        cve_sw["name_pattern"].search(pkg.get("publisher", "") or "")):
                    flags.append("vulnerable")
                    pkg["cve"] = cve_sw["cve"]
                    pkg["cve_severity"] = cve_sw["severity"]
                    pkg["fix_action"] = f"Apply security patch for {cve_sw.get('cve', 'vulnerability')}. Update to latest version."
                    pkg["fix_url"] = ""
                    break

            if flags:
                pkg["risk_flags"] = flags

        return packages

    @staticmethod
    def _version_behind(installed: str, latest: str) -> bool:
        def parse_version(v):
            parts = []
            for segment in re.split(r'[.\-_]', str(v)):
                try:
                    parts.append(int(segment))
                except ValueError:
                    for i, ch in enumerate(segment):
                        parts.append(ord(ch.lower()) - ord('a') + 1)
            return parts

        try:
            installed_parts = parse_version(installed)
            latest_parts = parse_version(latest)
            max_len = max(len(installed_parts), len(latest_parts))
            installed_parts.extend([0] * (max_len - len(installed_parts)))
            latest_parts.extend([0] * (max_len - len(latest_parts)))
            for i_val, l_val in zip(installed_parts, latest_parts):
                if i_val < l_val:
                    return True
                if i_val > l_val:
                    return False
            return False
        except Exception:
            return False
