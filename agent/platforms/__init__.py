import platform as _platform
import os
import sys


def get_platform():
    system = _platform.system().lower()
    if system == "windows":
        return "windows"
    elif system == "darwin":
        return "macos"
    else:
        return "linux"


def is_windows():
    return get_platform() == "windows"


def is_linux():
    return get_platform() == "linux"


def is_macos():
    return get_platform() == "macos"


def get_os_info():
    system = _platform.system()
    release = _platform.release()
    version = _platform.version()
    architecture = _platform.machine()

    if is_windows():
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            try:
                build = winreg.QueryValueEx(key, "CurrentBuild")[0]
            except OSError:
                build = release
            try:
                ubr = winreg.QueryValueEx(key, "UBR")[0]
                build = f"{build}.{ubr}"
            except OSError:
                pass
            try:
                display_version = winreg.QueryValueEx(key, "DisplayVersion")[0]
            except OSError:
                display_version = release
            try:
                product_name = winreg.QueryValueEx(key, "ProductName")[0]
            except OSError:
                product_name = f"Windows {release}"
            winreg.CloseKey(key)
            return {
                "name": product_name,
                "version": display_version,
                "build": build,
                "architecture": architecture,
                "kernel": version,
            }
        except Exception:
            return {
                "name": f"Windows {release}",
                "version": release,
                "build": release,
                "architecture": architecture,
                "kernel": version,
            }

    elif is_macos():
        try:
            import subprocess
            result = subprocess.run(["sw_vers"], capture_output=True, text=True)
            lines = result.stdout.strip().split("\n")
            info = {}
            for line in lines:
                if ":" in line:
                    key, val = line.split(":", 1)
                    info[key.strip()] = val.strip()
            return {
                "name": info.get("ProductName", "macOS"),
                "version": info.get("ProductVersion", release),
                "build": info.get("BuildVersion", ""),
                "architecture": architecture,
                "kernel": version,
            }
        except Exception:
            return {
                "name": "macOS",
                "version": release,
                "build": "",
                "architecture": architecture,
                "kernel": version,
            }

    else:
        import distro as _distro
        name = _distro.name(pretty=True) if 'distro' in sys.modules or _attempt_import_distro() else "Linux"
        return {
            "name": name,
            "version": release,
            "build": "",
            "architecture": architecture,
            "kernel": version,
        }


def _attempt_import_distro():
    try:
        import distro
        return True
    except ImportError:
        return False
