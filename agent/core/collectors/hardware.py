import logging
import os
import platform

from agent.core.collector import BaseCollector
from agent.platforms import is_windows, is_linux, is_macos


logger = logging.getLogger("aegisx.collector.hardware")


class HardwareCollector(BaseCollector):
    def __init__(self, config=None):
        super().__init__(config)
        try:
            import psutil
            self._psutil = psutil
        except ImportError:
            self._psutil = None

    async def collect(self) -> dict:
        result = {
            "motherboard": self._collect_motherboard(),
            "bios": self._collect_bios(),
            "chassis": self._collect_chassis(),
            "ram_modules": self._collect_ram(),
            "gpu": self._collect_gpu(),
            "usb_devices": self._collect_usb(),
            "tpm": self._collect_tpm(),
            "secure_boot": self._collect_secure_boot(),
            "battery_health": self._collect_battery_health(),
            "disk_health": self._collect_smart_disk_health(),
            "temperature_sensors": self._collect_temperature(),
        }
        return result

    def _collect_motherboard(self) -> dict:
        info = {"manufacturer": "", "model": "", "serial": ""}

        if is_windows():
            result = self._run_command(
                ["wmic", "baseboard", "get", "Manufacturer,Product,SerialNumber", "/format:csv"],
                timeout=10,
            )
            if result["returncode"] == 0 and result["stdout"]:
                lines = [l.strip() for l in result["stdout"].split("\n") if l.strip()]
                if len(lines) > 1:
                    parts = lines[1].split(",")
                    if len(parts) >= 4:
                        info = {
                            "manufacturer": parts[1],
                            "model": parts[2],
                            "serial": parts[3],
                        }

            if not info.get("model"):
                result = self._run_command(
                    ["powershell", "-Command", "(Get-WmiObject Win32_BaseBoard).Product"],
                    timeout=10,
                )
                if result["returncode"] == 0:
                    info["model"] = result["stdout"].strip()

        elif is_linux():
            for path in ["/sys/devices/virtual/dmi/id/board_vendor",
                         "/sys/devices/virtual/dmi/id/board_name",
                         "/sys/devices/virtual/dmi/id/board_serial"]:
                try:
                    with open(path) as f:
                        val = f.read().strip()
                    if "vendor" in path:
                        info["manufacturer"] = val
                    elif "name" in path:
                        info["model"] = val
                    elif "serial" in path:
                        info["serial"] = val
                except (FileNotFoundError, PermissionError):
                    pass

            if not info["manufacturer"]:
                result = self._run_command(["dmidecode", "-t", "baseboard"])
                if result["returncode"] == 0:
                    for line in result["stdout"].split("\n"):
                        line = line.strip()
                        if "Manufacturer:" in line:
                            info["manufacturer"] = line.split(":", 1)[1].strip()
                        elif "Product Name:" in line:
                            info["model"] = line.split(":", 1)[1].strip()
                        elif "Serial Number:" in line:
                            info["serial"] = line.split(":", 1)[1].strip()

        elif is_macos():
            result = self._run_command(["system_profiler", "SPHardwareDataType"])
            if result["returncode"] == 0:
                for line in result["stdout"].split("\n"):
                    line = line.strip()
                    if "Model Identifier:" in line:
                        info["model"] = line.split(":", 1)[1].strip()
                    elif "Serial Number" in line:
                        info["serial"] = line.split(":", 1)[1].strip()

        return info

    def _collect_chassis(self) -> dict:
        info = {"manufacturer": "", "model": "", "serial": "", "type": ""}

        if is_windows():
            result = self._run_command(
                ["wmic", "systemenclosure", "get", "Manufacturer,ChassisTypes,SerialNumber,SMBIOSAssetTag", "/format:csv"],
                timeout=10,
            )
            if result["returncode"] == 0 and result["stdout"]:
                lines = [l.strip() for l in result["stdout"].split("\n") if l.strip()]
                if len(lines) > 1:
                    parts = lines[1].split(",")
                    if len(parts) >= 4:
                        info = {
                            "manufacturer": parts[1] if len(parts) > 1 else "",
                            "type": parts[2] if len(parts) > 2 else "",
                            "serial": parts[3] if len(parts) > 3 else "",
                            "asset_tag": parts[4] if len(parts) > 4 else "",
                        }

            if not info.get("model"):
                result = self._run_command(
                    ["powershell", "-Command",
                     "(Get-WmiObject Win32_SystemEnclosure).Caption"],
                    timeout=10,
                )
                if result["returncode"] == 0:
                    info["model"] = result["stdout"].strip()

        elif is_linux():
            for key, path in [
                ("manufacturer", "/sys/devices/virtual/dmi/id/chassis_vendor"),
                ("model", "/sys/devices/virtual/dmi/id/chassis_type"),
                ("serial", "/sys/devices/virtual/dmi/id/chassis_serial"),
            ]:
                try:
                    with open(path) as f:
                        info[key] = f.read().strip()
                except (FileNotFoundError, PermissionError):
                    pass

            if not info["manufacturer"]:
                result = self._run_command(["dmidecode", "-t", "chassis"])
                if result["returncode"] == 0:
                    for line in result["stdout"].split("\n"):
                        line = line.strip()
                        if "Manufacturer:" in line:
                            info["manufacturer"] = line.split(":", 1)[1].strip()
                        elif "Type:" in line:
                            info["type"] = line.split(":", 1)[1].strip()
                        elif "Serial Number:" in line:
                            info["serial"] = line.split(":", 1)[1].strip()
                        elif "Asset Tag:" in line:
                            info["asset_tag"] = line.split(":", 1)[1].strip()

        return info

    def _collect_bios(self) -> dict:
        info = {"vendor": "", "version": "", "date": ""}

        if is_windows():
            result = self._run_command(
                ["wmic", "bios", "get", "Manufacturer,SMBIOSBIOSVersion,ReleaseDate", "/format:csv"],
                timeout=10,
            )
            if result["returncode"] == 0 and result["stdout"]:
                lines = [l.strip() for l in result["stdout"].split("\n") if l.strip()]
                if len(lines) > 1:
                    parts = lines[1].split(",")
                    if len(parts) >= 4:
                        info = {
                            "vendor": parts[1],
                            "version": parts[2],
                            "date": parts[3],
                        }

        elif is_linux():
            for key, path in [
                ("vendor", "/sys/devices/virtual/dmi/id/bios_vendor"),
                ("version", "/sys/devices/virtual/dmi/id/bios_version"),
                ("date", "/sys/devices/virtual/dmi/id/bios_date"),
            ]:
                try:
                    with open(path) as f:
                        info[key] = f.read().strip()
                except (FileNotFoundError, PermissionError):
                    pass

            if not info["vendor"]:
                result = self._run_command(["dmidecode", "-t", "bios"])
                if result["returncode"] == 0:
                    for line in result["stdout"].split("\n"):
                        line = line.strip()
                        if "Vendor:" in line:
                            info["vendor"] = line.split(":", 1)[1].strip()
                        elif "Version:" in line and not info["version"]:
                            info["version"] = line.split(":", 1)[1].strip()
                        elif "Release Date:" in line:
                            info["date"] = line.split(":", 1)[1].strip()

        return info

    def _collect_ram(self) -> list:
        modules = []

        if is_windows():
            result = self._run_command(
                ["wmic", "memorychip", "get", "Capacity,Speed,Manufacturer,PartNumber,SerialNumber,DeviceLocator", "/format:csv"],
                timeout=15,
            )
            if result["returncode"] == 0 and result["stdout"]:
                lines = [l.strip() for l in result["stdout"].split("\n") if l.strip()]
                for line in lines[1:]:
                    parts = line.split(",")
                    if len(parts) >= 7:
                        try:
                            capacity_gb = int(parts[1]) // (1024 ** 3) if parts[1] else 0
                        except ValueError:
                            capacity_gb = 0
                        modules.append({
                            "capacity_gb": capacity_gb,
                            "speed_mhz": parts[2] or "",
                            "manufacturer": parts[3] or "",
                            "part_number": parts[4] or "",
                            "serial": parts[5] or "",
                            "slot": parts[6] or "",
                        })

        elif is_linux():
            result = self._run_command(["dmidecode", "-t", "memory"])
            if result["returncode"] == 0:
                current = {}
                for line in result["stdout"].split("\n"):
                    line = line.strip()
                    if "Memory Device" in line:
                        if current:
                            modules.append(current)
                        current = {}
                    elif "Size:" in line:
                        size_str = line.split(":", 1)[1].strip()
                        if "GB" in size_str:
                            try:
                                current["capacity_gb"] = int(size_str.replace("GB", "").strip())
                            except ValueError:
                                current["capacity_gb"] = 0
                        elif "MB" in size_str:
                            try:
                                current["capacity_gb"] = int(size_str.replace("MB", "").strip()) // 1024
                            except ValueError:
                                current["capacity_gb"] = 0
                    elif "Speed:" in line:
                        speed = line.split(":", 1)[1].strip().replace("MHz", "").strip()
                        current["speed_mhz"] = speed
                    elif "Manufacturer:" in line:
                        current["manufacturer"] = line.split(":", 1)[1].strip()
                    elif "Part Number:" in line:
                        current["part_number"] = line.split(":", 1)[1].strip()
                    elif "Serial Number:" in line:
                        current["serial"] = line.split(":", 1)[1].strip()
                    elif "Locator:" in line:
                        current["slot"] = line.split(":", 1)[1].strip()
                if current:
                    modules.append(current)

            if not modules:
                try:
                    with open("/proc/meminfo") as f:
                        for line in f:
                            if "MemTotal" in line:
                                total_kb = int(line.split(":")[1].strip().split()[0])
                                modules = [{"capacity_gb": total_kb // (1024 * 1024), "source": "/proc/meminfo"}]
                                break
                except Exception:
                    pass

        elif is_macos():
            result = self._run_command(["system_profiler", "SPMemoryDataType"])
            if result["returncode"] == 0:
                current = {}
                for line in result["stdout"].split("\n"):
                    line = line.strip()
                    if "BANK" in line:
                        if current:
                            modules.append(current)
                        current = {"slot": line.split("/")[0]}
                    elif "Size:" in line:
                        size_str = line.split(":", 1)[1].strip()
                        if "GB" in size_str:
                            try:
                                current["capacity_gb"] = int(size_str.replace("GB", "").strip())
                            except ValueError:
                                current["capacity_gb"] = 0
                    elif "Type:" in line:
                        current["type"] = line.split(":", 1)[1].strip()
                    elif "Speed:" in line:
                        current["speed_mhz"] = line.split(":", 1)[1].strip().replace("MHz", "").strip()
                    elif "Manufacturer:" in line:
                        current["manufacturer"] = line.split(":", 1)[1].strip()
                    elif "Part Number:" in line:
                        current["part_number"] = line.split(":", 1)[1].strip()
                    elif "Serial Number:" in line:
                        current["serial"] = line.split(":", 1)[1].strip()
                if current:
                    modules.append(current)

        return modules

    def _collect_gpu(self) -> list:
        gpus = []

        if is_windows():
            result = self._run_command(
                ["wmic", "path", "Win32_VideoController", "get", "Name,AdapterRAM,DriverVersion,CurrentHorizontalResolution,CurrentVerticalResolution", "/format:csv"],
                timeout=10,
            )
            if result["returncode"] == 0 and result["stdout"]:
                lines = [l.strip() for l in result["stdout"].split("\n") if l.strip()]
                for line in lines[1:]:
                    parts = line.split(",")
                    if len(parts) >= 3:
                        try:
                            ram_gb = int(parts[2]) / (1024 ** 3) if parts[2] else 0
                        except (ValueError, IndexError):
                            ram_gb = 0
                        gpus.append({
                            "name": parts[1] if len(parts) > 1 else "",
                            "memory_gb": round(ram_gb, 2),
                            "driver_version": parts[3] if len(parts) > 3 else "",
                            "resolution": f"{parts[4]}x{parts[5]}" if len(parts) > 5 else "",
                        })

        elif is_linux():
            result = self._run_command(["lspci"])
            if result["returncode"] == 0:
                for line in result["stdout"].split("\n"):
                    if "VGA" in line or "3D" in line or "Display" in line:
                        if ":" in line:
                            gpus.append({"name": line.split(":", 1)[1].strip(), "source": "lspci"})

            for gpu in gpus:
                match = None
                import re
                name_match = re.match(r'\[([0-9a-fA-F:]+)\]', gpu.get("name", ""))
                if name_match:
                    bdf = name_match.group(1)
                    vendor_result = self._run_command(["lspci", "-v", "-s", bdf])
                    if vendor_result["returncode"] == 0:
                        for line in vendor_result["stdout"].split("\n"):
                            if "driver in use" in line.lower():
                                gpu["driver"] = line.split(":", 1)[1].strip()

            try:
                with open("/proc/driver/nvidia/version") as f:
                    gpu_driver = f.read()
                    for gpu in gpus:
                        if "NVIDIA" in gpu.get("name", ""):
                            gpu["driver_version"] = gpu_driver.split("Module")[-1].strip()[:80]
            except Exception:
                pass

        elif is_macos():
            result = self._run_command(["system_profiler", "SPDisplaysDataType"])
            if result["returncode"] == 0:
                current = {}
                for line in result["stdout"].split("\n"):
                    line = line.strip()
                    if "Chipset Model:" in line:
                        if current:
                            gpus.append(current)
                        current = {"name": line.split(":", 1)[1].strip()}
                    elif "VRAM" in line:
                        vram = line.split(":", 1)[1].strip().replace("MB", "").strip()
                        try:
                            current["memory_mb"] = int(vram)
                            current["memory_gb"] = int(vram) / 1024
                        except ValueError:
                            pass
                    elif "Metal:" in line:
                        current["metal_support"] = line.split(":", 1)[1].strip()
                if current:
                    gpus.append(current)

        if not gpus:
            try:
                from agent.platforms import get_os_info
                os_info = get_os_info()
                gpus = [{"name": f"Unknown GPU on {os_info.get('name', '')}", "source": "fallback"}]
            except Exception:
                pass

        return gpus

    def _collect_usb(self) -> list:
        devices = []

        if is_windows():
            result = self._run_command(
                ["powershell", "-Command",
                 "Get-PnpDevice -Class USB | Select-Object FriendlyName,InstanceId,Status | ConvertTo-Json -Compress"],
                timeout=15,
            )
            if result["returncode"] == 0 and result["stdout"]:
                try:
                    import json
                    data = json.loads(result["stdout"])
                    if isinstance(data, dict):
                        data = [data]
                    for dev in data:
                        if dev.get("Status") != "Unknown":
                            devices.append({
                                "name": dev.get("FriendlyName", ""),
                                "instance_id": dev.get("InstanceId", ""),
                                "status": dev.get("Status", ""),
                            })
                except json.JSONDecodeError:
                    result = self._run_command(["wmic", "path", "Win32_USBControllerDevice", "get", "Dependent", "/format:csv"])
                    if result["returncode"] == 0:
                        for line in result["stdout"].split("\n")[1:]:
                            if "VID_" in line or "PID_" in line:
                                devices.append({"raw": line.strip()})

        elif is_linux():
            result = self._run_command(["lsusb"])
            if result["returncode"] == 0:
                for line in result["stdout"].split("\n"):
                    line = line.strip()
                    if line:
                        parts = line.split(" ", 5)
                        if len(parts) >= 6:
                            devices.append({
                                "bus": parts[1],
                                "device": parts[3].rstrip(":"),
                                "id": parts[5].split(" ")[0] if len(parts[5].split(" ")) > 1 else parts[5],
                                "name": " ".join(parts[5].split(" ")[1:]) if len(parts[5].split(" ")) > 1 else parts[5],
                            })

        elif is_macos():
            result = self._run_command(["system_profiler", "SPUSBDataType"])
            if result["returncode"] == 0:
                current = {}
                for line in result["stdout"].split("\n"):
                    line = line.strip()
                    if line.endswith(":") and not line.startswith(" "):
                        if current.get("name"):
                            devices.append(current)
                        current = {"name": line.rstrip(":")}
                    elif "Product ID:" in line:
                        current["product_id"] = line.split(":", 1)[1].strip()
                    elif "Vendor ID:" in line:
                        current["vendor_id"] = line.split(":", 1)[1].strip()
                    elif "Serial Number:" in line:
                        current["serial"] = line.split(":", 1)[1].strip()
                    elif "Manufacturer:" in line:
                        current["manufacturer"] = line.split(":", 1)[1].strip()
                if current.get("name"):
                    devices.append(current)

        return devices

    def _collect_tpm(self) -> dict:
        info = {"present": False, "version": "", "manufacturer": ""}

        if is_windows():
            try:
                result = self._run_command(
                    ["powershell", "-Command", "Get-Tpm | Select-Object TpmPresent,TpmReady,ManufacturerVersion,ManufacturerId | ConvertTo-Json -Compress"],
                    timeout=10,
                )
                if result["returncode"] == 0 and result["stdout"]:
                    import json
                    data = json.loads(result["stdout"])
                    info = {
                        "present": data.get("TpmPresent", False),
                        "ready": data.get("TpmReady", False),
                        "version": str(data.get("ManufacturerVersion", "")),
                        "manufacturer_id": str(data.get("ManufacturerId", "")),
                    }
            except Exception as e:
                logger.debug(f"TPM detection error: {e}")

        elif is_linux():
            if os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0"):
                info["present"] = True
                result = self._run_command(["tpm_version"])
                if result["returncode"] == 0:
                    info["version"] = result["stdout"].strip()

                for path in ["/sys/class/tpm/tpm0/device/description",
                             "/sys/class/tpm/tpm0/device/caps", "/sys/class/tpm/tpm0/pcr"]:
                    if os.path.exists(path):
                        try:
                            with open(path) as f:
                                info["description"] = f.read().strip()
                                break
                        except Exception:
                            pass

        return info

    def _collect_secure_boot(self) -> dict:
        info = {"enabled": False, "detected": False}

        if is_windows():
            try:
                result = self._run_command(
                    ["powershell", "-Command", "Confirm-SecureBootUEFI | Select-Object -ExpandProperty Value"],
                    timeout=10,
                )
                if result["returncode"] == 0:
                    info["enabled"] = result["stdout"].strip().lower() == "true"
                    info["detected"] = True
            except Exception as e:
                logger.debug(f"Secure Boot detection error: {e}")

        elif is_linux():
            try:
                for path in ["/sys/firmware/efi/efivars/SecureBoot-*",
                             "/sys/firmware/efi/vars/SecureBoot-*"]:
                    import glob
                    matches = glob.glob(path)
                    if matches:
                        info["detected"] = True
                        with open(matches[0], "rb") as f:
                            data = f.read()
                            info["enabled"] = data[-1] == 1
                        break
            except Exception:
                result = self._run_command(["mokutil", "--sb-state"])
                if result["returncode"] == 0 and "enabled" in result["stdout"].lower():
                    info["detected"] = True
                    info["enabled"] = "SecureBoot enabled" in result["stdout"]

        return info

    def _collect_battery_health(self) -> dict:
        info = {"has_battery": False, "design_capacity_mwh": None, "current_capacity_mwh": None,
                "health_percent": None, "cycle_count": None}

        if is_windows():
            result = self._run_command(
                ["powershell", "-Command",
                 "Get-WmiObject Win32_Battery | Select-Object DesignCapacity,FullChargeCapacity,"
                 "DesignVoltage | ConvertTo-Json -Compress"],
                timeout=10,
            )
            if result["returncode"] == 0 and result["stdout"]:
                try:
                    import json
                    data = json.loads(result["stdout"])
                    if isinstance(data, list):
                        data = data[0] if data else {}
                    design_cap = data.get("DesignCapacity")
                    full_cap = data.get("FullChargeCapacity")
                    if design_cap and int(design_cap) > 0:
                        info["has_battery"] = True
                        info["design_capacity_mwh"] = int(design_cap)
                        info["current_capacity_mwh"] = int(full_cap) if full_cap else None
                        if full_cap:
                            info["health_percent"] = round((int(full_cap) / int(design_cap)) * 100, 1)
                    else:
                        if self._psutil:
                            try:
                                bat = self._psutil.sensors_battery()
                                if bat:
                                    info["has_battery"] = True
                                    info["health_percent"] = bat.percent
                            except Exception:
                                pass
                except (json.JSONDecodeError, ValueError):
                    pass

            cycle_result = self._run_command(
                ["powershell", "-Command",
                 "Get-WmiObject -Namespace root\\wmi BatteryCycleCount | "
                 "Select-Object -ExpandProperty CycleCount -ErrorAction SilentlyContinue"],
                timeout=10,
            )
            if cycle_result["returncode"] == 0 and cycle_result["stdout"].strip():
                try:
                    info["cycle_count"] = int(cycle_result["stdout"].strip())
                except ValueError:
                    pass

        elif is_linux():
            bat_dirs = ["/sys/class/power_supply/BAT0", "/sys/class/power_supply/BAT1"]
            for bat_dir in bat_dirs:
                if not os.path.isdir(bat_dir):
                    continue
                info["has_battery"] = True
                for field, param_name in [
                    ("energy_full_design", "design_capacity_mwh"),
                    ("energy_full", "current_capacity_mwh"),
                    ("cycle_count", "cycle_count"),
                ]:
                    fpath = os.path.join(bat_dir, field)
                    try:
                        with open(fpath) as f:
                            val = int(f.read().strip())
                            if param_name == "design_capacity_mwh":
                                val = val // 1000
                            elif param_name == "current_capacity_mwh":
                                val = val // 1000
                            info[param_name] = val
                    except (FileNotFoundError, ValueError):
                        pass

                if info["design_capacity_mwh"] and info["current_capacity_mwh"]:
                    try:
                        info["health_percent"] = round(
                            (info["current_capacity_mwh"] / info["design_capacity_mwh"]) * 100, 1
                        )
                    except (TypeError, ZeroDivisionError):
                        pass
                break

        elif is_macos():
            result = self._run_command(["system_profiler", "SPPowerDataType"], timeout=10)
            if result["returncode"] == 0:
                info["has_battery"] = "Battery Information" in result["stdout"]
                for line in result["stdout"].split("\n"):
                    line = line.strip()
                    if "Cycle Count:" in line:
                        try:
                            info["cycle_count"] = int(line.split(":", 1)[1].strip())
                        except ValueError:
                            pass
                    elif "Full Charge Capacity" in line:
                        try:
                            cap_str = line.split(":", 1)[1].strip().replace("mAh", "").strip()
                            info["current_capacity_mwh"] = int(cap_str)
                        except (ValueError, IndexError):
                            pass
                    elif "Charge Remaining" in line:
                        try:
                            cap_str = line.split(":", 1)[1].strip().replace("mAh", "").strip()
                            remaining = int(cap_str)
                            if info.get("current_capacity_mwh"):
                                info["health_percent"] = round(
                                    (remaining / info["current_capacity_mwh"]) * 100, 1
                                )
                        except (ValueError, IndexError):
                            pass

            result2 = self._run_command(
                ["ioreg", "-r", "-c", "AppleSmartBattery"], timeout=10
            )
            if result2["returncode"] == 0:
                for line in result2["stdout"].split("\n"):
                    if "DesignCapacity" in line:
                        try:
                            val = int(line.split("=")[1].strip())
                            info["design_capacity_mwh"] = val
                        except (ValueError, IndexError):
                            pass

        return info

    def _collect_smart_disk_health(self) -> list:
        disks = []

        if is_windows():
            ps_cmd = (
                "Get-PhysicalDisk | "
                "Select-Object FriendlyName,HealthStatus,OperationalStatus,MediaType,Size,BusType,"
                "DeviceId,SerialNumber | "
                "Sort-Object DeviceId | "
                "ConvertTo-Json -Compress -Depth 2"
            )
            result = self._run_command(["powershell", "-Command", ps_cmd], timeout=20)
            if result["returncode"] == 0 and result["stdout"]:
                try:
                    import json
                    data = json.loads(result["stdout"])
                    if isinstance(data, dict):
                        data = [data]
                    for disk in data:
                        size_gb = 0
                        try:
                            size_gb = round(int(disk.get("Size", 0)) / (1024 ** 3), 1)
                        except (ValueError, TypeError):
                            pass
                        disks.append({
                            "name": disk.get("FriendlyName", ""),
                            "health": disk.get("HealthStatus", ""),
                            "status": disk.get("OperationalStatus", ""),
                            "media_type": disk.get("MediaType", ""),
                            "bus_type": disk.get("BusType", ""),
                            "size_gb": size_gb,
                            "serial": disk.get("SerialNumber", ""),
                            "device_id": disk.get("DeviceId", ""),
                            "platform": "windows",
                        })
                except json.JSONDecodeError:
                    pass

            if not disks:
                result = self._run_command(
                    ["wmic", "diskdrive", "get", "Model,Status,Size,MediaType,InterfaceType,SerialNumber", "/format:csv"],
                    timeout=15,
                )
                if result["returncode"] == 0 and result["stdout"]:
                    lines = [l.strip() for l in result["stdout"].split("\n") if l.strip()]
                    for line in lines[1:]:
                        parts = line.split(",")
                        if len(parts) >= 4 and parts[1]:
                            try:
                                size_val = int(parts[3]) if len(parts) > 3 and parts[3] else 0
                                size_gb = round(size_val / (1024 ** 3), 1)
                            except (ValueError, TypeError):
                                size_gb = 0
                            disks.append({
                                "name": parts[1] if len(parts) > 1 else "",
                                "health": parts[2] if len(parts) > 2 else "",
                                "size_gb": size_gb,
                                "media_type": parts[4] if len(parts) > 4 else "",
                                "bus_type": parts[5] if len(parts) > 5 else "",
                                "serial": parts[6] if len(parts) > 6 else "",
                                "platform": "windows",
                            })

        elif is_linux():
            result = self._run_command(["smartctl", "--scan"], timeout=10)
            smart_devices = []
            if result["returncode"] == 0:
                for line in result["stdout"].split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if parts:
                            smart_devices.append(parts[0])

            import glob
            for device in smart_devices:
                disk_info = {"name": device, "platform": "linux", "smart_available": True}
                result = self._run_command(["smartctl", "-i", device], timeout=10)
                if result["returncode"] == 0:
                    for line in result["stdout"].split("\n"):
                        line = line.strip()
                        if "Device Model:" in line:
                            disk_info["model"] = line.split(":", 1)[1].strip()
                        elif "Serial Number:" in line:
                            disk_info["serial"] = line.split(":", 1)[1].strip()
                        elif "User Capacity:" in line:
                            cap_str = line.split("[", 1)[1].split("]")[0] if "[" in line else ""
                            disk_info["capacity"] = cap_str
                        elif "SMART support is:" in line:
                            disk_info["smart_support"] = "Available" in line

                health_result = self._run_command(["smartctl", "-H", device], timeout=10)
                if health_result["returncode"] == 0:
                    for line in health_result["stdout"].split("\n"):
                        line = line.strip()
                        if "SMART overall-health" in line:
                            disk_info["health"] = line.split(":", 1)[1].strip()
                        elif "SMART Health Status:" in line:
                            disk_info["health"] = line.split(":", 1)[1].strip()

                if not disk_info.get("health"):
                    health_result2 = self._run_command(["smartctl", "-A", device], timeout=10)
                    if health_result2["returncode"] == 0:
                        important_attrs = {
                            "Reallocated_Sector_Ct", "Reallocated_Event_Count",
                            "Current_Pending_Sector", "Offline_Uncorrectable",
                            "UDMA_CRC_Error_Count", "Reported_Uncorrect",
                            "Reallocation_Event_Count", "Spin_Retry_Count",
                        }
                        attrs = {}
                        for line in health_result2["stdout"].split("\n"):
                            for attr_name in important_attrs:
                                if attr_name in line:
                                    parts = line.split()
                                    if len(parts) >= 10:
                                        try:
                                            raw_val = int(parts[9])
                                            attrs[attr_name] = raw_val
                                        except ValueError:
                                            attrs[attr_name] = parts[9]
                        if attrs:
                            disk_info["smart_attributes"] = attrs

                disks.append(disk_info)

            if not disks:
                for dev_path in glob.glob("/sys/block/sd*/device/model"):
                    try:
                        with open(dev_path) as f:
                            model = f.read().strip()
                        serial_path = os.path.join(os.path.dirname(dev_path), "serial")
                        serial = ""
                        try:
                            with open(serial_path) as f:
                                serial = f.read().strip()
                        except Exception:
                            pass
                        disks.append({
                            "name": os.path.basename(os.path.dirname(os.path.dirname(dev_path))),
                            "model": model,
                            "serial": serial,
                            "platform": "linux",
                        })
                    except Exception:
                        pass

        elif is_macos():
            result = self._run_command(["system_profiler", "SPNVMeDataType"], timeout=15)
            if result["returncode"] == 0:
                current = {}
                for line in result["stdout"].split("\n"):
                    line = line.strip()
                    if ":" in line and not line.startswith(" "):
                        if current.get("name"):
                            disks.append(current)
                        current = {"name": line.rstrip(":")}
                    elif "Model:" in line:
                        current["model"] = line.split(":", 1)[1].strip()
                    elif "Serial:" in line:
                        current["serial"] = line.split(":", 1)[1].strip()
                    elif "Capacity:" in line:
                        current["capacity"] = line.split(":", 1)[1].strip()
                    elif "Status:" in line:
                        current["status"] = line.split(":", 1)[1].strip()
                if current.get("name"):
                    disks.append(current)

            result2 = self._run_command(["system_profiler", "SPSerialATADataType"], timeout=15)
            if result2["returncode"] == 0:
                current = {}
                for line in result2["stdout"].split("\n"):
                    line = line.strip()
                    if ":" in line and not line.startswith(" "):
                        if current.get("name"):
                            disks.append(current)
                        current = {"name": line.rstrip(":")}
                    elif "Model:" in line:
                        current["model"] = line.split(":", 1)[1].strip()
                    elif "Serial:" in line:
                        current["serial"] = line.split(":", 1)[1].strip()
                    elif "Capacity:" in line:
                        current["capacity"] = line.split(":", 1)[1].strip()
                    elif "S.M.A.R.T. status:" in line:
                        current["smart_status"] = line.split(":", 1)[1].strip()
                if current.get("name"):
                    disks.append(current)

            for disk in disks:
                disk["platform"] = "macos"

        return disks

    def _collect_temperature(self) -> dict:
        temps = {"cpu": None, "gpu": None, "sensors": []}

        if self._psutil:
            try:
                psutil_temps = self._psutil.sensors_temperatures()
                if psutil_temps:
                    for label, entries in psutil_temps.items():
                        for entry in entries:
                            sensor = {
                                "label": entry.label or label,
                                "current_c": entry.current,
                                "high_c": entry.high,
                                "critical_c": entry.critical,
                            }
                            temps["sensors"].append(sensor)
                            label_lower = label.lower()
                            if not temps["cpu"] and any(k in label_lower for k in ("cpu", "core", "package", "tdie", "tctl")):
                                temps["cpu"] = entry.current
                            if not temps["gpu"] and any(k in label_lower for k in ("gpu", "nvidia", "radeon", "edge")):
                                temps["gpu"] = entry.current
            except Exception:
                pass

        if not temps["sensors"]:
            if is_windows():
                result = self._run_command(
                    ["powershell", "-Command",
                     "Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace root\\wmi | "
                     "Select-Object CurrentTemperature,InstanceName | "
                     "ConvertTo-Json -Compress"],
                    timeout=10,
                )
                if result["returncode"] == 0 and result["stdout"]:
                    try:
                        import json
                        data = json.loads(result["stdout"])
                        if isinstance(data, dict):
                            data = [data]
                        for entry in data:
                            raw_temp = entry.get("CurrentTemperature")
                            if raw_temp:
                                temp_c = round(int(raw_temp) / 10.0 - 273.15, 1)
                                temps["sensors"].append({
                                    "label": entry.get("InstanceName", "CPU"),
                                    "current_c": temp_c,
                                    "platform": "windows",
                                })
                                if not temps["cpu"]:
                                    temps["cpu"] = temp_c
                    except (json.JSONDecodeError, ValueError):
                        pass

            elif is_linux():
                hwmon_base = "/sys/class/hwmon"
                if os.path.isdir(hwmon_base):
                    for hwmon in os.listdir(hwmon_base):
                        hwmon_path = os.path.join(hwmon_base, hwmon)
                        name_path = os.path.join(hwmon_path, "name")
                        hw_name = ""
                        try:
                            with open(name_path) as f:
                                hw_name = f.read().strip()
                        except Exception:
                            hw_name = hwmon

                        for i in range(1, 10):
                            temp_label_path = os.path.join(hwmon_path, f"temp{i}_label")
                            temp_input_path = os.path.join(hwmon_path, f"temp{i}_input")
                            if os.path.isfile(temp_input_path):
                                label = hw_name
                                if os.path.isfile(temp_label_path):
                                    try:
                                        with open(temp_label_path) as f:
                                            label = f"{hw_name}: {f.read().strip()}"
                                    except Exception:
                                        pass
                                try:
                                    with open(temp_input_path) as f:
                                        temp_val = int(f.read().strip()) / 1000.0
                                    temps["sensors"].append({
                                        "label": label,
                                        "current_c": temp_val,
                                        "platform": "linux",
                                    })
                                    label_lower = label.lower()
                                    if not temps["cpu"] and any(k in label_lower for k in ("cpu", "core", "package", "tdie", "tctl")):
                                        temps["cpu"] = temp_val
                                    if not temps["gpu"] and any(k in label_lower for k in ("gpu", "nvidia", "radeon")):
                                        temps["gpu"] = temp_val
                                except (ValueError, OSError):
                                    pass

                if not temps["sensors"]:
                    result = self._run_command(["sensors", "-j"], timeout=10)
                    if result["returncode"] == 0 and result["stdout"]:
                        try:
                            import json
                            data = json.loads(result["stdout"])
                            for chip_name, chip_data in data.items():
                                for sensor_name, sensor_data in chip_data.items():
                                    if isinstance(sensor_data, dict):
                                        for sub_key, sub_val in sensor_data.items():
                                            if "temp" in sub_key and isinstance(sub_val, (int, float)):
                                                label = f"{chip_name}: {sensor_name}/{sub_key}"
                                                temps["sensors"].append({
                                                    "label": label,
                                                    "current_c": sub_val,
                                                    "platform": "linux",
                                                })
                                    elif isinstance(sensor_data, (int, float)):
                                        temps["sensors"].append({
                                            "label": f"{chip_name}: {sensor_name}",
                                            "current_c": sensor_data,
                                            "platform": "linux",
                                        })
                        except (json.JSONDecodeError, Exception):
                            pass

            elif is_macos():
                result = self._run_command(["sudo", "powermetrics", "--samplers", "smc", "-n", "1", "-i", "1000"], timeout=15)
                if result["returncode"] == 0:
                    for line in result["stdout"].split("\n"):
                        if "CPU die temperature" in line:
                            try:
                                temp_str = line.split(":")[1].strip().replace("C", "").strip()
                                temps["cpu"] = float(temp_str)
                            except (ValueError, IndexError):
                                pass

        return temps
