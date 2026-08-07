import logging

from agent.core.collector import BaseCollector


logger = logging.getLogger("AEGIS.collector.system")


class SystemCollector(BaseCollector):
    def __init__(self, config=None):
        super().__init__(config)
        self._has_psutil = False
        try:
            import psutil
            self._psutil = psutil
            self._has_psutil = True
        except ImportError:
            logger.warning("psutil not available; system collector will use fallbacks")

    async def collect(self) -> dict:
        result = {
            "cpu": self._collect_cpu(),
            "memory": self._collect_memory(),
            "disk": self._collect_disk(),
            "network": self._collect_network(),
            "battery": self._collect_battery(),
            "uptime": self.get_uptime(),
            "boot_time": self.get_boot_time(),
            "load_average": self.get_load_average(),
        }
        return result

    def _collect_cpu(self) -> dict:
        if self._has_psutil:
            try:
                freq = self._psutil.cpu_freq()
                cpu_info = {
                    "model": self._psutil.cpu_info().get("brand_raw", "") if hasattr(self._psutil, "cpu_info") else "",
                    "physical_cores": self._psutil.cpu_count(logical=False),
                    "logical_cores": self._psutil.cpu_count(logical=True),
                    "current_frequency_mhz": round(freq.current, 1) if freq else None,
                    "max_frequency_mhz": round(freq.max, 1) if freq else None,
                    "usage_percent": self._psutil.cpu_percent(interval=0.5),
                    "per_core_usage": self._psutil.cpu_percent(interval=0.5, percpu=True),
                }
                try:
                    times = self._psutil.cpu_times_percent()
                    cpu_info["times"] = {
                        "user": getattr(times, "user", None),
                        "system": getattr(times, "system", None),
                        "idle": getattr(times, "idle", None),
                    }
                except Exception:
                    cpu_info["times"] = {}
                try:
                    stats = self._psutil.cpu_stats()
                    cpu_info["ctx_switches"] = getattr(stats, "ctx_switches", None)
                    cpu_info["interrupts"] = getattr(stats, "interrupts", None)
                except Exception:
                    pass
                return cpu_info
            except Exception as e:
                logger.warning(f"CPU collection error: {e}")
                return {"error": str(e)}

        return self._collect_cpu_fallback()

    def _collect_cpu_fallback(self) -> dict:
        import platform
        import os

        info = {
            "model": platform.processor() or "",
            "physical_cores": os.cpu_count(),
            "logical_cores": os.cpu_count(),
        }

        if os.name == "nt":
            result = self._run_command(["wmic", "cpu", "get", "Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed", "/format:csv"])
            if result["returncode"] == 0 and result["stdout"]:
                lines = [l.strip() for l in result["stdout"].split("\n") if l.strip()]
                if len(lines) > 1:
                    parts = lines[1].split(",")
                    if len(parts) >= 2:
                        info["model"] = parts[1]
        else:
            result = self._run_command(["cat", "/proc/cpuinfo"])
            if result["returncode"] == 0:
                for line in result["stdout"].split("\n"):
                    if "model name" in line:
                        info["model"] = line.split(":", 1)[1].strip()
                        break

        return info

    def _collect_memory(self) -> dict:
        if self._has_psutil:
            try:
                mem = self._psutil.virtual_memory()
                swap = self._psutil.swap_memory()
                return {
                    "total_bytes": mem.total,
                    "available_bytes": mem.available,
                    "used_bytes": mem.used,
                    "free_bytes": mem.free,
                    "percent_used": mem.percent,
                    "swap_total_bytes": swap.total,
                    "swap_used_bytes": swap.used,
                    "swap_free_bytes": swap.free,
                    "swap_percent": swap.percent,
                }
            except Exception as e:
                logger.warning(f"Memory collection error: {e}")
                return {"error": str(e)}
        return {}

    def _collect_disk(self) -> dict:
        partitions_data = []
        io_counters = {}

        if self._has_psutil:
            try:
                for partition in self._psutil.disk_partitions(all=False):
                    try:
                        usage = self._psutil.disk_usage(partition.mountpoint)
                        part_data = {
                            "device": partition.device,
                            "mountpoint": partition.mountpoint,
                            "filesystem": partition.fstype,
                            "total_bytes": usage.total,
                            "used_bytes": usage.used,
                            "free_bytes": usage.free,
                            "percent_used": usage.percent,
                        }
                        partitions_data.append(part_data)
                    except PermissionError:
                        partitions_data.append({
                            "device": partition.device,
                            "mountpoint": partition.mountpoint,
                            "filesystem": partition.fstype,
                            "error": "Permission denied",
                        })
                    except Exception as e:
                        partitions_data.append({
                            "device": partition.device,
                            "mountpoint": partition.mountpoint,
                            "error": str(e),
                        })
                try:
                    io = self._psutil.disk_io_counters(perdisk=True)
                    if io:
                        io_counters = {
                            disk: {
                                "read_count": getattr(v, "read_count", 0),
                                "write_count": getattr(v, "write_count", 0),
                                "read_bytes": getattr(v, "read_bytes", 0),
                                "write_bytes": getattr(v, "write_bytes", 0),
                                "read_time_ms": getattr(v, "read_time", 0),
                                "write_time_ms": getattr(v, "write_time", 0),
                            }
                            for disk, v in io.items()
                        }
                except Exception:
                    pass
            except Exception as e:
                logger.warning(f"Disk collection error: {e}")
                return {"error": str(e)}

        return {
            "partitions": partitions_data,
            "io_counters": io_counters,
        }

    def _collect_network(self) -> dict:
        interfaces = []
        io_counters = {}

        if self._has_psutil:
            try:
                addrs = self._psutil.net_if_addrs()
                stats = self._psutil.net_if_stats()

                for iface_name, iface_addrs in addrs.items():
                    iface_data = {
                        "name": iface_name,
                        "is_up": stats.get(iface_name, None),
                    }
                    if stats.get(iface_name):
                        iface_data["is_up"] = stats[iface_name].isup
                        iface_data["speed_mbps"] = stats[iface_name].speed
                        iface_data["mtu"] = stats[iface_name].mtu

                    mac_addr = None
                    for addr in iface_addrs:
                        if getattr(addr.family, "name", "") == "AF_LINK":
                            mac_addr = addr.address
                        if hasattr(addr.family, "name") and addr.family.name == "AF_INET":
                            iface_data.setdefault("ipv4", []).append({
                                "address": addr.address,
                                "netmask": addr.netmask,
                            })
                        if hasattr(addr.family, "name") and addr.family.name == "AF_INET6":
                            iface_data.setdefault("ipv6", []).append({
                                "address": addr.address,
                            })

                    iface_data["mac"] = mac_addr
                    interfaces.append(iface_data)

                net_io = self._psutil.net_io_counters(pernic=True)
                if net_io:
                    io_counters = {
                        nic: {
                            "bytes_sent": getattr(v, "bytes_sent", 0),
                            "bytes_recv": getattr(v, "bytes_recv", 0),
                            "packets_sent": getattr(v, "packets_sent", 0),
                            "packets_recv": getattr(v, "packets_recv", 0),
                            "errin": getattr(v, "errin", 0),
                            "errout": getattr(v, "errout", 0),
                            "dropin": getattr(v, "dropin", 0),
                            "dropout": getattr(v, "dropout", 0),
                        }
                        for nic, v in net_io.items()
                    }
            except Exception as e:
                logger.warning(f"Network collection error: {e}")
                return {"error": str(e)}

        return {
            "interfaces": interfaces,
            "io_counters": io_counters,
        }

    def _collect_battery(self) -> dict:
        if self._has_psutil:
            try:
                battery = self._psutil.sensors_battery()
                if battery:
                    return {
                        "percent": battery.percent,
                        "power_plugged": battery.power_plugged,
                        "charging": battery.power_plugged,
                        "seconds_left": battery.secsleft if battery.secsleft != self._psutil.POWER_TIME_UNLIMITED else None,
                    }
            except Exception:
                pass
        return {"available": False}
