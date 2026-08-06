import asyncio
import json
import logging
import os
import signal
import sys
import socket
import time
import argparse
from datetime import datetime
from pathlib import Path

import yaml

from agent.core.communication import CommunicationModule
from agent.core.collector import BaseCollector
from agent.platforms import get_platform, get_os_info, is_windows, is_linux, is_macos

logger = logging.getLogger("aegisx.agent")

__version__ = "1.1.0"


class AEGISXAgent:
    def __init__(self, config_path: str = None):
        self._config = self._load_config(config_path)
        self._setup_logging()
        self._running = False
        self._shutdown_event = asyncio.Event()
        self._agent_info = {}
        self._collectors: dict[str, BaseCollector] = {}
        self._collector_tasks: dict[str, asyncio.Task] = {}
        self._heartbeat_task: asyncio.Task = None
        self._comm: CommunicationModule = None
        self._data_dir = Path(self._config.get("data_dir", "./data"))
        self._data_dir.mkdir(parents=True, exist_ok=True)

    def _load_config(self, config_path: str = None) -> dict:
        search_paths = [
            config_path,
            os.environ.get("AEGISX_CONFIG"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml"),
            os.path.join(os.getcwd(), "config.yaml"),
        ]

        for path in search_paths:
            if path and os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f)
                logger.info(f"Loaded config from {path}")

                for key in ["server_url", "registration_key", "tenant_id"]:
                    env_key = f"AEGISX_{key.upper()}"
                    if os.environ.get(env_key):
                        config[key] = os.environ[env_key]

                return config

        logger.warning("No config file found, using defaults")
        return {
            "server_url": os.environ.get("AEGISX_SERVER_URL", "https://api.aegisx.local"),
            "registration_key": os.environ.get("AEGISX_REGISTRATION_KEY", ""),
            "tenant_id": os.environ.get("AEGISX_TENANT_ID", ""),
            "heartbeat_interval": 60,
            "monitoring_interval": 30,
            "log_level": "INFO",
            "data_dir": "./data",
        }

    def _setup_logging(self):
        log_level = getattr(logging, self._config.get("log_level", "INFO").upper(), logging.INFO)

        log_dir = self._data_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )

        root = logging.getLogger("aegisx")
        root.setLevel(log_level)

        console = logging.StreamHandler(sys.stdout)
        console.setLevel(log_level)
        console.setFormatter(fmt)
        root.addHandler(console)

        file_handler = logging.FileHandler(
            log_dir / f"agent_{datetime.now().strftime('%Y%m%d')}.log",
            encoding="utf-8",
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)

    def _build_agent_info(self) -> dict:
        os_info = get_os_info()
        ip_addresses = self._get_local_ip_addresses()
        return {
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "platform": get_platform(),
            "os_info": os_info,
            "architecture": os_info.get("architecture", ""),
            "agent_version": __version__,
            "python_version": sys.version,
            "collectors": list(self._collectors.keys()),
            "ip_addresses": ip_addresses,
        }

    @staticmethod
    def _get_local_ip_addresses() -> list:
        addresses = []
        try:
            hostname = socket.gethostname()
            try:
                addresses.append({
                    "interface": "hostname",
                    "ip": socket.gethostbyname(hostname),
                    "type": "IPv4",
                })
            except socket.gaierror:
                pass

            try:
                info = socket.getaddrinfo(hostname, None)
                seen = set()
                for item in info:
                    addr = item[4][0]
                    if addr not in seen and addr != "127.0.0.1" and addr != "::1":
                        seen.add(addr)
                        addr_type = "IPv6" if ":" in addr else "IPv4"
                        addresses.append({
                            "interface": "hostname",
                            "ip": addr,
                            "type": addr_type,
                        })
            except socket.gaierror:
                pass
        except Exception:
            pass

        try:
            import psutil
            for iface_name, iface_addrs in psutil.net_if_addrs().items():
                for addr in iface_addrs:
                    if addr.family.name == "AF_INET" and addr.address != "127.0.0.1":
                        addresses.append({
                            "interface": iface_name,
                            "ip": addr.address,
                            "netmask": addr.netmask,
                            "type": "IPv4",
                        })
                    elif addr.family.name == "AF_INET6" and not addr.address.startswith("fe80"):
                        if "%" not in addr.address:
                            addresses.append({
                                "interface": iface_name,
                                "ip": addr.address,
                                "type": "IPv6",
                            })
        except ImportError:
            pass

        return addresses

    async def _register(self):
        self._agent_info = self._build_agent_info()

        max_attempts = 10
        for attempt in range(max_attempts):
            try:
                result = await self._comm.register(self._agent_info)
                if result and "error" not in result:
                    logger.info(f"Registration successful. Agent ID: {self._comm.agent_id}")
                    return True
                else:
                    err = result.get("error", "Unknown error") if result else "No response"
                    logger.error(f"Registration failed: {err}")
            except Exception as e:
                logger.error(f"Registration error: {e}")

            if attempt < max_attempts - 1:
                delay = min(5 * (2 ** attempt), 60)
                logger.info(f"Retrying registration in {delay}s...")
                await asyncio.sleep(delay)

        logger.critical("Registration failed after max attempts")
        return False

    def _load_collectors(self):
        collector_configs = self._config.get("collectors", {})

        collector_map = {
            "cpu": ("agent.core.collectors.system", "SystemCollector"),
            "memory": ("agent.core.collectors.system", "SystemCollector"),
            "disk": ("agent.core.collectors.system", "SystemCollector"),
            "network": ("agent.core.collectors.system", "SystemCollector"),
            "processes": ("agent.core.collectors.processes", "ProcessCollector"),
            "services": ("agent.core.collectors.services", "ServicesCollector"),
            "installed_software": ("agent.core.collectors.software", "SoftwareCollector"),
            "hardware": ("agent.core.collectors.hardware", "HardwareCollector"),
            "usb": ("agent.core.collectors.hardware", "HardwareCollector"),
            "logs": ("agent.core.collectors.logs", "LogCollector"),
            "ransomware": ("agent.core.collectors.ransomware", "RansomwareMonitor"),
        }

        loaded_modules = {}
        for key, (module_path, class_name) in collector_map.items():
            if not collector_configs.get(key, True):
                continue
            if module_path not in loaded_modules:
                try:
                    import importlib
                    mod = importlib.import_module(module_path)
                    cls = getattr(mod, class_name)
                    loaded_modules[module_path] = (mod, cls)
                except ImportError as e:
                    logger.warning(f"Cannot load collector module {module_path}: {e}")
                    continue
                except AttributeError as e:
                    logger.warning(f"Cannot find class {class_name} in {module_path}: {e}")
                    continue

            mod, cls = loaded_modules[module_path]
            collector_config = {
                "enabled": collector_configs.get(key, True),
                "interval": self._config.get("monitoring_interval", 30),
                "suspicious_detection": self._config.get("suspicious_detection", {}),
                "logs": self._config.get("logs", {}),
            }

            collector_key = f"{key}_{class_name}"
            try:
                instance = cls(config=collector_config)
                self._collectors[collector_key] = instance
                logger.info(f"Loaded collector: {collector_key}")
            except Exception as e:
                logger.error(f"Failed to instantiate {class_name}: {e}")

    async def _heartbeat_loop(self):
        interval = self._config.get("heartbeat_interval", 60)
        logger.info(f"Heartbeat loop started (interval={interval}s)")

        failures = 0
        while not self._shutdown_event.is_set():
            try:
                result = await self._comm.heartbeat()
                if result and "error" not in result:
                    failures = 0
                    logger.debug("Heartbeat sent")
                else:
                    failures += 1
                    logger.warning(f"Heartbeat failed ({failures})")
                    if failures >= 5:
                        logger.error("Too many heartbeat failures, triggering re-registration")
                        self._comm._registered = False
                        await self._register()
                        failures = 0
            except Exception as e:
                failures += 1
                logger.error(f"Heartbeat error: {e}")

            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                pass

        logger.info("Heartbeat loop stopped")

    async def _collector_loop(self, key: str, collector: BaseCollector):
        logger.debug(f"Collector loop started: {key} (interval={collector.interval}s)")

        while not self._shutdown_event.is_set():
            try:
                result = await collector.run()
                await self._comm.send_data(result)
                logger.debug(f"Collection sent: {key} (status={result.get('status')})")
            except Exception as e:
                logger.error(f"Collector loop error ({key}): {e}")

            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=collector.interval)
                break
            except asyncio.TimeoutError:
                pass

        logger.debug(f"Collector loop stopped: {key}")

    def _handle_command(self, command: dict):
        action = command.get("action", "")
        params = command.get("params", {})

        logger.info(f"Processing command: {action}")

        handlers = {
            "collect": self._cmd_collect,
            "status": self._cmd_status,
            "reconfigure": self._cmd_reconfigure,
            "restart": self._cmd_restart,
            "shutdown": self._cmd_shutdown,
            "update": self._cmd_update,
            "get_full_inventory": self._cmd_full_inventory,
            "scan_ransomware": self._cmd_scan_ransomware,
            "get_services": self._cmd_get_services,
            "get_apps": self._cmd_get_apps,
        }

        handler = handlers.get(action)
        if handler:
            try:
                handler(params)
            except Exception as e:
                logger.error(f"Command handler error ({action}): {e}")
        else:
            logger.warning(f"Unknown command action: {action}")

    def _cmd_collect(self, params: dict):
        collector_name = params.get("collector")
        if collector_name:
            for key, collector in self._collectors.items():
                if collector_name in key:
                    asyncio.create_task(self._run_once_collector(key, collector))
                    return
            logger.warning(f"Collector not found: {collector_name}")
        else:
            for key, collector in self._collectors.items():
                asyncio.create_task(self._run_once_collector(key, collector))

    async def _run_once_collector(self, key, collector):
        result = await collector.run()
        await self._comm.send_data(result)

    def _cmd_status(self, params: dict):
        status = {
            "agent_id": self._comm.agent_id,
            "version": __version__,
            "platform": get_platform(),
            "uptime_seconds": time.time() - self._start_time if hasattr(self, "_start_time") else 0,
            "collectors": {k: {"enabled": v.enabled, "last_run": v._last_collection}
                           for k, v in self._collectors.items()},
            "ws_connected": self._comm._ws_connected,
        }
        logger.info(f"Status: {json.dumps(status, default=str)}")

    def _cmd_reconfigure(self, params: dict):
        if not params:
            return
        logger.info(f"Reconfiguring agent: {params}")
        if "monitoring_interval" in params:
            for collector in self._collectors.values():
                collector.interval = params["monitoring_interval"]
        if "log_level" in params:
            level = getattr(logging, params["log_level"].upper(), None)
            if level:
                logging.getLogger("aegisx").setLevel(level)
                for handler in logging.getLogger("aegisx").handlers:
                    handler.setLevel(level)

    def _cmd_restart(self, params: dict):
        logger.info("Restart command received")
        self._shutdown_event.set()
        asyncio.create_task(self._restart())

    def _cmd_shutdown(self, params: dict):
        logger.info("Shutdown command received")
        self._shutdown_event.set()

    def _cmd_update(self, params: dict):
        if self._config.get("enable_auto_update", True):
            logger.info("Update command received (auto-update placeholder)")
        else:
            logger.info("Update command received but auto-update is disabled")

    def _cmd_full_inventory(self, params: dict):
        logger.info("Full inventory collection requested")
        asyncio.create_task(self._run_full_inventory())

    async def _run_full_inventory(self):
        results = {"type": "full_inventory", "timestamp": datetime.utcnow().isoformat() + "Z", "data": {}}
        for key, collector in self._collectors.items():
            try:
                col_result = await collector.run()
                collector_name = col_result.get("collector", key)
                results["data"][collector_name] = col_result.get("data", col_result)
            except Exception as e:
                logger.error(f"Full inventory error ({key}): {e}")
                results["data"][key] = {"error": str(e)}
        await self._comm.send_data(results)
        logger.info("Full inventory sent")

    def _cmd_scan_ransomware(self, params: dict):
        logger.info("Ransomware scan requested")
        for key, collector in self._collectors.items():
            if "RansomwareMonitor" in key:
                asyncio.create_task(self._run_once_collector(key, collector))
                return
        asyncio.create_task(self._run_ransomware_scan())

    async def _run_ransomware_scan(self):
        try:
            from agent.core.collectors.ransomware import RansomwareMonitor
            monitor = RansomwareMonitor(config=self._config)
            result = await monitor.run()
            await self._comm.send_data(result)
        except Exception as e:
            logger.error(f"Ransomware scan error: {e}")

    def _cmd_get_services(self, params: dict):
        logger.info("Services list requested")
        for key, collector in self._collectors.items():
            if "ServicesCollector" in key:
                asyncio.create_task(self._run_once_collector(key, collector))
                return
        for key, collector in self._collectors.items():
            if "SoftwareCollector" in key:
                asyncio.create_task(self._run_once_collector(key, collector))
                return

    def _cmd_get_apps(self, params: dict):
        logger.info("Applications list requested")
        for key, collector in self._collectors.items():
            if "SoftwareCollector" in key:
                asyncio.create_task(self._run_once_collector(key, collector))
                return

    async def start(self):
        logger.info(f"AEGISX Agent v{__version__} starting on {get_platform()}")
        self._start_time = time.time()

        self._comm = CommunicationModule(self._config)
        self._comm.on_command(self._handle_command)

        self._load_collectors()
        logger.info(f"Loaded {len(self._collectors)} collectors")

        registered = await self._register()
        if not registered:
            logger.critical("Cannot start agent without registration")
            return

        asyncio.create_task(self._send_system_profile())

        self._comm.connect_ws()

        self._running = True
        self._shutdown_event.clear()

        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        for key, collector in self._collectors.items():
            self._collector_tasks[key] = asyncio.create_task(
                self._collector_loop(key, collector)
            )

        start_rt = None
        ransom_monitor = None
        for key, collector in self._collectors.items():
            if "LogCollector" in key and hasattr(collector, "start_real_time"):
                start_rt = collector
            if "RansomwareMonitor" in key and hasattr(collector, "start_monitoring"):
                ransom_monitor = collector

        if start_rt:
            start_rt.start_real_time()

        if ransom_monitor:
            ransom_monitor.start_monitoring()
            logger.info("Ransomware monitor started as background task")
        else:
            logger.info("Ransomware monitor not loaded, initializing standalone")
            self._ransomware_task = asyncio.create_task(self._ransomware_bg_task())

        self._inventory_task = asyncio.create_task(self._periodic_inventory())

        logger.info("Agent started successfully")

        try:
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            pass

        await self.shutdown()

    async def shutdown(self):
        if not self._running:
            return

        logger.info("Shutting down agent...")
        self._running = False
        self._shutdown_event.set()

        for key, collector in self._collectors.items():
            if "LogCollector" in key and hasattr(collector, "stop_real_time"):
                collector.stop_real_time()
            if "RansomwareMonitor" in key and hasattr(collector, "stop_monitoring"):
                collector.stop_monitoring()

        if hasattr(self, "_ransomware_task") and not self._ransomware_task.done():
            self._ransomware_task.cancel()
            try:
                await self._ransomware_task
            except asyncio.CancelledError:
                pass

        if hasattr(self, "_inventory_task") and not self._inventory_task.done():
            self._inventory_task.cancel()
            try:
                await self._inventory_task
            except asyncio.CancelledError:
                pass

        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        for key, task in list(self._collector_tasks.items()):
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        if self._comm:
            await self._comm.shutdown()

        logger.info("Agent shut down complete")

    async def _send_system_profile(self):
        try:
            profile = {
                "type": "system_profile",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "agent_info": self._build_agent_info(),
                "ip_addresses": self._get_local_ip_addresses(),
            }
            await self._comm.send_data(profile)
            logger.info("System profile sent on registration")
        except Exception as e:
            logger.error(f"Failed to send system profile: {e}")

    async def _ransomware_bg_task(self):
        try:
            from agent.core.collectors.ransomware import RansomwareMonitor
            monitor = RansomwareMonitor(config={
                "ransomware": self._config.get("ransomware", {}),
            })
            monitor.start_monitoring()
            logger.info("Standalone ransomware monitor started")
            scan_interval = self._config.get("ransomware", {}).get("scan_interval_seconds", 30)
            while not self._shutdown_event.is_set():
                try:
                    result = await monitor.run()
                    alerts = result.get("data", {}).get("alerts", [])
                    if alerts:
                        await self._comm.send_data(result)
                        logger.debug(f"Ransomware scan sent: {len(alerts)} alerts")
                except Exception as e:
                    logger.error(f"Ransomware background task error: {e}")
                try:
                    await asyncio.wait_for(self._shutdown_event.wait(), timeout=scan_interval)
                    break
                except asyncio.TimeoutError:
                    pass
            monitor.stop_monitoring()
        except ImportError as e:
            logger.warning(f"Ransomware module not available: {e}")
        except Exception as e:
            logger.error(f"Ransomware background task failed: {e}")

    async def _periodic_inventory(self):
        inventory_interval = self._config.get("inventory_interval_seconds", 21600)
        logger.info(f"Periodic inventory scheduled every {inventory_interval}s")
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=inventory_interval)
                break
            except asyncio.TimeoutError:
                pass
            try:
                logger.info("Starting periodic full inventory collection")
                await self._run_full_inventory()
            except Exception as e:
                logger.error(f"Periodic inventory error: {e}")

    async def _restart(self):
        await self.shutdown()
        await asyncio.sleep(2)
        await self.start()


def _setup_signal_handlers(agent: AEGISXAgent, loop: asyncio.AbstractEventLoop):
    def handle_signal(sig, frame):
        sig_name = signal.Signals(sig).name
        logger.info(f"Received signal: {sig_name}")
        agent._shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, handle_signal)
        except Exception:
            pass

    if sys.platform == "win32":
        try:
            signal.signal(signal.SIGBREAK, handle_signal)
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="AEGISX Security Agent")
    parser.add_argument("--config", help="Path to config.yaml file")
    parser.add_argument("--server", help="AEGISX server URL (overrides config)")
    parser.add_argument("--key", help="Agent registration key (overrides config)")
    parser.add_argument("--tenant", help="Tenant ID (overrides config)")
    parser.add_argument("--version", action="version", version=f"AEGISX Agent v{__version__}")
    args = parser.parse_args()

    agent = AEGISXAgent(config_path=args.config)

    # Override config with CLI arguments
    if args.server:
        agent._config["server_url"] = args.server
    if args.key:
        agent._config["registration_key"] = args.key
    if args.tenant:
        agent._config["tenant_id"] = args.tenant

    logger.info(f"AEGISX Agent v{__version__} starting")
    logger.info(f"Server: {agent._config.get('server_url', 'not configured')}")
    logger.info(f"Tenant: {agent._config.get('tenant_id', 'not configured')}")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    _setup_signal_handlers(agent, loop)

    try:
        loop.run_until_complete(agent.start())
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
    finally:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()


if __name__ == "__main__":
    main()
