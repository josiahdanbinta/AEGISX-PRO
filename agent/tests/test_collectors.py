"""
Unit tests for AEGIS agent collectors.
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestSystemCollector:
    def test_import_collector(self):
        from agent.core.collectors.system import SystemCollector
        assert SystemCollector is not None

    def test_collector_has_name(self):
        from agent.core.collectors.system import SystemCollector
        c = SystemCollector()
        assert hasattr(c, 'name')
        assert c.name == 'SystemCollector'

    def test_collector_is_enabled_by_default(self):
        from agent.core.collectors.system import SystemCollector
        c = SystemCollector()
        assert c.enabled is True

    def test_collector_has_interval(self):
        from agent.core.collectors.system import SystemCollector
        c = SystemCollector()
        assert hasattr(c, 'interval')
        assert c.interval == 30

    def test_collect_returns_dict(self):
        import asyncio
        from agent.core.collectors.system import SystemCollector
        c = SystemCollector()
        result = asyncio.new_event_loop().run_until_complete(c.run())
        assert isinstance(result, dict)
        assert 'collector' in result
        assert 'status' in result
        assert result['status'] in ('success', 'error')
        if result['status'] == 'success':
            assert 'data' in result
            assert 'cpu' in result['data']
            assert 'memory' in result['data']
            assert 'disk' in result['data']
            assert 'network' in result['data']


class TestHardwareCollector:
    def test_import(self):
        from agent.core.collectors.hardware import HardwareCollector
        assert HardwareCollector is not None

    def test_collector_has_name(self):
        from agent.core.collectors.hardware import HardwareCollector
        c = HardwareCollector()
        assert c.name == 'HardwareCollector'

    def test_collect_returns_dict(self):
        import asyncio
        from agent.core.collectors.hardware import HardwareCollector
        c = HardwareCollector()
        result = asyncio.new_event_loop().run_until_complete(c.run())
        assert isinstance(result, dict)
        assert 'collector' in result
        if result['status'] == 'success':
            assert 'motherboard' in result['data']


class TestProcessesCollector:
    def test_import(self):
        from agent.core.collectors.processes import ProcessCollector
        assert ProcessCollector is not None

    def test_collector_has_name(self):
        from agent.core.collectors.processes import ProcessCollector
        c = ProcessCollector()
        assert c.name == 'ProcessCollector'

    def test_collect_returns_dict(self):
        import asyncio
        from agent.core.collectors.processes import ProcessCollector
        c = ProcessCollector()
        result = asyncio.new_event_loop().run_until_complete(c.run())
        assert isinstance(result, dict)
        assert 'collector' in result
        if result['status'] == 'success':
            assert 'processes' in result['data']


class TestServicesCollector:
    def test_import(self):
        from agent.core.collectors.services import ServicesCollector
        assert ServicesCollector is not None

    def test_collector_has_name(self):
        from agent.core.collectors.services import ServicesCollector
        c = ServicesCollector()
        assert c.name == 'ServicesCollector'


class TestSoftwareCollector:
    def test_import(self):
        from agent.core.collectors.software import SoftwareCollector
        assert SoftwareCollector is not None

    def test_collector_has_name(self):
        from agent.core.collectors.software import SoftwareCollector
        c = SoftwareCollector()
        assert c.name == 'SoftwareCollector'

    def test_version_behind_true(self):
        from agent.core.collectors.software import SoftwareCollector
        assert SoftwareCollector._version_behind('1.0.0', '2.0.0') is True

    def test_version_behind_false(self):
        from agent.core.collectors.software import SoftwareCollector
        assert SoftwareCollector._version_behind('3.0.0', '2.0.0') is False

    def test_version_behind_equal(self):
        from agent.core.collectors.software import SoftwareCollector
        assert SoftwareCollector._version_behind('2.0.0', '2.0.0') is False


class TestLogsCollector:
    def test_import(self):
        from agent.core.collectors.logs import LogCollector
        assert LogCollector is not None

    def test_collector_has_name(self):
        from agent.core.collectors.logs import LogCollector
        c = LogCollector()
        assert c.name == 'LogCollector'


class TestRansomwareCollector:
    def test_import(self):
        from agent.core.collectors.ransomware import RansomwareMonitor
        assert RansomwareMonitor is not None

    def test_collector_has_name(self):
        from agent.core.collectors.ransomware import RansomwareMonitor
        c = RansomwareMonitor()
        assert c.name == 'RansomwareMonitor'

    def test_ransomware_extensions_list(self):
        from agent.core.collectors.ransomware import _RANSOMWARE_EXTENSIONS
        assert isinstance(_RANSOMWARE_EXTENSIONS, set)
        assert '.encrypted' in _RANSOMWARE_EXTENSIONS

    def test_ransomware_has_note_names(self):
        from agent.core.collectors.ransomware import _RANSOM_NOTE_NAMES
        assert isinstance(_RANSOM_NOTE_NAMES, list)
        assert len(_RANSOM_NOTE_NAMES) > 0

    def test_monitor_starts_stops(self):
        from agent.core.collectors.ransomware import RansomwareMonitor
        c = RansomwareMonitor()
        c.start_monitoring()
        assert c._monitor_active is True
        c.stop_monitoring()
        assert c._monitor_active is False

    def test_collect_returns_dict(self):
        import asyncio
        from agent.core.collectors.ransomware import RansomwareMonitor
        c = RansomwareMonitor()
        result = asyncio.new_event_loop().run_until_complete(c.run())
        assert isinstance(result, dict)
        assert 'collector' in result
        if result['status'] == 'success':
            assert 'alerts' in result['data']
            assert 'ransomware_indicators' in result['data']


class TestPlatformDetection:
    def test_platform_imports(self):
        from agent.platforms import get_platform, is_windows, is_linux, is_macos, get_os_info
        assert callable(get_platform)
        assert callable(is_windows)
        assert callable(is_linux)
        assert callable(is_macos)
        assert callable(get_os_info)

    def test_get_platform_returns_string(self):
        from agent.platforms import get_platform
        plat = get_platform()
        assert plat in ('windows', 'linux', 'macos')

    def test_get_os_info_returns_dict(self):
        from agent.platforms import get_os_info
        info = get_os_info()
        assert isinstance(info, dict)
        assert 'name' in info
        assert 'architecture' in info


class TestCommunication:
    def test_communication_import(self):
        from agent.core.communication import CommunicationModule
        assert CommunicationModule is not None

    def test_communication_init(self):
        from agent.core.communication import CommunicationModule
        config = {
            'server_url': 'http://localhost:8000',
            'registration_key': 'test-key',
            'tenant_id': 'test-tenant',
        }
        c = CommunicationModule(config)
        assert c.is_registered is False

    def test_communication_agent_id(self):
        from agent.core.communication import CommunicationModule
        config = {
            'server_url': 'http://localhost:8000',
            'registration_key': 'test-key',
            'tenant_id': 'test-tenant',
        }
        c = CommunicationModule(config, agent_id='agent-001')
        assert c.agent_id == 'agent-001'


class TestAgentEntry:
    def test_agent_import(self):
        import agent
        assert agent is not None

    def test_agent_class_import(self):
        from agent.agent import AEGISAgent
        assert AEGISAgent is not None

    def test_agent_version(self):
        from agent.agent import __version__
        assert isinstance(__version__, str)
        assert len(__version__) > 0


class StubCollector:
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

    def get_system_info(self):
        from agent.core.collector import BaseCollector
        return BaseCollector.get_system_info(self)

    def _run_command(self, cmd, timeout=10):
        from agent.core.collector import BaseCollector
        return BaseCollector._run_command(self, cmd, timeout)

    async def collect(self):
        return {}


class TestBaseCollector:
    def test_base_collector_import(self):
        from agent.core.collector import BaseCollector
        assert BaseCollector is not None

    def test_run_command_returns_dict(self):
        c = StubCollector()
        result = c._run_command(['echo', 'hello'])
        assert isinstance(result, dict)
        assert 'returncode' in result
        assert 'stdout' in result

    def test_get_system_info(self):
        c = StubCollector()
        info = c.get_system_info()
        assert isinstance(info, dict)
        assert 'hostname' in info
        assert 'platform' in info
        assert 'architecture' in info


class TestConfigLoading:
    def test_config_exists(self):
        config_path = Path(__file__).parent.parent / "config.yaml"
        assert config_path.exists(), f"Config file not found at {config_path}"
