"""
Pytest configuration and shared fixtures for AEGIS tests.
"""
import pytest
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def test_tenant_id():
    return "00000000-0000-0000-0000-000000000001"


@pytest.fixture
def test_user_id():
    return "00000000-0000-0000-0000-000000000002"


@pytest.fixture
def test_asset_id():
    return "00000000-0000-0000-0000-000000000003"


@pytest.fixture
def test_incident_id():
    return "00000000-0000-0000-0000-000000000004"


@pytest.fixture
def super_admin_roles():
    return ["super_admin"]


@pytest.fixture
def soc_analyst_roles():
    return ["soc_analyst_l1"]


@pytest.fixture
def tenant_admin_roles():
    return ["tenant_admin"]
