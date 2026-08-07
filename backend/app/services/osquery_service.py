"""
AEGIS - Osquery Service (Tier 6)
Query builder, template management, and scheduling for osquery-based
endpoint interrogation across the fleet.
"""
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, and_, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session_factory
from app.models import Agent

logger = logging.getLogger(__name__)

OSQUERY_TEMPLATES = {
    "list_processes": {
        "name": "List All Processes",
        "query": "SELECT pid, name, path, cmdline, parent FROM processes;",
        "category": "processes",
        "description": "Enumerate all running processes with command lines",
        "interval": 3600,
        "tags": ["process", "investigation"],
        "platform": "all",
    },
    "list_users": {
        "name": "List Local Users",
        "query": "SELECT uid, username, description, directory, shell FROM users;",
        "category": "users",
        "description": "List all local user accounts",
        "interval": 86400,
        "tags": ["user", "account"],
        "platform": "all",
    },
    "list_startup_items": {
        "name": "Startup Items",
        "query": "SELECT name, path, args, source, status FROM startup_items;",
        "category": "persistence",
        "description": "Check all auto-start programs and services",
        "interval": 3600,
        "tags": ["persistence", "autostart"],
        "platform": "all",
    },
    "list_listening_ports": {
        "name": "Listening Network Ports",
        "query": "SELECT pid, port, address, protocol, family FROM listening_ports;",
        "category": "network",
        "description": "Discover all listening network ports",
        "interval": 1800,
        "tags": ["network", "ports", "c2"],
        "platform": "all",
    },
    "list_kernel_modules": {
        "name": "Kernel Modules (Linux)",
        "query": "SELECT name, size, used_by, status FROM kernel_modules;",
        "category": "kernel",
        "description": "List loaded kernel modules (rootkits check)",
        "interval": 3600,
        "tags": ["kernel", "rootkit"],
        "platform": "linux",
    },
    "list_kernel_extensions": {
        "name": "Kernel Extensions (macOS)",
        "query": "SELECT name, idx, refs, linked_against FROM kernel_extensions;",
        "category": "kernel",
        "description": "List loaded kernel extensions",
        "interval": 3600,
        "tags": ["kernel", "kext"],
        "platform": "darwin",
    },
    "list_windows_drivers": {
        "name": "Windows Drivers",
        "query": "SELECT device_id, description, service, service_type, image_path FROM drivers WHERE service_type = 'kernel';",
        "category": "kernel",
        "description": "List kernel-mode drivers on Windows",
        "interval": 3600,
        "tags": ["kernel", "driver", "rootkit"],
        "platform": "windows",
    },
    "list_scheduled_tasks": {
        "name": "Scheduled Tasks",
        "query": "SELECT name, action, path, enabled, state, last_run_time FROM scheduled_tasks;",
        "category": "persistence",
        "description": "Enumerate scheduled tasks (Windows) and cron jobs",
        "interval": 3600,
        "tags": ["persistence", "scheduled_task"],
        "platform": "all",
    },
    "list_crontab": {
        "name": "Cron Jobs (Linux/macOS)",
        "query": "SELECT command, path, hour, minute, month, day_of_week FROM crontab;",
        "category": "persistence",
        "description": "List all cron jobs",
        "interval": 3600,
        "tags": ["persistence", "cron"],
        "platform": "linux,darwin",
    },
    "list_launchd": {
        "name": "Launchd (macOS)",
        "query": "SELECT name, path, program, run_at_load, keep_alive FROM launchd;",
        "category": "persistence",
        "description": "List launchd agents and daemons on macOS",
        "interval": 3600,
        "tags": ["persistence", "launchd"],
        "platform": "darwin",
    },
    "list_windows_services": {
        "name": "Windows Services",
        "query": "SELECT name, display_name, status, start_type, path, user_account FROM services WHERE start_type != 'disabled';",
        "category": "services",
        "description": "Enumerate running Windows services",
        "interval": 3600,
        "tags": ["service", "windows"],
        "platform": "windows",
    },
    "list_suspicious_files": {
        "name": "Suspicious Temporary Files",
        "query": "SELECT path, filename, size, mtime, uid FROM file WHERE path LIKE '/tmp/%' AND size > 0;",
        "category": "files",
        "description": "Check for suspicious files in temp directories",
        "interval": 1800,
        "tags": ["files", "temp", "malware"],
        "platform": "linux,darwin",
    },
    "list_windows_temp_files": {
        "name": "Windows Temp Files",
        "query": "SELECT path, filename, size, mtime FROM file WHERE directory LIKE 'C:\\Windows\\Temp\\%' AND filename LIKE '%.exe';",
        "category": "files",
        "description": "Check for executables in Windows temp",
        "interval": 1800,
        "tags": ["files", "temp", "malware"],
        "platform": "windows",
    },
    "list_authorized_keys": {
        "name": "SSH Authorized Keys",
        "query": "SELECT uid, username, key, key_file, path FROM authorized_keys;",
        "category": "ssh",
        "description": "List all SSH authorized keys",
        "interval": 86400,
        "tags": ["ssh", "authorized_keys", "persistence"],
        "platform": "linux,darwin",
    },
    "list_arptable": {
        "name": "ARP Table",
        "query": "SELECT address, mac, interface FROM arp_cache;",
        "category": "network",
        "description": "View the ARP cache for lateral movement detection",
        "interval": 900,
        "tags": ["network", "arp", "lateral_movement"],
        "platform": "all",
    },
    "list_dns_resolvers": {
        "name": "DNS Resolvers",
        "query": "SELECT id, type, address, netmask FROM dns_resolvers;",
        "category": "network",
        "description": "Check DNS server configuration for tampering",
        "interval": 3600,
        "tags": ["dns", "network", "tampering"],
        "platform": "all",
    },
    "list_installed_apps": {
        "name": "Installed Applications (macOS)",
        "query": "SELECT name, bundle_name, bundle_version, path FROM apps;",
        "category": "software",
        "description": "List installed macOS applications",
        "interval": 86400,
        "tags": ["software", "inventory"],
        "platform": "darwin",
    },
    "list_windows_programs": {
        "name": "Installed Programs (Windows)",
        "query": "SELECT name, version, publisher, install_location, uninstall_string FROM programs;",
        "category": "software",
        "description": "List installed Windows programs",
        "interval": 86400,
        "tags": ["software", "inventory"],
        "platform": "windows",
    },
    "list_debian_packages": {
        "name": "Installed Packages (Debian)",
        "query": "SELECT name, version, source, arch FROM deb_packages;",
        "category": "software",
        "description": "List installed Debian packages",
        "interval": 86400,
        "tags": ["software", "inventory","packages"],
        "platform": "linux",
    },
    "list_rpm_packages": {
        "name": "Installed Packages (RPM)",
        "query": "SELECT name, version, release, source, arch FROM rpm_packages;",
        "category": "software",
        "description": "List installed RPM packages",
        "interval": 86400,
        "tags": ["software", "inventory", "packages"],
        "platform": "linux",
    },
    "check_filevault": {
        "name": "FileVault Status (macOS)",
        "query": "SELECT * FROM disk_encryption WHERE name = 'FileVault';",
        "category": "encryption",
        "description": "Check FileVault encryption status",
        "interval": 86400,
        "tags": ["encryption", "filevault"],
        "platform": "darwin",
    },
    "check_bitlocker": {
        "name": "BitLocker Status (Windows)",
        "query": "SELECT device_id, drive_letter, encryption_method, protection_status FROM bitlocker_info;",
        "category": "encryption",
        "description": "Check BitLocker encryption status",
        "interval": 86400,
        "tags": ["encryption", "bitlocker"],
        "platform": "windows",
    },
    "list_browser_extensions_chrome": {
        "name": "Chrome Extensions",
        "query": "SELECT name, identifier, version, path, browser_type FROM browser_extensions WHERE browser_type = 'chrome';",
        "category": "browser",
        "description": "Check Chrome extensions for malicious addons",
        "interval": 86400,
        "tags": ["browser", "extensions", "chrome"],
        "platform": "all",
    },
    "list_browser_extensions_firefox": {
        "name": "Firefox Addons",
        "query": "SELECT name, identifier, active, path, browser_type FROM browser_extensions WHERE browser_type = 'firefox';",
        "category": "browser",
        "description": "Check Firefox extensions",
        "interval": 86400,
        "tags": ["browser", "extensions", "firefox"],
        "platform": "all",
    },
    "list_environment_variables": {
        "name": "Environment Variables",
        "query": "SELECT key, value FROM environment;",
        "category": "system",
        "description": "Check env vars for suspicious paths or keys",
        "interval": 3600,
        "tags": ["env", "system"],
        "platform": "all",
    },
    "list_mounts": {
        "name": "Mounted Filesystems",
        "query": "SELECT device, path, type, inodes_free, blocks_free FROM mounts;",
        "category": "system",
        "description": "Show mounted filesystems",
        "interval": 3600,
        "tags": ["mounts", "disks"],
        "platform": "all",
    },
}


class OsqueryTemplateService:
    """Manage osquery templates and schedule queries across agents."""

    def __init__(self):
        self._custom_templates: Dict[str, Dict[str, Any]] = {}

    def get_all_templates(self) -> List[Dict[str, Any]]:
        return [
            {"id": key, **value}
            for key, value in {**OSQUERY_TEMPLATES, **self._custom_templates}.items()
        ]

    def get_template(self, template_id: str) -> Optional[Dict[str, Any]]:
        tmpl = OSQUERY_TEMPLATES.get(template_id) or self._custom_templates.get(template_id)
        if tmpl:
            return {"id": template_id, **tmpl}
        return None

    def create_template(self, template: Dict[str, Any]) -> Dict[str, Any]:
        tid = template.get("id") or str(uuid.uuid4())[:8]
        self._custom_templates[tid] = {
            "name": template["name"],
            "query": template["query"],
            "category": template.get("category", "custom"),
            "description": template.get("description", ""),
            "interval": template.get("interval", 3600),
            "tags": template.get("tags", []),
            "platform": template.get("platform", "all"),
        }
        return {"id": tid, **self._custom_templates[tid]}

    def delete_template(self, template_id: str) -> bool:
        if template_id in self._custom_templates:
            del self._custom_templates[template_id]
            return True
        return False

    async def schedule_query(self, agent_id: str, query: str, template_id: str,
                               interval_seconds: int = 3600) -> Dict[str, Any]:
        async with async_session_factory() as db:
            result = await db.execute(select(Agent).where(Agent.id == agent_id))
            agent = result.scalar_one_or_none()

            if not agent:
                return {"success": False, "error": "Agent not found"}

            schedule_entry = {
                "template_id": template_id,
                "query": query,
                "interval_seconds": interval_seconds,
                "scheduled_at": datetime.now(timezone.utc).isoformat(),
                "next_run_at": (datetime.now(timezone.utc).timestamp() + interval_seconds),
            }

            config = agent.config or {}
            osq_schedules = config.get("osquery_schedules", [])
            osq_schedules = [s for s in osq_schedules if s.get("template_id") != template_id]
            osq_schedules.append(schedule_entry)
            config["osquery_schedules"] = osq_schedules
            agent.config = config

            await db.commit()

            return {
                "success": True,
                "agent_id": str(agent.id),
                "template_id": template_id,
                "interval_seconds": interval_seconds,
                "schedule": schedule_entry,
            }

    async def un_schedule_query(self, agent_id: str, template_id: str) -> Dict[str, Any]:
        async with async_session_factory() as db:
            result = await db.execute(select(Agent).where(Agent.id == agent_id))
            agent = result.scalar_one_or_none()

            if not agent:
                return {"success": False, "error": "Agent not found"}

            config = agent.config or {}
            osq_schedules = config.get("osquery_schedules", [])
            config["osquery_schedules"] = [
                s for s in osq_schedules if s.get("template_id") != template_id
            ]
            agent.config = config
            await db.commit()

            return {"success": True, "agent_id": str(agent.id), "template_id": template_id}

    async def get_agent_schedules(self, agent_id: str) -> List[Dict[str, Any]]:
        async with async_session_factory() as db:
            result = await db.execute(select(Agent).where(Agent.id == agent_id))
            agent = result.scalar_one_or_none()
            if not agent:
                return []
            config = agent.config or {}
            return config.get("osquery_schedules", [])

    def validate_query(self, sql: str) -> Dict[str, Any]:
        if not sql or not sql.strip():
            return {"valid": False, "error": "Query cannot be empty"}

        sql_upper = sql.upper().strip()
        if not sql_upper.startswith("SELECT"):
            return {"valid": False, "error": "Only SELECT queries are supported"}

        dangerous = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE",
                      "TRUNCATE", "ATTACH", "DETACH", "PRAGMA", "REINDEX"]
        for kw in dangerous:
            if kw in sql_upper:
                return {"valid": False, "error": f"Dangerous keyword detected: {kw}"}

        return {"valid": True, "query": sql.strip()}


osquery_service = OsqueryTemplateService()
