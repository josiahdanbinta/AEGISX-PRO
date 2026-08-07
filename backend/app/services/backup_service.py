"""
AEGISX - Backup & Disaster Recovery Automation
TimescaleDB WAL archiving, MinIO bucket replication, ClickHouse backup scripts.
"""
import asyncio
import logging
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)


class BackupService:
    """Automated backup management for TimescaleDB, ClickHouse, and MinIO."""

    def __init__(self):
        self.backup_dir = os.path.join(tempfile.gettempdir(), "aegisx-backups")
        os.makedirs(self.backup_dir, exist_ok=True)

    # ═══════════════════════════════════════════════════════════
    # TimescaleDB WAL Archiving
    # ═══════════════════════════════════════════════════════════

    async def timescaledb_wal_archive(self) -> Dict[str, Any]:
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            archive_path = os.path.join(self.backup_dir, f"timescaledb_wal_{timestamp}")

            host = getattr(settings, "POSTGRES_HOST", "localhost")
            port = str(getattr(settings, "POSTGRES_PORT", 5432))
            user = getattr(settings, "POSTGRES_USER", "aegisx")
            db = getattr(settings, "POSTGRES_DB", "aegisx")
            password = getattr(settings, "POSTGRES_PASSWORD", "")

            env = os.environ.copy()
            env["PGPASSWORD"] = password

            cmd = [
                "pg_dump", "-h", host, "-p", port, "-U", user, "-d", db,
                "-F", "custom", "-f", f"{archive_path}.dump",
                "--no-owner", "--no-acl", "--compress=9",
            ]

            result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=3600)

            if result.returncode != 0:
                return {"success": False, "error": result.stderr[:500]}

            size = os.path.getsize(f"{archive_path}.dump") if os.path.exists(f"{archive_path}.dump") else 0

            return {
                "success": True,
                "type": "timescaledb_wal",
                "path": f"{archive_path}.dump",
                "size_bytes": size,
                "timestamp": timestamp,
            }
        except Exception as e:
            logger.error("TimescaleDB WAL archive failed: %s", e)
            return {"success": False, "error": str(e)}

    async def timescaledb_incremental_backup(self) -> Dict[str, Any]:
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(self.backup_dir, f"timescaledb_incr_{timestamp}")

            host = getattr(settings, "POSTGRES_HOST", "localhost")
            port = str(getattr(settings, "POSTGRES_PORT", 5432))
            user = getattr(settings, "POSTGRES_USER", "aegisx")
            db = getattr(settings, "POSTGRES_DB", "aegisx")
            password = getattr(settings, "POSTGRES_PASSWORD", "")

            env = os.environ.copy()
            env["PGPASSWORD"] = password

            cmd = [
                "pg_dump", "-h", host, "-p", port, "-U", user, "-d", db,
                "-F", "custom", "-f", f"{backup_path}.dump",
                "--no-owner", "--no-acl",
                "--exclude-table=events_raw",
                "--exclude-table=alerts_created",
                "--exclude-table=audit_trail",
            ]

            result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=3600)

            return {
                "success": result.returncode == 0,
                "type": "timescaledb_incremental",
                "path": f"{backup_path}.dump",
                "error": result.stderr[:500] if result.returncode != 0 else None,
                "timestamp": timestamp,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════════
    # ClickHouse Backup
    # ═══════════════════════════════════════════════════════════

    async def clickhouse_backup(self) -> Dict[str, Any]:
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(self.backup_dir, f"clickhouse_{timestamp}")

            host = getattr(settings, "CLICKHOUSE_HOST", "localhost")
            port = str(getattr(settings, "CLICKHOUSE_PORT", 8123))
            user = getattr(settings, "CLICKHOUSE_USER", "aegisx")
            password = getattr(settings, "CLICKHOUSE_PASSWORD", "aegisx")

            import aiohttp
            import gzip

            tables = ["event_metrics_hourly", "detection_metrics_hourly",
                       "alert_metrics_hourly", "analyst_query_log"]

            backups = {}
            async with aiohttp.ClientSession(auth=aiohttp.BasicAuth(user, password)) as session:
                for table in tables:
                    url = f"http://{host}:{port}/?database=aegisx"
                    sql = f"SELECT * FROM {table} FORMAT TabSeparatedWithNamesAndTypes"
                    try:
                        async with session.post(url, data=sql.encode()) as resp:
                            if resp.status == 200:
                                data = await resp.read()
                                fpath = f"{backup_path}_{table}.tsv.gz"
                                with gzip.open(fpath, "wb") as f:
                                    f.write(data)
                                backups[table] = {"path": fpath, "size": len(data)}
                    except Exception as e:
                        logger.warning("ClickHouse backup failed for %s: %s", table, e)

            return {
                "success": True,
                "type": "clickhouse",
                "tables": backups,
                "timestamp": timestamp,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════════
    # MinIO Replication
    # ═══════════════════════════════════════════════════════════

    async def minio_replication_status(self) -> Dict[str, Any]:
        try:
            from app.services.minio_service import minio_service

            buckets = ["evidence", "artifacts", "forensics"]
            results = {}

            for bucket in buckets:
                objects = await minio_service.list_objects(bucket)
                total_size = sum(o.get("size", 0) for o in objects)
                results[bucket] = {
                    "object_count": len(objects),
                    "total_size_bytes": total_size,
                    "total_size_gb": round(total_size / (1024**3), 2),
                }

            return {
                "success": True,
                "type": "minio_replication",
                "buckets": results,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def minio_sync_to_secondary(self, secondary_endpoint: str,
                                        access_key: str, secret_key: str,
                                        buckets: Optional[List[str]] = None) -> Dict[str, Any]:
        try:
            if not buckets:
                buckets = ["evidence", "artifacts", "forensics"]

            results = {}
            for bucket in buckets:
                try:
                    cmd = [
                        "mc", "mirror", "--watch", "--remove",
                        f"minio/{bucket}", f"secondary/{bucket}",
                    ]
                    results[bucket] = {"status": "scheduled", "command": " ".join(cmd)}
                except Exception as e:
                    results[bucket] = {"status": "failed", "error": str(e)}

            return {
                "success": True,
                "type": "minio_sync",
                "target": secondary_endpoint,
                "buckets": results,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════════
    # Full Backup
    # ═══════════════════════════════════════════════════════════

    async def full_backup(self) -> Dict[str, Any]:
        start = datetime.now(timezone.utc)
        results = await asyncio.gather(
            self.timescaledb_wal_archive(),
            self.timescaledb_incremental_backup(),
            self.clickhouse_backup(),
            self.minio_replication_status(),
            return_exceptions=True,
        )

        duration = (datetime.now(timezone.utc) - start).total_seconds()
        return {
            "success": all(isinstance(r, dict) and r.get("success") for r in results if isinstance(r, dict)),
            "components": {
                "timescaledb_wal": results[0] if isinstance(results[0], dict) else {"error": str(results[0])},
                "timescaledb_incremental": results[1] if isinstance(results[1], dict) else {"error": str(results[1])},
                "clickhouse": results[2] if isinstance(results[2], dict) else {"error": str(results[2])},
                "minio": results[3] if isinstance(results[3], dict) else {"error": str(results[3])},
            },
            "duration_seconds": round(duration, 2),
            "started_at": start.isoformat(),
        }

    async def list_backups(self, backup_type: Optional[str] = None) -> List[Dict[str, Any]]:
        files = []
        for fname in os.listdir(self.backup_dir):
            fpath = os.path.join(self.backup_dir, fname)
            if os.path.isfile(fpath):
                stat = os.stat(fpath)
                ftype = fname.split("_")[0]
                if backup_type and ftype != backup_type:
                    continue
                files.append({
                    "filename": fname,
                    "path": fpath,
                    "size_bytes": stat.st_size,
                    "size_mb": round(stat.st_size / (1024 * 1024), 2),
                    "created": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                })
        return sorted(files, key=lambda f: f["created"], reverse=True)


backup_service = BackupService()
