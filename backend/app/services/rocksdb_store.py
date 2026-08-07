"""
AEGIS - RocksDB State Backend (Tier 3)
Durable local state store for the stream processor using RocksDB.
Stores checkpoints, window state, and baseline data for crash recovery.
"""
import json
import logging
import os
import struct
import tempfile
from typing import Any, Dict, Iterator, List, Optional, Tuple

from app.core.config import settings

logger = logging.getLogger(__name__)

STATE_DIR = os.path.join(tempfile.gettempdir(), "AEGIS-rocksdb-state")
os.makedirs(STATE_DIR, exist_ok=True)


class RocksDBStore:
    """
    RocksDB-backed key-value state store for durable stream processing state.
    Falls back to SQLite when rocksdb package is not available.
    Uses WAL (Write-Ahead Log) for crash recovery.
    """

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or os.path.join(STATE_DIR, "stream-state")
        self._db = None
        self._engine = None

    def _init_rocksdb(self):
        try:
            import rocksdb
            opts = rocksdb.Options()
            opts.create_if_missing = True
            opts.wal_recovery_mode = rocksdb.WALRecoveryMode.kAbsoluteConsistency
            opts.max_open_files = 300000
            opts.write_buffer_size = 64 * 1024 * 1024
            opts.max_write_buffer_number = 3
            opts.compression = rocksdb.CompressionType.lz4_compression
            opts.enable_pipelined_write = True
            opts.bytes_per_sync = 1 * 1024 * 1024

            db_path = os.path.join(self._db_path, "rocksdb")
            os.makedirs(db_path, exist_ok=True)
            self._db = rocksdb.DB(str(db_path), opts)
            self._engine = "rocksdb"
            logger.info("RocksDB state store initialized at %s", db_path)
        except ImportError:
            self._init_sqlite_fallback()

    def _init_sqlite_fallback(self):
        import sqlite3
        db_path = os.path.join(self._db_path, "state.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_state_updated ON state(updated_at)")
        self._db.commit()
        self._engine = "sqlite"
        logger.info("SQLite state store initialized at %s (RocksDB not available)", db_path)

    def _ensure_db(self):
        if self._db is None:
            self._init_rocksdb()

    # â”€â”€ Key-Value Operations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def put(self, key: str, value: Any) -> None:
        self._ensure_db()
        serialized = json.dumps(value)
        if self._engine == "rocksdb":
            self._db.put(key.encode(), serialized.encode())
        elif self._engine == "sqlite":
            self._db.execute(
                "INSERT OR REPLACE INTO state(key, value, updated_at) VALUES(?, ?, ?)",
                (key, serialized, __import__('time').time())
            )
            self._db.commit()

    def get(self, key: str) -> Optional[Any]:
        self._ensure_db()
        if self._engine == "rocksdb":
            val = self._db.get(key.encode())
            if val is None:
                return None
            return json.loads(val.decode())
        elif self._engine == "sqlite":
            cursor = self._db.execute("SELECT value FROM state WHERE key = ?", (key,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None

    def delete(self, key: str) -> None:
        self._ensure_db()
        if self._engine == "rocksdb":
            self._db.delete(key.encode())
        elif self._engine == "sqlite":
            self._db.execute("DELETE FROM state WHERE key = ?", (key,))
            self._db.commit()

    def scan(self, prefix: str) -> Iterator[Tuple[str, Any]]:
        self._ensure_db()
        if self._engine == "rocksdb":
            it = self._db.iterkeys()
            it.seek(prefix.encode())
            for key in it:
                key_str = key.decode()
                if not key_str.startswith(prefix):
                    break
                val = self._db.get(key)
                if val is not None:
                    yield key_str, json.loads(val.decode())
        elif self._engine == "sqlite":
            cursor = self._db.execute(
                "SELECT key, value FROM state WHERE key LIKE ?",
                (f"{prefix}%",)
            )
            for key, val in cursor.fetchall():
                yield key, json.loads(val)

    def put_batch(self, entries: Dict[str, Any]) -> None:
        self._ensure_db()
        if self._engine == "rocksdb":
            batch = self._db.write_batch()
            for key, value in entries.items():
                batch.put(key.encode(), json.dumps(value).encode())
            self._db.write(batch)
        elif self._engine == "sqlite":
            import time
            now = time.time()
            self._db.executemany(
                "INSERT OR REPLACE INTO state(key, value, updated_at) VALUES(?, ?, ?)",
                [(k, json.dumps(v), now) for k, v in entries.items()]
            )
            self._db.commit()

    # â”€â”€ Checkpoint & Recovery â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def checkpoint(self, checkpoint_id: str, state: Dict[str, Any]) -> None:
        key = f"checkpoint:{checkpoint_id}"
        self.put(key, state)

    def restore_checkpoint(self, checkpoint_id: str) -> Optional[Dict[str, Any]]:
        key = f"checkpoint:{checkpoint_id}"
        return self.get(key)

    def list_checkpoints(self) -> List[str]:
        prefixes = set()
        for key, _ in self.scan("checkpoint:"):
            cid = key.split(":", 1)[1]
            prefixes.add(cid)
        return sorted(prefixes)

    # â”€â”€ Window State â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def put_window(self, window_id: str, tenant_key: str, events: List[Dict]) -> None:
        key = f"window:{window_id}:{tenant_key}"
        self.put(key, events)

    def get_window(self, window_id: str, tenant_key: str) -> List[Dict]:
        key = f"window:{window_id}:{tenant_key}"
        result = self.get(key)
        return result if isinstance(result, list) else []

    def expire_windows(self, max_age_seconds: float) -> int:
        import time
        cutoff = time.time() - max_age_seconds
        expired = 0
        if self._engine == "sqlite":
            cursor = self._db.execute(
                "DELETE FROM state WHERE key LIKE 'window:%' AND updated_at < ?",
                (cutoff,)
            )
            expired = cursor.rowcount
            self._db.commit()
        return expired

    # â”€â”€ Baseline Storage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def put_baseline(self, entity_id: str, entity_type: str, profile: Dict[str, Any]) -> None:
        key = f"ueba:baseline:{entity_type}:{entity_id}"
        self.put(key, profile)

    def get_baseline(self, entity_id: str, entity_type: str) -> Optional[Dict[str, Any]]:
        key = f"ueba:baseline:{entity_type}:{entity_id}"
        return self.get(key)

    def list_baselines(self, entity_type: str) -> List[str]:
        entity_ids = set()
        prefix = f"ueba:baseline:{entity_type}:"
        for key, _ in self.scan(prefix):
            entity_ids.add(key.split(":", 3)[3])
        return sorted(entity_ids)

    def get_engine(self) -> str:
        return self._engine

    def compact(self):
        if self._engine == "rocksdb":
            self._db.compact_range()

    def close(self):
        if self._db and self._engine == "rocksdb":
            del self._db
        elif self._db and self._engine == "sqlite":
            self._db.close()
        self._db = None


state_store = RocksDBStore()
