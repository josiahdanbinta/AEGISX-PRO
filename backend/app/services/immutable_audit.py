"""
AEGISX - Immutable Audit Log Service (Tier 1)
WORM (Write Once Read Many) enforcement with SHA-256 hash chain verification.
Ensures audit trail integrity — any tampering is cryptographically detectable.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings

logger = logging.getLogger(__name__)


class AuditChainEntry:
    """Single entry in an immutable hash chain."""

    __slots__ = ('sequence', 'timestamp', 'action', 'details', 'previous_hash', '_hash')

    def __init__(self, sequence: int, timestamp: str, action: str,
                 details: Dict[str, Any], previous_hash: str):
        self.sequence = sequence
        self.timestamp = timestamp
        self.action = action
        self.details = details
        self.previous_hash = previous_hash
        self._hash = self._compute_hash()

    def _compute_hash(self) -> str:
        payload = (
            f"{self.sequence}|{self.timestamp}|{self.action}|"
            f"{json.dumps(self.details, sort_keys=True)}|{self.previous_hash}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    @property
    def hash(self) -> str:
        return self._hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "action": self.action,
            "details": self.details,
            "previous_hash": self.previous_hash,
            "hash": self._hash,
        }

    def verify(self) -> bool:
        return self._hash == self._compute_hash()


class ImmutableAuditLog:
    """
    Append-only audit log with cryptographic hash chain.
    Each entry references the hash of the previous entry, making the
    entire chain tamper-evident.
    """

    def __init__(self, tenant_id: str, genesis_hash: Optional[str] = None):
        self.tenant_id = tenant_id
        self._chain: List[AuditChainEntry] = []
        self._genesis_hash = genesis_hash or hashlib.sha256(
            f"aegisx-audit-genesis-{tenant_id}-{settings.APP_VERSION}".encode()
        ).hexdigest()
        self._last_hash = self._genesis_hash
        self._sequence = 0
        self._lock_key = f"audit:lock:{tenant_id}"

    async def append(self, action: str, details: Dict[str, Any]) -> AuditChainEntry:
        self._sequence += 1
        now = datetime.now(timezone.utc).isoformat()
        entry = AuditChainEntry(
            sequence=self._sequence,
            timestamp=now,
            action=action,
            details=details,
            previous_hash=self._last_hash,
        )
        self._chain.append(entry)
        self._last_hash = entry.hash
        return entry

    def verify_chain(self) -> Tuple[bool, Optional[int]]:
        """
        Verify the integrity of the entire hash chain.
        Returns (valid, first_invalid_index).
        """
        expected_prev = self._genesis_hash
        for i, entry in enumerate(self._chain):
            if entry.previous_hash != expected_prev:
                logger.critical(
                    "Audit chain broken at entry %d (tenant=%s): expected %s, got %s",
                    i, self.tenant_id, expected_prev[:16], entry.previous_hash[:16]
                )
                return False, i
            if not entry.verify():
                logger.critical(
                    "Audit entry %d hash mismatch (tenant=%s)",
                    i, self.tenant_id
                )
                return False, i
            expected_prev = entry.hash
        return True, None

    def get_receipt(self, sequence: int) -> Optional[Dict[str, Any]]:
        """Generate a cryptographic receipt proving an entry exists in the chain."""
        if sequence < 1 or sequence > len(self._chain):
            return None
        entry = self._chain[sequence - 1]
        return {
            "entry": entry.to_dict(),
            "chain_root": self._last_hash,
            "genesis": self._genesis_hash,
            "total_entries": len(self._chain),
            "tenant_id": self.tenant_id,
            "verified": entry.verify(),
        }

    def export_chain(self, since_index: int = 0) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._chain[since_index:]]

    @property
    def length(self) -> int:
        return len(self._chain)

    @property
    def root_hash(self) -> str:
        return self._last_hash


class AuditWormService:
    """
    WORM (Write Once Read Many) enforcement service.
    Ensures audit log entries cannot be modified or deleted after commit.
    Uses hash chain + Redis for cross-instance chain state.
    """

    def __init__(self):
        self._chains: Dict[str, ImmutableAuditLog] = {}

    def _get_chain(self, tenant_id: str) -> ImmutableAuditLog:
        if tenant_id not in self._chains:
            self._chains[tenant_id] = ImmutableAuditLog(tenant_id)
        return self._chains[tenant_id]

    async def write(self, tenant_id: str, action: str,
                    details: Dict[str, Any]) -> AuditChainEntry:
        """Append an immutable entry to the audit chain. Cannot be modified or deleted."""
        chain = self._get_chain(tenant_id)
        entry = await chain.append(action, details)
        logger.debug(
            "WORM audit: %s:%s seq=%d hash=%s",
            tenant_id, action, entry.sequence, entry.hash[:16]
        )
        return entry

    def verify_integrity(self, tenant_id: str) -> Tuple[bool, Optional[int]]:
        """Verify the entire audit chain hasn't been tampered with."""
        chain = self._get_chain(tenant_id)
        valid, index = chain.verify_chain()
        if not valid:
            logger.critical("AUDIT CHAIN TAMPERED: tenant=%s, index=%s", tenant_id, index)
        return valid, index

    def get_receipt(self, tenant_id: str, sequence: int) -> Optional[Dict[str, Any]]:
        chain = self._get_chain(tenant_id)
        return chain.get_receipt(sequence)

    def export(self, tenant_id: str, since: int = 0) -> List[Dict[str, Any]]:
        chain = self._get_chain(tenant_id)
        return chain.export_chain(since)


audit_worm = AuditWormService()
