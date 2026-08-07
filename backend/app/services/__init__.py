"""
AEGIS - Business Services Layer
Audit, Tenant, Notification, Email, Search services with ORM integration.
"""
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, func, delete as sql_delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import (
    AuditLog,
    Tenant,
    User,
    Asset,
    Incident,
    NotificationChannel,
    NotificationHistory,
    NotificationPreference,
    RefreshToken,
)


class AuditService:
    @staticmethod
    async def log(
        db: AsyncSession,
        action: str,
        resource_type: str,
        tenant_id: str,
        user_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        status: str = "success",
        severity: str = "info",
    ) -> AuditLog:
        log_entry = AuditLog(
            id=uuid.uuid4(),
            tenant_id=uuid.UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id,
            user_id=uuid.UUID(user_id) if isinstance(user_id, str) and user_id else user_id,
            action=action,
            resource_type=resource_type,
            resource_id=uuid.UUID(resource_id) if isinstance(resource_id, str) and resource_id else resource_id,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            severity=severity,
            created_at=datetime.now(timezone.utc),
        )
        db.add(log_entry)
        await db.flush()
        return log_entry

    @staticmethod
    async def get_user_activity(
        db: AsyncSession, user_id: str, tenant_id: str, limit: int = 50
    ) -> List[AuditLog]:
        stmt = (
            select(AuditLog)
            .where(AuditLog.user_id == uuid.UUID(user_id), AuditLog.tenant_id == uuid.UUID(tenant_id))
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def get_resource_audit_trail(
        db: AsyncSession, resource_type: str, resource_id: str, tenant_id: str
    ) -> List[AuditLog]:
        stmt = (
            select(AuditLog)
            .where(
                AuditLog.resource_type == resource_type,
                AuditLog.resource_id == uuid.UUID(resource_id),
                AuditLog.tenant_id == uuid.UUID(tenant_id),
            )
            .order_by(AuditLog.created_at.desc())
        )
        result = await db.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def purge_old_logs(db: AsyncSession, before_date: datetime, tenant_id: Optional[str] = None) -> int:
        conditions = [AuditLog.created_at < before_date]
        if tenant_id:
            conditions.append(AuditLog.tenant_id == uuid.UUID(tenant_id))
        result = await db.execute(sql_delete(AuditLog).where(*conditions))
        await db.flush()
        return result.rowcount


class TenantService:
    @staticmethod
    async def get_tenant(db: AsyncSession, tenant_id: str) -> Optional[Tenant]:
        stmt = select(Tenant).where(Tenant.id == uuid.UUID(tenant_id))
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def check_quota(db: AsyncSession, tenant_id: str, resource: str, current: int) -> bool:
        tenant = await TenantService.get_tenant(db, tenant_id)
        if not tenant:
            return False
        limits = {
            "assets": tenant.quota_assets,
            "users": tenant.quota_users,
            "storage": tenant.quota_storage_gb,
        }
        limit = limits.get(resource, 1000)
        return current < limit

    @staticmethod
    async def get_usage(db: AsyncSession, tenant_id: str) -> Dict[str, Any]:
        tid = uuid.UUID(tenant_id)
        asset_count = await db.scalar(select(func.count()).select_from(Asset).where(Asset.tenant_id == tid, Asset.is_deleted == False)) or 0
        user_count = await db.scalar(select(func.count()).select_from(User).where(User.tenant_id == tid, User.is_deleted == False)) or 0
        incident_count = await db.scalar(select(func.count()).select_from(Incident).where(Incident.tenant_id == tid, Incident.status.notin_(['closed', 'resolved']))) or 0
        return {
            "assets": asset_count,
            "users": user_count,
            "storage_gb": 0,
            "incidents_open": incident_count,
            "alerts_today": 0,
        }

    @staticmethod
    async def suspend_tenant(db: AsyncSession, tenant_id: str) -> None:
        tenant = await TenantService.get_tenant(db, tenant_id)
        if tenant:
            tenant.status = "suspended"
            await db.flush()

    @staticmethod
    async def activate_tenant(db: AsyncSession, tenant_id: str) -> None:
        tenant = await TenantService.get_tenant(db, tenant_id)
        if tenant:
            tenant.status = "active"
            await db.flush()


class NotificationService:
    @staticmethod
    async def get_user_preferences(db: AsyncSession, user_id: str) -> Optional[NotificationPreference]:
        stmt = select(NotificationPreference).where(NotificationPreference.user_id == uuid.UUID(user_id))
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def send(
        db: AsyncSession,
        channel_type: str,
        recipient: str,
        subject: str,
        body: str,
        tenant_id: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> NotificationHistory:
        history = NotificationHistory(
            id=uuid.uuid4(),
            tenant_id=uuid.UUID(tenant_id),
            channel_type=channel_type,
            recipient=recipient,
            subject=subject,
            content=body,
            status="sent",
            created_at=datetime.now(timezone.utc),
        )
        db.add(history)
        await db.flush()
        return history

    @staticmethod
    async def get_active_channels(
        db: AsyncSession, tenant_id: str, channel_type: Optional[str] = None
    ) -> List[NotificationChannel]:
        conditions = [
            NotificationChannel.tenant_id == uuid.UUID(tenant_id),
            NotificationChannel.is_active == True,
        ]
        if channel_type:
            conditions.append(NotificationChannel.channel_type == channel_type)
        stmt = select(NotificationChannel).where(*conditions)
        result = await db.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def notify_users(
        db: AsyncSession,
        tenant_id: str,
        user_ids: List[str],
        subject: str,
        body: str,
        channel_type: str = "email",
    ) -> List[NotificationHistory]:
        results = []
        for uid in user_ids:
            stmt = select(User).where(User.id == uuid.UUID(uid), User.tenant_id == uuid.UUID(tenant_id))
            user_result = await db.execute(stmt)
            user = user_result.scalar_one_or_none()
            if user:
                history = await NotificationService.send(
                    db, channel_type, user.email, subject, body, tenant_id
                )
                results.append(history)
        return results


class EmailService:
    CHANNELS = NotificationService.CHANNELS if hasattr(NotificationService, 'CHANNELS') else ["email", "sms", "slack", "teams", "discord", "telegram", "webhook"]

    @staticmethod
    async def send_email(
        to: str,
        subject: str,
        body: str,
        html_body: Optional[str] = None,
        attachments: Optional[list] = None,
    ) -> bool:
        import aiosmtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart("alternative") if html_body else MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM
        msg["To"] = to

        if html_body:
            msg.attach(MIMEText(body, "plain", "utf-8"))
            msg.attach(MIMEText(html_body, "html", "utf-8"))

        try:
            await aiosmtplib.send(
                msg,
                hostname=settings.SMTP_HOST,
                port=settings.SMTP_PORT,
                username=settings.SMTP_USER,
                password=settings.SMTP_PASSWORD,
                use_tls=settings.SMTP_TLS,
            )
            return True
        except Exception:
            return False


class SearchService:
    @staticmethod
    async def global_search(
        db: AsyncSession, tenant_id: str, query: str, limit: int = 10
    ) -> Dict[str, Any]:
        tid = uuid.UUID(tenant_id)
        q = f"%{query}%"
        results = {}

        asset_stmt = select(Asset).where(Asset.tenant_id == tid, Asset.is_deleted == False, Asset.name.ilike(q)).limit(limit)
        results["assets"] = [{"id": str(r.id), "name": r.name, "type": r.type} for r in (await db.execute(asset_stmt)).scalars().all()]

        inc_stmt = select(Incident).where(Incident.tenant_id == tid, Incident.title.ilike(q)).limit(limit)
        results["incidents"] = [{"id": str(r.id), "title": r.title, "severity": r.severity} for r in (await db.execute(inc_stmt)).scalars().all()]

        user_stmt = select(User).where(User.tenant_id == tid, User.is_deleted == False, User.full_name.ilike(q)).limit(limit)
        results["users"] = [{"id": str(r.id), "full_name": r.full_name, "email": r.email} for r in (await db.execute(user_stmt)).scalars().all()]

        return {"query": query, "results": results, "total_hits": sum(len(v) for v in results.values())}

    @staticmethod
    async def search_assets(
        db: AsyncSession, tenant_id: str, query: str, filters: Optional[Dict[str, Any]] = None,
        page: int = 1, page_size: int = 20
    ) -> Dict[str, Any]:
        tid = uuid.UUID(tenant_id)
        q = f"%{query}%"
        conditions = [Asset.tenant_id == tid, Asset.is_deleted == False, Asset.name.ilike(q)]
        if filters:
            if filters.get("type"):
                conditions.append(Asset.type == filters["type"])
            if filters.get("status"):
                conditions.append(Asset.status == filters["status"])

        count_stmt = select(func.count()).select_from(Asset).where(*conditions)
        total = await db.scalar(count_stmt) or 0

        stmt = select(Asset).where(*conditions).order_by(Asset.updated_at.desc()).offset((page - 1) * page_size).limit(page_size)
        items = [{"id": str(r.id), "name": r.name, "hostname": r.hostname, "type": r.type, "os": r.os, "status": r.status, "risk_level": r.risk_level} for r in (await db.execute(stmt)).scalars().all()]

        return {"results": items, "total": total, "page": page, "page_size": page_size, "pages": max(1, (total + page_size - 1) // page_size)}


class SessionService:
    @staticmethod
    async def revoke_all_user_sessions(db: AsyncSession, user_id: str) -> int:
        stmt = (
            sql_delete(RefreshToken)
            .where(RefreshToken.user_id == uuid.UUID(user_id), RefreshToken.is_revoked == False)
        )
        result = await db.execute(stmt)
        await db.flush()
        return result.rowcount

    @staticmethod
    async def get_active_sessions(db: AsyncSession, user_id: str) -> List[RefreshToken]:
        stmt = (
            select(RefreshToken)
            .where(
                RefreshToken.user_id == uuid.UUID(user_id),
                RefreshToken.is_revoked == False,
                RefreshToken.expires_at > datetime.now(timezone.utc),
            )
            .order_by(RefreshToken.created_at.desc())
        )
        result = await db.execute(stmt)
        return list(result.scalars().all())
