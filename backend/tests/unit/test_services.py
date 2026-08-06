import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AuditLog, Tenant, NotificationChannel, NotificationHistory,
    NotificationPreference, User, Asset, Incident, RefreshToken,
)
from app.services import (
    AuditService, TenantService, NotificationService,
    EmailService, SearchService, SessionService,
)


class TestAuditService:
    @pytest.mark.asyncio
    async def test_log_creation_mock(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tenant_id = uuid.uuid4()
        user_id = uuid.uuid4()
        resource_id = uuid.uuid4()

        result = await AuditService.log(
            db=mock_db,
            action="user.create",
            resource_type="user",
            tenant_id=str(tenant_id),
            user_id=str(user_id),
            resource_id=str(resource_id),
            details={"role": "admin"},
            ip_address="192.168.1.100",
            user_agent="TestAgent/1.0",
            status="success",
            severity="info",
        )

        mock_db.add.assert_called_once()
        mock_db.flush.assert_awaited_once()
        added_log = mock_db.add.call_args[0][0]
        assert isinstance(added_log, AuditLog)
        assert added_log.action == "user.create"
        assert added_log.resource_type == "user"
        assert added_log.tenant_id == tenant_id
        assert added_log.user_id == user_id
        assert added_log.resource_id == resource_id
        assert added_log.details == {"role": "admin"}
        assert added_log.ip_address == "192.168.1.100"
        assert added_log.user_agent == "TestAgent/1.0"
        assert added_log.status == "success"
        assert added_log.severity == "info"
        assert isinstance(result, AuditLog)

    @pytest.mark.asyncio
    async def test_get_user_activity(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tenant_id = uuid.uuid4()
        user_id = uuid.uuid4()

        log1 = AuditLog(
            tenant_id=tenant_id, user_id=user_id,
            action="login", resource_type="auth", severity="info",
        )
        log2 = AuditLog(
            tenant_id=tenant_id, user_id=user_id,
            action="logout", resource_type="auth", severity="info",
        )
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [log1, log2]
        mock_db.execute.return_value = mock_result

        logs = await AuditService.get_user_activity(
            db=mock_db, user_id=str(user_id), tenant_id=str(tenant_id), limit=50
        )

        assert len(logs) == 2
        assert logs[0].action == "login"
        assert logs[1].action == "logout"
        mock_db.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_resource_audit_trail(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tenant_id = uuid.uuid4()
        resource_id = uuid.uuid4()

        log = AuditLog(
            tenant_id=tenant_id, resource_id=resource_id,
            action="update", resource_type="asset", severity="info",
        )
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [log]
        mock_db.execute.return_value = mock_result

        logs = await AuditService.get_resource_audit_trail(
            db=mock_db,
            resource_type="asset",
            resource_id=str(resource_id),
            tenant_id=str(tenant_id),
        )

        assert len(logs) == 1
        assert logs[0].action == "update"
        assert logs[0].resource_type == "asset"
        mock_db.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_purge_old_logs(self):
        mock_db = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.rowcount = 42
        mock_db.execute.return_value = mock_result
        before_date = datetime(2024, 1, 1, tzinfo=timezone.utc)

        count = await AuditService.purge_old_logs(db=mock_db, before_date=before_date)

        assert count == 42
        mock_db.execute.assert_awaited_once()
        mock_db.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_purge_old_logs_with_tenant(self):
        mock_db = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.rowcount = 10
        mock_db.execute.return_value = mock_result
        tenant_id = uuid.uuid4()
        before_date = datetime(2024, 1, 1, tzinfo=timezone.utc)

        count = await AuditService.purge_old_logs(
            db=mock_db, before_date=before_date, tenant_id=str(tenant_id)
        )

        assert count == 10
        mock_db.execute.assert_awaited_once()
        mock_db.flush.assert_awaited_once()


class TestTenantService:
    @pytest.mark.asyncio
    async def test_get_tenant(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tid = uuid.uuid4()
        tenant = Tenant(name="test-tenant", id=tid, subscription_tier="pro")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = tenant
        mock_db.execute.return_value = mock_result

        result = await TenantService.get_tenant(db=mock_db, tenant_id=str(tid))

        assert result is not None
        assert result.name == "test-tenant"
        assert result.subscription_tier == "pro"
        mock_db.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_tenant_not_found(self):
        mock_db = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        result = await TenantService.get_tenant(
            db=mock_db, tenant_id=str(uuid.uuid4())
        )

        assert result is None
        mock_db.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_check_quota_within_limit(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tid = uuid.uuid4()
        tenant = Tenant(name="test", id=tid, quota_assets=100)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = tenant
        mock_db.execute.return_value = mock_result

        ok = await TenantService.check_quota(
            db=mock_db, tenant_id=str(tid), resource="assets", current=50
        )

        assert ok is True

    @pytest.mark.asyncio
    async def test_check_quota_at_limit(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tid = uuid.uuid4()
        tenant = Tenant(name="test", id=tid, quota_assets=100)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = tenant
        mock_db.execute.return_value = mock_result

        ok = await TenantService.check_quota(
            db=mock_db, tenant_id=str(tid), resource="assets", current=100
        )

        assert ok is False

    @pytest.mark.asyncio
    async def test_check_quota_exceeded(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tid = uuid.uuid4()
        tenant = Tenant(name="test", id=tid, quota_users=50)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = tenant
        mock_db.execute.return_value = mock_result

        ok = await TenantService.check_quota(
            db=mock_db, tenant_id=str(tid), resource="users", current=75
        )

        assert ok is False

    @pytest.mark.asyncio
    async def test_check_quota_tenant_not_found(self):
        mock_db = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        ok = await TenantService.check_quota(
            db=mock_db, tenant_id=str(uuid.uuid4()), resource="assets", current=10
        )

        assert ok is False

    @pytest.mark.asyncio
    async def test_get_usage(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tid = uuid.uuid4()
        mock_db.scalar = AsyncMock()
        mock_db.scalar.side_effect = [25, 15, 3]

        usage = await TenantService.get_usage(db=mock_db, tenant_id=str(tid))

        assert usage["assets"] == 25
        assert usage["users"] == 15
        assert usage["incidents_open"] == 3
        assert "storage_gb" in usage
        assert "alerts_today" in usage

    @pytest.mark.asyncio
    async def test_suspend_tenant(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tid = uuid.uuid4()
        tenant = Tenant(name="test", id=tid, status="active")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = tenant
        mock_db.execute.return_value = mock_result

        await TenantService.suspend_tenant(db=mock_db, tenant_id=str(tid))

        assert tenant.status == "suspended"
        mock_db.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_suspend_tenant_not_found(self):
        mock_db = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        await TenantService.suspend_tenant(db=mock_db, tenant_id=str(uuid.uuid4()))

        mock_db.flush.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_activate_tenant(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tid = uuid.uuid4()
        tenant = Tenant(name="test", id=tid, status="suspended")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = tenant
        mock_db.execute.return_value = mock_result

        await TenantService.activate_tenant(db=mock_db, tenant_id=str(tid))

        assert tenant.status == "active"
        mock_db.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_activate_tenant_not_found(self):
        mock_db = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        await TenantService.activate_tenant(db=mock_db, tenant_id=str(uuid.uuid4()))

        mock_db.flush.assert_not_awaited()


class TestNotificationService:
    @pytest.mark.asyncio
    async def test_get_user_preferences(self):
        mock_db = AsyncMock(spec=AsyncSession)
        uid = uuid.uuid4()
        pref = NotificationPreference(
            tenant_id=uuid.uuid4(), user_id=uid,
            alert_severity_filter="high",
        )
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pref
        mock_db.execute.return_value = mock_result

        result = await NotificationService.get_user_preferences(
            db=mock_db, user_id=str(uid)
        )

        assert result is not None
        assert result.alert_severity_filter == "high"
        mock_db.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_user_preferences_not_found(self):
        mock_db = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        result = await NotificationService.get_user_preferences(
            db=mock_db, user_id=str(uuid.uuid4())
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_send_notification(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tid = uuid.uuid4()

        history = await NotificationService.send(
            db=mock_db,
            channel_type="email",
            recipient="user@test.com",
            subject="Test Alert",
            body="This is a test notification",
            tenant_id=str(tid),
            data={"alert_id": "123"},
        )

        mock_db.add.assert_called_once()
        mock_db.flush.assert_awaited_once()
        added = mock_db.add.call_args[0][0]
        assert isinstance(added, NotificationHistory)
        assert added.channel_type == "email"
        assert added.recipient == "user@test.com"
        assert added.subject == "Test Alert"
        assert added.content == "This is a test notification"
        assert added.status == "sent"
        assert isinstance(history, NotificationHistory)

    @pytest.mark.asyncio
    async def test_get_active_channels(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tid = uuid.uuid4()
        channel = NotificationChannel(
            tenant_id=tid, name="Email Alerts",
            channel_type="email", is_active=True,
        )
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [channel]
        mock_db.execute.return_value = mock_result

        channels = await NotificationService.get_active_channels(
            db=mock_db, tenant_id=str(tid)
        )

        assert len(channels) == 1
        assert channels[0].channel_type == "email"
        mock_db.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_active_channels_with_type_filter(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tid = uuid.uuid4()
        channel = NotificationChannel(
            tenant_id=tid, name="Slack Channel",
            channel_type="slack", is_active=True,
        )
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [channel]
        mock_db.execute.return_value = mock_result

        channels = await NotificationService.get_active_channels(
            db=mock_db, tenant_id=str(tid), channel_type="slack"
        )

        assert len(channels) == 1
        assert channels[0].channel_type == "slack"
        mock_db.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_notify_users(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tid = uuid.uuid4()
        uid = uuid.uuid4()
        user = User(
            tenant_id=tid, username="testuser",
            email="testuser@test.com", hashed_password="pw",
        )
        user.id = uid

        user_result = MagicMock()
        user_result.scalar_one_or_none.return_value = user
        mock_db.execute.return_value = user_result

        histories = await NotificationService.notify_users(
            db=mock_db,
            tenant_id=str(tid),
            user_ids=[str(uid)],
            subject="Bulk Alert",
            body="Bulk notification body",
            channel_type="email",
        )

        assert len(histories) == 1
        assert histories[0].channel_type == "email"
        assert histories[0].recipient == "testuser@test.com"


class TestSearchService:
    @pytest.mark.asyncio
    async def test_global_search(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tid = uuid.uuid4()

        asset_result = MagicMock()
        asset_result.scalars.return_value.all.return_value = []
        inc_result = MagicMock()
        inc_result.scalars.return_value.all.return_value = []
        user_result = MagicMock()
        user_result.scalars.return_value.all.return_value = []
        mock_db.execute.side_effect = [asset_result, inc_result, user_result]

        results = await SearchService.global_search(
            db=mock_db, tenant_id=str(tid), query="test", limit=10
        )

        assert "query" in results
        assert results["query"] == "test"
        assert "results" in results
        assert "assets" in results["results"]
        assert "incidents" in results["results"]
        assert "users" in results["results"]
        assert results["total_hits"] == 0

    @pytest.mark.asyncio
    async def test_search_assets(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tid = uuid.uuid4()

        mock_db.scalar = AsyncMock()
        mock_db.scalar.return_value = 5

        asset = Asset(
            tenant_id=tid, name="Test Asset", hostname="test-host",
            type="server", os="linux", status="online", risk_level="low",
        )
        asset.id = uuid.uuid4()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [asset]
        mock_db.execute.side_effect = [mock_result, mock_result]

        results = await SearchService.search_assets(
            db=mock_db, tenant_id=str(tid), query="test", page=1, page_size=20
        )

        assert results["total"] == 5
        assert len(results["results"]) == 1
        assert results["page"] == 1
        assert results["page_size"] == 20

    @pytest.mark.asyncio
    async def test_search_assets_with_filters(self):
        mock_db = AsyncMock(spec=AsyncSession)
        tid = uuid.uuid4()

        mock_db.scalar = AsyncMock()
        mock_db.scalar.return_value = 2

        asset = Asset(
            tenant_id=tid, name="Filtered Asset",
            type="endpoint", status="online",
        )
        asset.id = uuid.uuid4()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [asset]
        mock_db.execute.side_effect = [mock_result, mock_result]

        results = await SearchService.search_assets(
            db=mock_db, tenant_id=str(tid),
            query="filtered",
            filters={"type": "endpoint", "status": "online"},
            page=2, page_size=10,
        )

        assert results["total"] == 2
        assert results["page"] == 2


class TestSessionService:
    @pytest.mark.asyncio
    async def test_revoke_all_user_sessions(self):
        mock_db = AsyncMock(spec=AsyncSession)
        uid = uuid.uuid4()
        mock_result = MagicMock()
        mock_result.rowcount = 3
        mock_db.execute.return_value = mock_result

        count = await SessionService.revoke_all_user_sessions(
            db=mock_db, user_id=str(uid)
        )

        assert count == 3
        mock_db.execute.assert_awaited_once()
        mock_db.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_revoke_all_user_sessions_none(self):
        mock_db = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.rowcount = 0
        mock_db.execute.return_value = mock_result

        count = await SessionService.revoke_all_user_sessions(
            db=mock_db, user_id=str(uuid.uuid4())
        )

        assert count == 0

    @pytest.mark.asyncio
    async def test_get_active_sessions(self):
        mock_db = AsyncMock(spec=AsyncSession)
        uid = uuid.uuid4()
        tid = uuid.uuid4()
        token = RefreshToken(
            tenant_id=tid, user_id=uid,
            token_jti="jti-1", token_hash="hash-1",
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
            is_revoked=False,
        )
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [token]
        mock_db.execute.return_value = mock_result

        sessions = await SessionService.get_active_sessions(
            db=mock_db, user_id=str(uid)
        )

        assert len(sessions) == 1
        assert sessions[0].token_jti == "jti-1"
        mock_db.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_active_sessions_empty(self):
        mock_db = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute.return_value = mock_result

        sessions = await SessionService.get_active_sessions(
            db=mock_db, user_id=str(uuid.uuid4())
        )

        assert len(sessions) == 0


class TestEmailService:
    @pytest.mark.asyncio
    @patch("aiosmtplib.send", new_callable=AsyncMock)
    async def test_send_email_success(self, mock_send):
        result = await EmailService.send_email(
            to="user@example.com",
            subject="Test Subject",
            body="Test body content",
        )

        assert result is True

    @pytest.mark.asyncio
    @patch("aiosmtplib.send", new_callable=AsyncMock)
    async def test_send_email_with_html(self, mock_send):
        result = await EmailService.send_email(
            to="user@example.com",
            subject="HTML Test",
            body="Plain text fallback",
            html_body="<h1>HTML Content</h1>",
        )

        assert result is True

    @pytest.mark.asyncio
    @patch("aiosmtplib.send", new_callable=AsyncMock)
    async def test_send_email_failure(self, mock_send):
        mock_send.side_effect = Exception("SMTP connection failed")

        result = await EmailService.send_email(
            to="user@example.com",
            subject="Failure Test",
            body="This should fail",
        )

        assert result is False
