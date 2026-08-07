"""
Unit tests for AEGIS configuration module.
"""
import pytest
from unittest.mock import patch
from app.core.config import Settings


class TestSettings:
    @patch.dict('os.environ', {}, clear=True)
    def test_default_values(self):
        settings = Settings()
        assert settings.APP_NAME == "AEGIS"
        assert settings.APP_VERSION == "1.0.0"
        assert settings.API_V1_PREFIX == "/api/v1"
        assert settings.PORT == 8000

    @patch.dict('os.environ', {}, clear=True)
    def test_database_url_assembly(self):
        settings = Settings(
            POSTGRES_HOST="db.example.com",
            POSTGRES_PORT=5432,
            POSTGRES_USER="testuser",
            POSTGRES_PASSWORD="testpass",
            POSTGRES_DB="testdb",
        )
        assert "db.example.com:5432/testdb" in settings.DATABASE_URL
        assert "testuser:testpass" in settings.DATABASE_URL

    @patch.dict('os.environ', {}, clear=True)
    def test_redis_url_assembly(self):
        settings = Settings(
            REDIS_HOST="redis.example.com",
            REDIS_PORT=6379,
            REDIS_DB=1,
        )
        assert "redis://redis.example.com:6379/1" == settings.REDIS_URL

    @patch.dict('os.environ', {}, clear=True)
    def test_redis_url_with_password(self):
        settings = Settings(
            REDIS_HOST="localhost",
            REDIS_PASSWORD="secret123",
        )
        assert ":secret123@" in settings.REDIS_URL

    @patch.dict('os.environ', {}, clear=True)
    def test_cors_origins_parsing(self):
        settings = Settings(BACKEND_CORS_ORIGINS="http://localhost:3000,http://example.com")
        assert "http://localhost:3000" in settings.BACKEND_CORS_ORIGINS
        assert "http://example.com" in settings.BACKEND_CORS_ORIGINS

    def test_cors_origins_as_list(self):
        settings = Settings()
        settings.BACKEND_CORS_ORIGINS = ["http://localhost:3000"]
        assert len(settings.BACKEND_CORS_ORIGINS) == 1

    @patch.dict('os.environ', {}, clear=True)
    def test_password_policy_defaults(self):
        settings = Settings()
        assert settings.PASSWORD_MIN_LENGTH == 12
        assert settings.PASSWORD_REQUIRE_UPPERCASE is True
        assert settings.PASSWORD_REQUIRE_LOWERCASE is True

    @patch.dict('os.environ', {}, clear=True)
    def test_jwt_settings(self):
        settings = Settings()
        assert settings.JWT_ALGORITHM == "HS256"
        assert settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES == 30
        assert settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS == 7

    @patch.dict('os.environ', {}, clear=True)
    def test_feature_flags_default_enabled(self):
        settings = Settings()
        assert settings.FEATURE_SOAR is True
        assert settings.FEATURE_AI is True
        assert settings.FEATURE_THREAT_INTEL is True
        assert settings.FEATURE_COMPLIANCE is True

    @patch.dict('os.environ', {}, clear=True)
    def test_tenant_defaults(self):
        settings = Settings()
        assert settings.DEFAULT_TENANT_QUOTA_ASSETS == 1000
        assert settings.DEFAULT_TENANT_QUOTA_USERS == 100
        assert settings.TENANT_ISOLATION_MODE == "row"

    @patch.dict('os.environ', {}, clear=True)
    def test_agent_settings(self):
        settings = Settings()
        assert settings.AGENT_HEARTBEAT_INTERVAL == 60
        assert settings.AGENT_STALE_TIMEOUT == 300
