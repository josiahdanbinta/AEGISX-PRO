"""
AEGISX - Enterprise Cybersecurity Operations Platform
Core Configuration Module
"""
import os
from typing import List, Optional, Union
from pathlib import Path

from pydantic import (
    AnyHttpUrl,
    EmailStr,
    PostgresDsn,
    RedisDsn,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="allow",
    )

    # ── Application ──────────────────────────────────────────────
    APP_NAME: str = "AEGISX"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"
    DEBUG: bool = False
    SECRET_KEY: str = "change-me-in-production-use-secrets-manager"
    API_V1_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "AEGISX Platform"

    # ── Server ───────────────────────────────────────────────────
    HOST: str = "0.0.0.0"
    PORT: int = 8001
    WORKERS: int = 4
    RELOAD: bool = True

    # ── CORS ─────────────────────────────────────────────────────
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if not v:
                return []
            try:
                import json
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                pass
            return [i.strip() for i in v.split(",") if i.strip()]
        return v

    # ── Database ─────────────────────────────────────────────────
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "aegisx"
    POSTGRES_PASSWORD: str = "aegisx"
    POSTGRES_DB: str = "aegisx"
    DATABASE_URL: Optional[str] = None
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 40
    DATABASE_POOL_TIMEOUT: int = 30
    DATABASE_ECHO: bool = False

    @model_validator(mode="after")
    def assemble_db_url(self) -> "Settings":
        if not self.DATABASE_URL:
            self.DATABASE_URL = (
                f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
                f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
            )
        # Railway provides DATABASE_URL as postgresql:// - convert to asyncpg
        if self.DATABASE_URL and self.DATABASE_URL.startswith("postgresql://"):
            self.DATABASE_URL = self.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
        return self

    SQLALCHEMY_DATABASE_URL: Optional[str] = None

    @model_validator(mode="after")
    def assemble_sync_url(self) -> "Settings":
        if not self.SQLALCHEMY_DATABASE_URL:
            self.SQLALCHEMY_DATABASE_URL = (
                f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
                f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
            )
        # If DATABASE_URL was converted from Railway, use the sync version too
        if not self.SQLALCHEMY_DATABASE_URL and self.DATABASE_URL:
            self.SQLALCHEMY_DATABASE_URL = self.DATABASE_URL.replace("+asyncpg", "", 1)
        return self

    # ── Redis ────────────────────────────────────────────────────
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0
    REDIS_URL: Optional[str] = None

    @model_validator(mode="after")
    def assemble_redis_url(self) -> "Settings":
        if not self.REDIS_URL:
            pwd = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
            self.REDIS_URL = f"redis://{pwd}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
        return self

    # ── Celery ───────────────────────────────────────────────────
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None

    @model_validator(mode="after")
    def assemble_celery_urls(self) -> "Settings":
        if not self.CELERY_BROKER_URL:
            self.CELERY_BROKER_URL = self.REDIS_URL
        if not self.CELERY_RESULT_BACKEND:
            self.CELERY_RESULT_BACKEND = self.REDIS_URL
        return self

    # ── Elasticsearch / OpenSearch ───────────────────────────────
    OPENSEARCH_HOST: str = "localhost"
    OPENSEARCH_PORT: int = 9200
    OPENSEARCH_USER: str = "admin"
    OPENSEARCH_PASSWORD: str = "admin"
    OPENSEARCH_USE_SSL: bool = False
    OPENSEARCH_INDEX_PREFIX: str = "aegisx"

    # ── RabbitMQ ─────────────────────────────────────────────────
    RABBITMQ_HOST: str = "localhost"
    RABBITMQ_PORT: int = 5672
    RABBITMQ_USER: str = "guest"
    RABBITMQ_PASSWORD: str = "guest"
    RABBITMQ_VHOST: str = "/"

    # ── JWT Authentication ───────────────────────────────────────
    JWT_SECRET_KEY: str = "change-me-jwt-secret-use-strong-random"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_RESET_TOKEN_EXPIRE_HOURS: int = 24

    # ── Password Policy ──────────────────────────────────────────
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGITS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    PASSWORD_LOCKOUT_ATTEMPTS: int = 5
    PASSWORD_LOCKOUT_MINUTES: int = 15

    # ── MFA ──────────────────────────────────────────────────────
    MFA_ENABLED: bool = True
    MFA_ISSUER: str = "AEGISX"

    # ── Rate Limiting ────────────────────────────────────────────
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_AUTH: str = "10/minute"
    RATE_LIMIT_API: str = "1000/minute"

    # ── File Upload ──────────────────────────────────────────────
    MAX_UPLOAD_SIZE_MB: int = 100
    ALLOWED_UPLOAD_EXTENSIONS: List[str] = [
        "csv", "json", "xml", "pdf", "xlsx", "docx",
        "txt", "log", "pcap", "zip", "tar", "gz",
    ]
    UPLOAD_DIR: str = "/app/uploads"

    # ── Email ────────────────────────────────────────────────────
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: str = "noreply@aegisx.com"
    SMTP_TLS: bool = True

    # ── Logging ──────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    LOG_RETENTION_DAYS: int = 90

    # ── Tenants ──────────────────────────────────────────────────
    MAX_TENANTS: int = 10000
    TENANT_ISOLATION_MODE: str = "row"  # 'row' | 'schema' | 'database'
    DEFAULT_TENANT_QUOTA_ASSETS: int = 1000
    DEFAULT_TENANT_QUOTA_USERS: int = 100
    DEFAULT_TENANT_QUOTA_STORAGE_GB: int = 500

    # ── AI / ML ──────────────────────────────────────────────────
    AI_ENABLED: bool = True
    AI_PROVIDER: str = "openai"
    AI_MODEL: str = "gpt-4"
    AI_MAX_TOKENS: int = 4096
    AI_TEMPERATURE: float = 0.3
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_API_BASE: Optional[str] = None
    AZURE_OPENAI_KEY: Optional[str] = None
    AZURE_OPENAI_ENDPOINT: Optional[str] = None
    AZURE_OPENAI_DEPLOYMENT: Optional[str] = None

    # ── Threat Intelligence Integrations ─────────────────────────
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    MISP_URL: Optional[str] = None
    MISP_API_KEY: Optional[str] = None
    OPENCTI_URL: Optional[str] = None
    OPENCTI_API_KEY: Optional[str] = None

    # ── Agent Registration ──────────────────────────────────────
    AGENT_REGISTRATION_KEY: str = "change-me-agent-key"
    AGENT_HEARTBEAT_INTERVAL: int = 60
    AGENT_STALE_TIMEOUT: int = 300

    # ── Kubernetes ───────────────────────────────────────────────
    KUBERNETES_ENABLED: bool = False
    KUBERNETES_NAMESPACE: str = "aegisx"

    # ── Feature Flags ────────────────────────────────────────────
    FEATURE_SOAR: bool = True
    FEATURE_THREAT_INTEL: bool = True
    FEATURE_AI: bool = True
    FEATURE_COMPLIANCE: bool = True
    FEATURE_VULNERABILITY: bool = True
    FEATURE_ASSET_DISCOVERY: bool = True
    FEATURE_AGENT: bool = True
    FEATURE_AUDIT: bool = True
    FEATURE_GRAPHQL: bool = True


settings = Settings()
