"""
AEGIS - Enterprise Cybersecurity Operations Platform
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

    # â”€â”€ Application â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    APP_NAME: str = "AEGIS"
    APP_VERSION: str = "2.0.0"
    APP_ENV: str = "development"
    DEBUG: bool = False
    SECRET_KEY: str = "change-me-in-production-use-secrets-manager"
    API_V1_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "AEGIS Platform"

    # â”€â”€ Server â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    HOST: str = "0.0.0.0"
    PORT: int = 8001
    WORKERS: int = 4
    RELOAD: bool = False

    # â”€â”€ CORS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    # â”€â”€ Database â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "AEGIS"
    POSTGRES_PASSWORD: str = "AEGIS"
    POSTGRES_DB: str = "AEGIS"
    DATABASE_URL: Optional[str] = None
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 40
    DATABASE_POOL_TIMEOUT: int = 30
    DATABASE_ECHO: bool = False

    @model_validator(mode="after")
    def assemble_db_url(self) -> "Settings":
        import os
        
        # 1. Use DATABASE_URL from env if set
        url = self.DATABASE_URL or os.environ.get("DATABASE_URL", "")
        if url and ("postgres" in url) and "localhost" not in url:
            url = url.replace("postgres://", "postgresql+asyncpg://", 1).replace("postgresql://", "postgresql+asyncpg://", 1)
            self.DATABASE_URL = url
            return self
        
        # 2. Try Railway PostgreSQL via proxy (PGHOST + PGPORT + PGPASSWORD)
        pg_host = os.environ.get("PGHOST", "")
        pg_port = os.environ.get("PGPORT", "5432")
        pg_user = os.environ.get("PGUSER", "postgres")
        pg_pass = os.environ.get("PGPASSWORD", "")
        pg_db   = os.environ.get("PGDATABASE", "railway")
        
        if pg_host and pg_pass:
            url = f"postgresql+asyncpg://{pg_user}:{pg_pass}@{pg_host}:{pg_port}/{pg_db}"
            self.DATABASE_URL = url
            return self
        
        # 3. Assemble from component defaults
        self.DATABASE_URL = (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )
        return self

    SQLALCHEMY_DATABASE_URL: Optional[str] = None

    @model_validator(mode="after")
    def assemble_sync_url(self) -> "Settings":
        if not self.SQLALCHEMY_DATABASE_URL:
            self.SQLALCHEMY_DATABASE_URL = (
                f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
                f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
            )
        if self.DATABASE_URL and "postgresql+" in (self.DATABASE_URL or ""):
            self.SQLALCHEMY_DATABASE_URL = self.DATABASE_URL.replace("+asyncpg", "", 1)
        if not self.SQLALCHEMY_DATABASE_URL:
            self.SQLALCHEMY_DATABASE_URL = "sqlite:///./fallback.db"
        return self

    # â”€â”€ Redis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    # â”€â”€ Celery â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None

    @model_validator(mode="after")
    def assemble_celery_urls(self) -> "Settings":
        if not self.CELERY_BROKER_URL:
            self.CELERY_BROKER_URL = self.REDIS_URL
        if not self.CELERY_RESULT_BACKEND:
            self.CELERY_RESULT_BACKEND = self.REDIS_URL
        return self

    # â”€â”€ Elasticsearch / OpenSearch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    OPENSEARCH_HOST: str = "localhost"
    OPENSEARCH_PORT: int = 9200
    OPENSEARCH_USER: str = "admin"
    OPENSEARCH_PASSWORD: str = "admin"
    OPENSEARCH_USE_SSL: bool = False
    OPENSEARCH_INDEX_PREFIX: str = "AEGIS"

    # â”€â”€ RabbitMQ â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    RABBITMQ_HOST: str = "localhost"
    RABBITMQ_PORT: int = 5672
    RABBITMQ_USER: str = "guest"
    RABBITMQ_PASSWORD: str = "guest"
    RABBITMQ_VHOST: str = "/"

    # â”€â”€ JWT Authentication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    JWT_SECRET_KEY: str = "change-me-jwt-secret-use-strong-random"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_RESET_TOKEN_EXPIRE_HOURS: int = 24

    # â”€â”€ Password Policy â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGITS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    PASSWORD_LOCKOUT_ATTEMPTS: int = 5
    PASSWORD_LOCKOUT_MINUTES: int = 15

    # â”€â”€ MFA â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    MFA_ENABLED: bool = True
    MFA_ISSUER: str = "AEGIS"

    # â”€â”€ Rate Limiting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_AUTH: str = "10/minute"
    RATE_LIMIT_API: str = "1000/minute"

    # â”€â”€ File Upload â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    MAX_UPLOAD_SIZE_MB: int = 100
    ALLOWED_UPLOAD_EXTENSIONS: List[str] = [
        "csv", "json", "xml", "pdf", "xlsx", "docx",
        "txt", "log", "pcap", "zip", "tar", "gz",
    ]
    UPLOAD_DIR: str = "/app/uploads"

    # â”€â”€ Email â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: str = "noreply@AEGIS.com"
    SMTP_TLS: bool = True

    # â”€â”€ Logging â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    LOG_RETENTION_DAYS: int = 90

    # â”€â”€ Tenants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    MAX_TENANTS: int = 10000
    TENANT_ISOLATION_MODE: str = "row"  # 'row' | 'schema' | 'database'
    DEFAULT_TENANT_QUOTA_ASSETS: int = 1000
    DEFAULT_TENANT_QUOTA_USERS: int = 100
    DEFAULT_TENANT_QUOTA_STORAGE_GB: int = 500

    # â”€â”€ AI / ML â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    # â”€â”€ Threat Intelligence Integrations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    MISP_URL: Optional[str] = None
    MISP_API_KEY: Optional[str] = None
    OPENCTI_URL: Optional[str] = None
    OPENCTI_API_KEY: Optional[str] = None

    # â”€â”€ Agent Registration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    AGENT_REGISTRATION_KEY: str = "change-me-agent-key"
    AGENT_HEARTBEAT_INTERVAL: int = 60
    AGENT_STALE_TIMEOUT: int = 300

    # â”€â”€ Kubernetes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    KUBERNETES_ENABLED: bool = False
    KUBERNETES_NAMESPACE: str = "AEGIS"

    # â”€â”€ Kafka â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    SCHEMA_REGISTRY_URL: str = "http://localhost:8081"

    # â”€â”€ ClickHouse â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    CLICKHOUSE_HOST: str = "localhost"
    CLICKHOUSE_PORT: int = 8123
    CLICKHOUSE_USER: str = "AEGIS"
    CLICKHOUSE_PASSWORD: str = "AEGIS"
    CLICKHOUSE_DB: str = "AEGIS"

    # â”€â”€ MinIO â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    MINIO_ENDPOINT: str = "localhost:9002"
    MINIO_ROOT_USER: str = "AEGIS-admin"
    MINIO_ROOT_PASSWORD: str = "AEGIS-minio-secure"
    MINIO_SECURE: bool = False

    # â”€â”€ Observability â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    PROMETHEUS_ENABLED: bool = True
    PROMETHEUS_METRICS_PORT: int = 9090

    # â”€â”€ Elasticsearch (ELK) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    ELASTICSEARCH_HOST: str = "localhost"
    ELASTICSEARCH_PORT: int = 9201

    # â”€â”€ Jaeger Tracing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    JAEGER_HOST: str = "localhost"
    JAEGER_PORT: int = 6831
    JAEGER_SAMPLING_RATE: float = 0.1
    TRACING_ENABLED: bool = True
    OTEL_SERVICE_NAME: str = "AEGIS-backend"

    # â”€â”€ UEBA â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    UEBA_ENABLED: bool = True
    UEBA_ANOMALY_THRESHOLD: float = 0.7
    UEBA_CRITICAL_THRESHOLD: float = 0.85
    UEBA_BASELINE_WINDOW_DAYS: int = 30

    # â”€â”€ Feature Flags â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    FEATURE_SOAR: bool = True
    FEATURE_THREAT_INTEL: bool = True
    FEATURE_AI: bool = True
    FEATURE_COMPLIANCE: bool = True
    FEATURE_VULNERABILITY: bool = True
    FEATURE_ASSET_DISCOVERY: bool = True
    FEATURE_AGENT: bool = True
    FEATURE_AUDIT: bool = True
    FEATURE_GRAPHQL: bool = True
    FEATURE_KAFKA: bool = True
    FEATURE_CLICKHOUSE: bool = True
    FEATURE_UEBA: bool = True
    FEATURE_SLACK_BOT: bool = False
    FEATURE_AI_REMEDIATION: bool = False

    # Licensing
    LICENSE_KEY: Optional[str] = None
    LICENSE_VALID: bool = False
    LICENSE_CUSTOMER: str = "Community Edition"
    LICENSE_EXPIRES: Optional[int] = None
    LICENSE_MAX_TENANTS: int = 3
    LICENSE_MAX_ENDPOINTS: int = 50

    # Edition
    EDITION: str = "community"
    MAX_TENANTS_COMMUNITY: int = 3
    MAX_ENDPOINTS_COMMUNITY: int = 50
    MAX_SOAR_PLAYBOOKS_COMMUNITY: int = 5

    # â”€â”€ Slack Bot â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    SLACK_BOT_TOKEN: Optional[str] = None
    SLACK_APP_TOKEN: Optional[str] = None
    SLACK_SIGNING_SECRET: Optional[str] = None

    _INSECURE_DEFAULTS = [
        "change-me-in-production-use-secrets-manager",
        "change-me-jwt-secret-use-strong-random",
        "change-me-agent-key",
        "change-me-postgres-password",
    ]
    _INSECURE_PASSWORDS = {
        "POSTGRES_PASSWORD": ["AEGIS", "postgres", "password", "change-me"],
        "OPENSEARCH_PASSWORD": ["admin", "password", "change-me"],
        "RABBITMQ_PASSWORD": ["guest", "password", "change-me"],
        "CLICKHOUSE_PASSWORD": ["AEGIS", "password", "change-me"],
        "MINIO_ROOT_PASSWORD": ["AEGIS-minio-secure", "minioadmin", "password", "change-me"],
        "REDIS_PASSWORD": [],
        "GRAFANA_PASSWORD": ["admin", "AEGIS-grafana", "password"],
    }

    @model_validator(mode="after")
    def validate_production_secrets(self):
        if self.APP_ENV != "production":
            return self

        errors = []
        for name, value in self.__dict__.items():
            if not isinstance(value, str):
                continue
            v = value.lower()
            for insecure in self._INSECURE_DEFAULTS:
                if insecure in v:
                    errors.append(f"'{name}' contains insecure default value")
            if name in self._INSECURE_PASSWORDS:
                for weak in self._INSECURE_PASSWORDS[name]:
                    if v == weak:
                        errors.append(f"'{name}' is set to a well-known default password")

        if errors:
            raise ValueError(
                f"Insecure production configuration detected:\n  " + "\n  ".join(errors) +
                "\nSet strong values via environment variables in production."
            )
        return self


settings = Settings()
