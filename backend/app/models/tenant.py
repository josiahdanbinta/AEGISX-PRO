import uuid
from typing import Optional

from sqlalchemy import Integer, JSON, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.base import TimestampMixin


class Tenant(TimestampMixin, Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    display_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    subscription_tier: Mapped[str] = mapped_column(
        String(50), default="free", nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(50), default="active", nullable=False
    )
    settings: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    quota_assets: Mapped[int] = mapped_column(Integer, default=1000, nullable=False)
    quota_users: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    quota_storage_gb: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    contact_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    contact_phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    address: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    meta_data: Mapped[Optional[dict]] = mapped_column(
        "metadata_", JSON, nullable=True
    )
