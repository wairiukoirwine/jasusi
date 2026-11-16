"""Database tables.

Privacy by design: a scan stores a SHA-256 of the content, never the content itself.
IOCs are stored masked/defanged. Raw text exists only in `feedback`, only with consent,
anonymised and encrypted.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    channel: Mapped[str] = mapped_column(String(10), index=True)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(String(12), index=True)
    category: Mapped[str] = mapped_column(String(40), index=True)
    model_version: Mapped[str] = mapped_column(String(80))
    latency_ms: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)

    iocs: Mapped[list["ScanIOC"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ScanIOC(Base):
    __tablename__ = "scan_iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(10))
    value_masked: Mapped[str] = mapped_column(String(300))

    scan: Mapped[Scan] = relationship(back_populates="iocs")


class Feedback(Base):
    __tablename__ = "feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    user_label: Mapped[str] = mapped_column(String(10))
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    consent_raw_text: Mapped[bool] = mapped_column(Boolean, default=False)
    raw_text_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner: Mapped[str] = mapped_column(String(120))
    hashed_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    tier: Mapped[str] = mapped_column(String(20), default="free")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
