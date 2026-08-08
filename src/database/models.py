"""SQLAlchemy model for stored scans.

One row per completed scan. The full `SecurityReport` is stored as JSON so the
history endpoints can return it verbatim, without a second schema to keep in
sync with the contract every other component already speaks.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SecurityScan(Base):
    """One completed repository security scan."""

    __tablename__ = "security_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # "owner/repo" when the extension knew it; null for ad-hoc uploads.
    repo: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Branch or commit the files came from, for reproducing the scan.
    ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    # Full SecurityReport JSON.
    report: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
