"""SQLAlchemy model for stored reviews.

One row per completed review. The full Section-7 `Report` is stored as JSON so
the history endpoints can return it verbatim without a second schema to keep in
sync.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Review(Base):
    __tablename__ = "reviews"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # "url" or "diff" — how the review was requested.
    source: Mapped[str] = mapped_column(String(16))
    # The PR URL (when source == "url"); null for pasted diffs.
    pr_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    issue_count: Mapped[int] = mapped_column(Integer, default=0)
    # Full Report JSON (summary, issues, tokens_used, latency_ms).
    report: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )


class SecurityScan(Base):
    """One completed repository security scan.

    A separate table from `reviews` because it stores a different contract: a
    `SecurityReport` carries detector provenance and degraded-detector state
    that a code-review `Report` has no place for. Squeezing both into one JSON
    column would make every reader guess which shape it got.
    """

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
