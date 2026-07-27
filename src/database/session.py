"""Database engine/session wiring.

`init_db()` is called on app startup to create tables (spec allows create_all
for the MVP; no Alembic). SQLite (local dev) and Postgres (docker-compose /
deploy) are both supported through the same SQLAlchemy engine.
"""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from config import settings

from .models import Base

# SQLite needs check_same_thread=False when used from FastAPI's threadpool.
_connect_args = (
    {"check_same_thread": False}
    if settings.database_url.startswith("sqlite")
    else {}
)

engine = create_engine(settings.database_url, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
