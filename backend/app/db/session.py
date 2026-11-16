"""Engine and session factory. Tables are created at startup (Alembic comes with the first
schema change that needs a migration)."""

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models import Base


def make_engine(url: str) -> Engine:
    """Create the engine and make sure the tables exist."""
    if url.startswith("sqlite"):
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool  # one shared in-memory DB (tests)
        engine = create_engine(url, **kwargs)
    else:
        engine = create_engine(url, pool_pre_ping=True)
    Base.metadata.create_all(engine)
    return engine


def make_session_factory(url: str) -> sessionmaker[Session]:
    return sessionmaker(bind=make_engine(url), expire_on_commit=False)


def get_db(request: Request) -> Iterator[Session]:
    """FastAPI dependency: one session per request, from the app's own factory."""
    with request.app.state.session_factory() as session:
        yield session
