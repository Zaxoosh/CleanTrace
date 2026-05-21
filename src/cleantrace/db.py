from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import Engine
from sqlmodel import Session, SQLModel, create_engine, select

from cleantrace.config import load_config
from cleantrace.models import Finding, Profile
from cleantrace.paths import ensure_app_dirs


def get_engine(database: Path | None = None) -> Engine:
    ensure_app_dirs()
    db_path = database or load_config().database
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})


def init_db(engine: Engine | None = None) -> None:
    SQLModel.metadata.create_all(engine or get_engine())


def session_scope(engine: Engine | None = None) -> Iterator[Session]:
    with Session(engine or get_engine()) as session:
        yield session


def get_profile_by_slug(session: Session, slug: str) -> Profile | None:
    return session.exec(select(Profile).where(Profile.slug == slug)).first()


def list_findings(session: Session, profile: Profile | None = None) -> list[Finding]:
    statement = select(Finding)
    if profile and profile.id is not None:
        statement = statement.where(Finding.profile_id == profile.id)
    return list(session.exec(statement).all())
