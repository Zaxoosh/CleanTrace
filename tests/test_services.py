from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from cleantrace.models import Finding
from cleantrace.plugins.base import PluginFinding
from cleantrace.security import CryptoBox, derive_test_key
from cleantrace.services import create_profile, upsert_finding


def test_upsert_finding_keeps_distinct_titles_with_same_input_and_url() -> None:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    box = CryptoBox(derive_test_key())

    with Session(engine) as session:
        profile = create_profile(
            session,
            box,
            slug="default",
            legal_name=None,
            display_names=[],
            usernames=[],
            emails=[],
            phones=[],
            location=None,
            domains=[],
            social_links=[],
            role_notes=None,
            risk_sensitivity="normal",
            consent=True,
        )
        for title in ["Location warning", "Shared-link warning"]:
            upsert_finding(
                session,
                profile,
                PluginFinding(
                    source_plugin="google_takeout",
                    input_type="google_takeout",
                    input_value_hash="same-archive",
                    title=title,
                    description="desc",
                    url=None,
                    evidence={},
                    confidence=80,
                    severity="medium",
                    remediation="Review.",
                    tags=["google"],
                ),
            )
        session.commit()

        assert len(session.exec(select(Finding)).all()) == 2
