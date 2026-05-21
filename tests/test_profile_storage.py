from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from cleantrace.models import Profile
from cleantrace.security import CryptoBox, derive_test_key
from cleantrace.services import create_profile


def test_profile_identifiers_are_encrypted_and_hashable() -> None:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    box = CryptoBox(derive_test_key())

    with Session(engine) as session:
        create_profile(
            session,
            box,
            slug="default",
            legal_name="Alice Example",
            display_names=["Alice"],
            usernames=["alicehandle"],
            emails=["alice@example.com"],
            phones=[],
            location=None,
            domains=[],
            social_links=[],
            role_notes=None,
            risk_sensitivity="normal",
            consent=True,
        )
        stored = session.exec(select(Profile)).one()

    assert "alicehandle" not in stored.usernames_enc
    assert "alice@example.com" not in stored.emails_enc
    assert stored.username_hashes_json != "[]"
    assert stored.usernames(box) == ["alicehandle"]
