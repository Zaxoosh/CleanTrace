from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from cleantrace.models import LinkedAccount
from cleantrace.security import CryptoBox, derive_test_key
from cleantrace.services import create_profile, link_account, unlink_provider


def test_linked_account_token_is_encrypted_and_unlinked() -> None:
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
        account = link_account(
            session,
            box,
            profile=profile,
            provider="github",
            username="alice",
            token="ghp_secretvalue",
        )
        stored = session.exec(select(LinkedAccount)).one()

        assert "ghp_secretvalue" not in stored.token_enc
        assert account.token(box) == "ghp_secretvalue"
        assert unlink_provider(session, profile, "github") == 1
        assert session.exec(select(LinkedAccount)).all() == []
