from cleantrace.security import (
    CryptoBox,
    derive_test_key,
    fingerprint,
    redact,
    redact_text,
    stable_hash,
)


def test_crypto_box_round_trip_json() -> None:
    box = CryptoBox(derive_test_key())
    encrypted = box.encrypt_json({"emails": ["me@example.com"]})

    assert "me@example.com" not in encrypted
    assert box.decrypt_json(encrypted, {}) == {"emails": ["me@example.com"]}


def test_hash_and_fingerprint_are_stable_without_revealing_value() -> None:
    assert stable_hash(" Alice@example.com ") == stable_hash("alice@example.com")
    assert "alice" not in fingerprint("alice@example.com")


def test_redaction_helpers() -> None:
    assert redact("person@example.com") == "pe***@ex***"
    assert redact("+44 7700 900123") == "***0123"
    assert "[redacted-email]" in redact_text("mail me at person@example.com")
