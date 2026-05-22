from cleantrace.models import Finding, Profile
from cleantrace.removal import find_broker, render_broker_request, render_finding_request


def test_render_finding_request_includes_reference_without_sending() -> None:
    profile = Profile(id=1, slug="default", consent=True)
    finding = Finding(
        id="abc123",
        profile_id=1,
        source_plugin="username_discovery",
        input_type="username",
        input_value_hash="hash",
        title="Possible public profile",
        description="desc",
        url="https://example.com/me",
        confidence=80,
        severity="medium",
        remediation="Remove details.",
    )

    subject, body = render_finding_request(profile, finding, "Alice Example")

    assert "Possible public profile" in subject
    assert "abc123" in body
    assert "https://example.com/me" in body


def test_render_broker_request_uses_directory_metadata() -> None:
    broker = find_broker("192.com")
    assert broker is not None

    subject, body = render_broker_request(Profile(id=1, slug="default"), broker, "Alice Example")

    assert subject == "Data broker opt-out request: 192.com"
    assert broker.opt_out_url in body
    assert "UK GDPR" in body
