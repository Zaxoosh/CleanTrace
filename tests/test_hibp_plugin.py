from cleantrace.plugins.base import ScanTarget
from cleantrace.plugins.hibp import breach_to_finding, parse_breach


def test_hibp_breach_finding_marks_password_exposure_high() -> None:
    breach = parse_breach(
        {
            "Name": "Example",
            "Title": "Example Breach",
            "Domain": "example.com",
            "BreachDate": "2020-01-01",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True,
            "IsSensitive": False,
        }
    )
    target = ScanTarget(profile_id=1, input_type="email", value="a@example.com", value_hash="hash")

    finding = breach_to_finding(target, breach)

    assert finding.severity == "high"
    assert finding.confidence == 96
    assert "password" in finding.tags
    assert finding.evidence["breach_name"] == "Example"
