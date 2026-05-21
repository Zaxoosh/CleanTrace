from cleantrace.models import Finding, Profile
from cleantrace.scoring import exposure_score, score_band, top_actions


def test_exposure_score_uses_severity_and_confidence() -> None:
    profile = Profile(slug="default", consent=True)
    findings = [
        Finding(
            profile_id=1,
            source_plugin="test",
            input_type="username",
            input_value_hash="hash",
            title="Public profile",
            description="desc",
            confidence=90,
            severity="medium",
            remediation="Remove personal details from this profile.",
        )
    ]

    score = exposure_score(findings, profile)

    assert score > 0
    assert score_band(score)[0] == "low"
    assert top_actions(findings)[0] == "Remove personal details from this profile."


def test_protected_role_boosts_relevant_findings() -> None:
    normal = Profile(slug="normal", consent=True, risk_sensitivity="normal")
    protected = Profile(slug="protected", consent=True, risk_sensitivity="protected-role")
    finding = Finding(
        profile_id=1,
        source_plugin="test",
        input_type="username",
        input_value_hash="hash",
        title="Professional profile",
        description="desc",
        confidence=100,
        severity="medium",
        remediation="Review work-role linkage.",
        tags_json='["professional"]',
    )

    assert exposure_score([finding], protected) > exposure_score([finding], normal)
