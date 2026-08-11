from uuid import uuid4

import pytest
from ra_xsoc_engine.domain import (
    AnalysisResult,
    AnalystFeedback,
    AttackMatch,
    DomainValidationError,
    IncidentInput,
    MitreTechnique,
    NoveltyStatus,
    ResponsePlaybook,
    ReviewStatus,
    SeverityLevel,
)


def build_attack_match() -> AttackMatch:
    technique = MitreTechnique(
        technique_id="T1566",
        name="Phishing",
        tactic="Initial Access",
    )

    return AttackMatch(
        attack_id="phishing",
        name="Phishing",
        semantic_score=0.87,
        keyword_score=0.15,
        hybrid_score=0.92,
        mitre_techniques=(technique,),
    )


def test_incident_input_accepts_valid_description() -> None:
    incident = IncidentInput(
        description=("A user entered credentials into a suspicious Microsoft login page.")
    )

    assert incident.description.startswith("A user")
    assert incident.incident_id is not None
    assert incident.submitted_at.tzinfo is not None


def test_incident_input_rejects_empty_description() -> None:
    with pytest.raises(DomainValidationError):
        IncidentInput(description="   ")


def test_attack_match_rejects_invalid_score() -> None:
    with pytest.raises(DomainValidationError):
        AttackMatch(
            attack_id="phishing",
            name="Phishing",
            semantic_score=1.2,
            keyword_score=0.1,
            hybrid_score=0.9,
        )


def test_analysis_result_sets_pending_review() -> None:
    match = build_attack_match()

    result = AnalysisResult(
        incident_id=uuid4(),
        primary_match=match,
        alternatives=(),
        severity=SeverityLevel.HIGH,
        novelty_status=NoveltyStatus.POSSIBLY_NOVEL,
        confidence=0.55,
        playbook=ResponsePlaybook(
            containment=("Reset the affected account password.",),
            investigation=("Review authentication logs.",),
        ),
        explanation=("Credential-harvesting indicators were found.",),
        requires_review=True,
        model_version="ra-xsoc-v2-domain-0.1.0",
    )

    assert result.review_status is ReviewStatus.PENDING


def test_corrected_feedback_requires_attack_id() -> None:
    with pytest.raises(DomainValidationError):
        AnalystFeedback(
            analysis_id=uuid4(),
            analyst_id=uuid4(),
            status=ReviewStatus.CORRECTED,
            comments="The prediction should be changed.",
        )


def test_corrected_feedback_accepts_attack_id() -> None:
    feedback = AnalystFeedback(
        analysis_id=uuid4(),
        analyst_id=uuid4(),
        status=ReviewStatus.CORRECTED,
        comments="The incident is credential stuffing.",
        corrected_attack_id="credential_stuffing",
    )

    assert feedback.corrected_attack_id == ("credential_stuffing")
