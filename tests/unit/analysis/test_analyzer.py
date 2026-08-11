from __future__ import annotations
from uuid import uuid4
import pytest
from ra_xsoc_engine.analysis.analyzer import IncidentAnalysisService
from ra_xsoc_engine.domain.enums import (
    IncidentSource,
    NoveltyStatus,
    ReviewStatus,
)
from ra_xsoc_engine.domain.exceptions import (
    AnalysisError,
    DomainValidationError,
)
from ra_xsoc_engine.domain.models import (
    AttackMatch,
    IncidentInput,
    MitreTechnique,
    ResponsePlaybook,
)
class StubRetriever:
    def __init__(
        self,
        matches: tuple[AttackMatch, ...],
    ) -> None:
        self.matches = matches
        self.calls: list[tuple[IncidentInput, int]] = []
    def retrieve(
        self,
        incident: IncidentInput,
        limit: int = 3,
    ) -> tuple[AttackMatch, ...]:
        self.calls.append((incident, limit))
        return self.matches[:limit]
class StubPlaybookRepository:
    def __init__(
        self,
        playbooks: dict[str, ResponsePlaybook],
    ) -> None:
        self.playbooks = playbooks
        self.requested_attack_ids: list[str] = []
    def get_by_attack_id(
        self,
        attack_id: str,
    ) -> ResponsePlaybook:
        self.requested_attack_ids.append(attack_id)
        try:
            return self.playbooks[attack_id]
        except KeyError as error:
            raise AnalysisError(
                f"No playbook exists for attack ID: {attack_id}"
            ) from error
def build_incident(
    description: str = "User received a suspicious phishing email.",
) -> IncidentInput:
    return IncidentInput(
        description=description,
        source=IncidentSource.MANUAL,
    )
def build_match(
    attack_id: str,
    *,
    semantic_score: float,
    keyword_score: float,
    hybrid_score: float,
) -> AttackMatch:
    return AttackMatch(
        attack_id=attack_id,
        name=attack_id.upper(),
        semantic_score=semantic_score,
        keyword_score=keyword_score,
        hybrid_score=hybrid_score,
        mitre_techniques=(
            MitreTechnique(
                technique_id="T1566",
                name="Phishing",
            ),
        ),
    )
def build_playbook() -> ResponsePlaybook:
    return ResponsePlaybook(
        containment=("Disable the compromised account.",),
        investigation=("Review authentication logs.",),
        recovery=("Reset credentials.",),
        prevention=("Enable phishing-resistant MFA.",),
        detection_rules=("Alert on suspicious sender domains.",),
    )
def build_service(
    matches: tuple[AttackMatch, ...],
    *,
    confidence_threshold: float = 0.70,
) -> tuple[
    IncidentAnalysisService,
    StubRetriever,
    StubPlaybookRepository,
]:
    retriever = StubRetriever(matches)
    playbook_repository = StubPlaybookRepository(
        {
            "phishing": build_playbook(),
            "ransomware": build_playbook(),
            "unknown": build_playbook(),
        }
    )
    service = IncidentAnalysisService(
        retriever=retriever,
        playbook_repository=playbook_repository,
        confidence_threshold=confidence_threshold,
        model_version="ra-xsoc-v2",
    )
    return service, retriever, playbook_repository
def test_analyzer_returns_primary_match() -> None:
    matches = (
        build_match(
            "phishing",
            semantic_score=0.90,
            keyword_score=0.80,
            hybrid_score=0.87,
        ),
        build_match(
            "ransomware",
            semantic_score=0.40,
            keyword_score=0.20,
            hybrid_score=0.34,
        ),
    )
    service, _, _ = build_service(matches)
    result = service.analyze(build_incident())
    assert result.primary_match.attack_id == "phishing"
    assert result.primary_match.hybrid_score == pytest.approx(0.87)
def test_analyzer_preserves_alternative_matches() -> None:
    matches = (
        build_match(
            "phishing",
            semantic_score=0.90,
            keyword_score=0.80,
            hybrid_score=0.87,
        ),
        build_match(
            "ransomware",
            semantic_score=0.70,
            keyword_score=0.50,
            hybrid_score=0.64,
        ),
    )
    service, _, _ = build_service(matches)
    result = service.analyze(build_incident())
    assert [match.attack_id for match in result.alternatives] == [
        "ransomware",
    ]
def test_analyzer_loads_primary_playbook() -> None:
    matches = (
        build_match(
            "phishing",
            semantic_score=0.90,
            keyword_score=0.80,
            hybrid_score=0.87,
        ),
    )
    service, _, playbook_repository = build_service(matches)
    result = service.analyze(build_incident())
    assert result.playbook == build_playbook()
    assert playbook_repository.requested_attack_ids == ["phishing"]
def test_high_confidence_match_is_known() -> None:
    matches = (
        build_match(
            "phishing",
            semantic_score=0.90,
            keyword_score=0.80,
            hybrid_score=0.87,
        ),
    )
    service, _, _ = build_service(matches)
    result = service.analyze(build_incident())
    assert result.novelty_status is NoveltyStatus.KNOWN
    assert result.confidence == pytest.approx(0.87)
    assert result.requires_review is False
    assert result.review_status is ReviewStatus.NOT_REQUIRED
def test_low_confidence_match_is_possibly_novel_and_requires_review() -> None:
    matches = (
        build_match(
            "phishing",
            semantic_score=0.40,
            keyword_score=0.30,
            hybrid_score=0.37,
        ),
    )
    service, _, _ = build_service(
        matches,
        confidence_threshold=0.70,
    )
    result = service.analyze(build_incident())
    assert result.novelty_status is NoveltyStatus.POSSIBLY_NOVEL
    assert result.confidence == pytest.approx(0.37)
    assert result.requires_review is True
    assert result.review_status is ReviewStatus.PENDING
def test_analyzer_passes_limit_to_retriever() -> None:
    matches = (
        build_match(
            "phishing",
            semantic_score=0.90,
            keyword_score=0.80,
            hybrid_score=0.87,
        ),
    )
    service, retriever, _ = build_service(matches)
    service.analyze(
        build_incident(),
        limit=5,
    )
    assert len(retriever.calls) == 1
    assert retriever.calls[0][1] == 5
def test_analyzer_rejects_invalid_limit() -> None:
    service, _, _ = build_service(
        (
            build_match(
                "phishing",
                semantic_score=0.90,
                keyword_score=0.80,
                hybrid_score=0.87,
            ),
        )
    )
    with pytest.raises(
        DomainValidationError,
        match="limit must be greater than zero",
    ):
        service.analyze(
            build_incident(),
            limit=0,
        )
def test_analyzer_rejects_empty_retrieval_result() -> None:
    service, _, _ = build_service(())
    with pytest.raises(
        AnalysisError,
        match="No attack candidates",
    ):
        service.analyze(build_incident())
def test_analysis_result_preserves_incident_id() -> None:
    incident_id = uuid4()
    incident = IncidentInput(
        description="Suspicious phishing email.",
        incident_id=incident_id,
    )
    service, _, _ = build_service(
        (
            build_match(
                "phishing",
                semantic_score=0.90,
                keyword_score=0.80,
                hybrid_score=0.87,
            ),
        )
    )
    result = service.analyze(incident)
    assert result.incident_id == incident_id
def test_analysis_result_contains_explanation() -> None:
    service, _, _ = build_service(
        (
            build_match(
                "phishing",
                semantic_score=0.90,
                keyword_score=0.80,
                hybrid_score=0.87,
            ),
        )
    )
    result = service.analyze(build_incident())
    assert result.explanation
    assert any(
        "phishing" in explanation.lower()
        for explanation in result.explanation
    )
