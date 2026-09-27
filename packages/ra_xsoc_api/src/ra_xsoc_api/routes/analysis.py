from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from ra_xsoc_engine.domain.exceptions import (
    AnalysisError,
    DomainValidationError,
)
from ra_xsoc_engine.domain.models import IncidentInput

from ra_xsoc_api.dependencies import get_application, get_case_store
from ra_xsoc_api.auth import AuthenticatedUser, require_roles
from ra_xsoc_engine.domain.enums import UserRole
from ra_xsoc_api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    AttackMatchResponse,
    MitreTechniqueResponse,
    ResponsePlaybookResponse,
    EvidenceItemResponse, HypothesisResponse, IncidentIdentityResponse,
    NoveltyAssessmentResponse, ResearchEvaluationResponse,
    InvestigationQuestionResponse, SourceVerificationResponse,
    InvestigationStepResponse, InvestigationAssessmentResponse,
)

router = APIRouter(
    prefix="/api/v1",
    tags=["analysis"],
)


def _attack_match_to_response(match: object) -> AttackMatchResponse:
    return AttackMatchResponse(
        attack_id=match.attack_id,
        name=match.name,
        semantic_score=match.semantic_score,
        keyword_score=match.keyword_score,
        hybrid_score=match.hybrid_score,
        mitre_techniques=[
            MitreTechniqueResponse(
                technique_id=technique.technique_id,
                name=technique.name,
                tactic=technique.tactic,
                url=technique.url,
            )
            for technique in match.mitre_techniques
        ],
    )


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
)
def analyze_incident(
    request: AnalyzeRequest,
    application=Depends(get_application),
    store=Depends(get_case_store),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.REVIEWER)),
) -> AnalyzeResponse:
    try:
        incident_kwargs = {
            "description": request.description,
            "external_reference": request.external_reference,
            "metadata": request.metadata,
        }

        if request.incident_id is not None:
            incident_kwargs["incident_id"] = request.incident_id

        incident = IncidentInput(**incident_kwargs)

        result = application.analyzer.analyze(
            incident,
            limit=5,
        )
    except DomainValidationError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(error),
        ) from error
    except AnalysisError as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(error),
        ) from error

    response = AnalyzeResponse(
        analysis_id=result.analysis_id,
        incident_id=result.incident_id,
        primary_match=_attack_match_to_response(
            result.primary_match
        ),
        alternatives=[
            _attack_match_to_response(match)
            for match in result.alternatives
        ],
        severity=result.severity.value,
        novelty_status=result.novelty_status.value,
        confidence=result.confidence,
        playbook=ResponsePlaybookResponse(
            containment=list(result.playbook.containment),
            investigation=list(result.playbook.investigation),
            recovery=list(result.playbook.recovery),
            prevention=list(result.playbook.prevention),
            detection_rules=list(result.playbook.detection_rules),
        ),
        explanation=list(result.explanation),
        requires_review=result.requires_review,
        model_version=result.model_version,
        review_status=result.review_status.value,
        created_at=result.created_at.isoformat(),
        incident=IncidentIdentityResponse(
            name=result.primary_match.name,
            attack_family=result.primary_match.attack_id,
            stage=result.primary_match.mitre_techniques[0].tactic if result.primary_match.mitre_techniques and result.primary_match.mitre_techniques[0].tactic else "Unknown",
            confidence=result.confidence,
            description=request.description,
        ),
        novelty=NoveltyAssessmentResponse(
            score=max(0.0, min(1.0, 1.0 - result.confidence)),
            status="KNOWN_PATTERN" if result.novelty_status.value == "known" else "INSUFFICIENT_EVIDENCE",
            known_similarity=result.confidence,
            behavior_coverage=1.0 if result.confidence >= 0.7 else result.confidence,
            unseen_signal_ratio=0.0,
            combination_novelty=0.0,
            reasons=list(result.explanation),
        ),
        research=ResearchEvaluationResponse(
            planner=[],
            feature_vector=[],
            matched_pattern_ids=[result.primary_match.attack_id] + [m.attack_id for m in result.alternatives],
            unmatched_features=[],
            hypothesis_count=1 + len(result.alternatives),
            technique_count=len(result.primary_match.mitre_techniques),
            reproducible=True,
            evaluation_version="RA-XSOC-X-API-1.0",
        ),
        evidence=[
            EvidenceItemResponse(
                id=f"{result.analysis_id}-primary",
                text=f"Retrieval-derived signal: hybrid retrieval score {result.primary_match.hybrid_score:.3f}.",
                type="retrieval_signal",
                source="RA-XSOC retrieval engine (not independent telemetry)",
                strength=result.primary_match.hybrid_score,
            )
        ],
        hypotheses=[
            HypothesisResponse(
                id=match.attack_id,
                name=match.name,
                category=match.attack_id,
                score=match.hybrid_score,
                status="supported" if match is result.primary_match else "possible",
                supporting=[f"Retrieved with hybrid score {match.hybrid_score:.3f}"],
                contradicting=[],
                missing=[],
                techniques=[
                    MitreTechniqueResponse(
                        technique_id=t.technique_id, name=t.name, tactic=t.tactic, url=t.url
                    ) for t in match.mitre_techniques
                ],
            )
            for match in (result.primary_match,) + result.alternatives
        ],
        verification=[],
        investigation=[
            InvestigationStepResponse(
                order=1,
                title="Preserve and correlate evidence",
                action="Record the original alert, event, identity, asset and timestamp.",
                whatToLookFor="Original telemetry and correlated authentication, endpoint or network evidence.",
                supports=["A reproducible security event."],
                contradicts=["Missing or unreliable source evidence."],
            ),
            InvestigationStepResponse(
                order=2,
                title="Review the response playbook",
                action="Validate containment, investigation, recovery and prevention guidance against local procedures.",
                whatToLookFor="Applicable response steps and required analyst approval.",
                supports=["Guidance consistent with the incident context."],
                contradicts=["Guidance inconsistent with local policy or evidence."],
            ),
        ],
        assessment=InvestigationAssessmentResponse(
            detectionState="unknown",
            securityState="undetermined",
            verdict="UNDETERMINED",
            rationale="This API response is retrieval-derived and does not receive independent alert-state, endpoint, network, identity, or authorization telemetry. Do not treat retrieval confidence as proof of maliciousness; corroborating evidence and human review are required before assigning TP/FP/TN/FN.",
        ),
        next_evidence=[
            "Original alert/rule context",
            "Identity and source/destination information",
            "Authentication and MFA events",
            "Endpoint or application telemetry",
            "Authorization or change-ticket context",
        ],
        beginner_summary=[
            "Start with the original evidence rather than a screenshot or summary.",
            "Confirm the affected identity, asset and timestamp.",
            "Correlate surrounding telemetry before assigning a final verdict.",
        ],
    )

    store.save_analysis(response.model_dump(mode="json"))
    return response
