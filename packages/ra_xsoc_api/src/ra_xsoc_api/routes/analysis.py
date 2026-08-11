from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from ra_xsoc_engine.domain.exceptions import (
    AnalysisError,
    DomainValidationError,
)
from ra_xsoc_engine.domain.models import IncidentInput

from ra_xsoc_api.dependencies import get_application
from ra_xsoc_api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    AttackMatchResponse,
    MitreTechniqueResponse,
    ResponsePlaybookResponse,
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

    return AnalyzeResponse(
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
    )