from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from ra_xsoc_api.dependencies import get_case_store
from ra_xsoc_api.auth import AuthenticatedUser, require_roles
from ra_xsoc_engine.domain.enums import ReviewStatus, UserRole
from ra_xsoc_engine.domain.models import AnalystFeedback
from ra_xsoc_api.schemas import FeedbackRequest, FeedbackResponse
from ra_xsoc_api.schemas import CaseSummaryResponse

router = APIRouter(prefix="/api/v1/cases", tags=["cases"])

@router.get("", response_model=list[CaseSummaryResponse])
def list_cases(limit: int = 50, store=Depends(get_case_store), user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.REVIEWER, UserRole.VIEWER))):
    return [CaseSummaryResponse(**{
        "analysis_id": item["analysis_id"],
        "incident_id": item["incident_id"],
        "review_status": item["review_status"],
        "created_at": item["created_at"],
        "primary_attack_id": item["primary_match"]["attack_id"],
        "primary_attack_name": item["primary_match"]["name"],
        "confidence": item["confidence"],
    }) for item in store.list_cases(limit)]

@router.get("/{analysis_id}", response_model=dict)
def get_case(analysis_id: UUID, store=Depends(get_case_store), user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.REVIEWER, UserRole.VIEWER))):
    payload = store.get_analysis(analysis_id)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis case not found.")
    return payload


@router.post("/{analysis_id}/feedback", response_model=FeedbackResponse)
def submit_feedback(
    analysis_id: UUID,
    request: FeedbackRequest,
    store=Depends(get_case_store),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.REVIEWER)),
):
    payload = store.get_analysis(analysis_id)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis case not found.")

    feedback = AnalystFeedback(
        analysis_id=analysis_id,
        analyst_id=user.user_id,
        status=ReviewStatus(request.status),
        comments=request.comments,
        corrected_attack_id=request.corrected_attack_id,
    )
    store.update_review_status(analysis_id, feedback.status.value)
    store.save_feedback({
        "feedback_id": feedback.feedback_id,
        "analysis_id": feedback.analysis_id,
        "analyst_id": feedback.analyst_id,
        "status": feedback.status.value,
        "comments": feedback.comments,
        "corrected_attack_id": feedback.corrected_attack_id,
        "created_at": feedback.created_at.isoformat(),
    })
    return FeedbackResponse(
        feedback_id=feedback.feedback_id,
        analysis_id=feedback.analysis_id,
        analyst_id=feedback.analyst_id,
        status=feedback.status.value,
        comments=feedback.comments,
        corrected_attack_id=feedback.corrected_attack_id,
        created_at=feedback.created_at.isoformat(),
    )
