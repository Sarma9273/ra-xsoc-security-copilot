from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from ra_xsoc_api.dependencies import get_case_store
from ra_xsoc_api.schemas import CaseSummaryResponse

router = APIRouter(prefix="/api/v1/cases", tags=["cases"])

@router.get("", response_model=list[CaseSummaryResponse])
def list_cases(limit: int = 50, store=Depends(get_case_store)):
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
def get_case(analysis_id: UUID, store=Depends(get_case_store)):
    payload = store.get_analysis(analysis_id)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis case not found.")
    return payload
