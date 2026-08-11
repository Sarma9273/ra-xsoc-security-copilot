from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    description: str = Field(
        ...,
        min_length=1,
        max_length=20_000,
        description="Unstructured security incident description.",
    )
    incident_id: UUID | None = Field(
        default=None,
        description="Optional incident identifier.",
    )
    external_reference: str | None = Field(
        default=None,
        description="Optional external incident reference.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional incident metadata.",
    )


class MitreTechniqueResponse(BaseModel):
    technique_id: str
    name: str
    tactic: str | None = None
    url: str | None = None


class AttackMatchResponse(BaseModel):
    attack_id: str
    name: str
    semantic_score: float
    keyword_score: float
    hybrid_score: float
    mitre_techniques: list[MitreTechniqueResponse]


class ResponsePlaybookResponse(BaseModel):
    containment: list[str]
    investigation: list[str]
    recovery: list[str]
    prevention: list[str]
    detection_rules: list[str]


class AnalyzeResponse(BaseModel):
    analysis_id: UUID
    incident_id: UUID
    primary_match: AttackMatchResponse
    alternatives: list[AttackMatchResponse]
    severity: str
    novelty_status: str
    confidence: float
    playbook: ResponsePlaybookResponse
    explanation: list[str]
    requires_review: bool
    model_version: str
    review_status: str
    created_at: str