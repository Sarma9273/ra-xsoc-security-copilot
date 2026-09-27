from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    description: str = Field(..., min_length=1, max_length=20_000)
    incident_id: UUID | None = None
    external_reference: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


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


class EvidenceItemResponse(BaseModel):
    id: str
    text: str
    type: str
    source: str
    strength: float


class HypothesisResponse(BaseModel):
    id: str
    name: str
    category: str
    score: float
    status: str
    supporting: list[str]
    contradicting: list[str]
    missing: list[str]
    techniques: list[MitreTechniqueResponse]


class IncidentIdentityResponse(BaseModel):
    name: str
    attack_family: str
    stage: str
    confidence: float
    description: str


class NoveltyAssessmentResponse(BaseModel):
    score: float
    status: str
    known_similarity: float
    behavior_coverage: float
    unseen_signal_ratio: float
    combination_novelty: float
    reasons: list[str]


class InvestigationQuestionResponse(BaseModel):
    id: str
    question: str
    evidenceType: str
    informationGain: float
    distinguishes: list[str]


class ResearchEvaluationResponse(BaseModel):
    planner: list[InvestigationQuestionResponse]
    experience_adjustment: float = 0.0
    feature_vector: list[str]
    matched_pattern_ids: list[str]
    unmatched_features: list[str]
    hypothesis_count: int
    technique_count: int
    reproducible: bool
    evaluation_version: str


class SourceVerificationResponse(BaseModel):
    source: str
    status: str
    version: str | None = None
    details: str
    url: str


class InvestigationStepResponse(BaseModel):
    order: int
    title: str
    action: str
    whatToLookFor: str
    supports: list[str]
    contradicts: list[str]


class InvestigationAssessmentResponse(BaseModel):
    detectionState: str
    securityState: str
    verdict: str
    rationale: str


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
    incident: IncidentIdentityResponse
    novelty: NoveltyAssessmentResponse
    research: ResearchEvaluationResponse
    evidence: list[EvidenceItemResponse]
    hypotheses: list[HypothesisResponse]
    verification: list[SourceVerificationResponse]
    investigation: list[InvestigationStepResponse]
    assessment: InvestigationAssessmentResponse
    next_evidence: list[str]
    beginner_summary: list[str]


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: list[dict[str, Any]] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    error: ErrorDetail
    request_id: str


class CaseSummaryResponse(BaseModel):
    analysis_id: UUID
    incident_id: UUID
    review_status: str
    created_at: str
    primary_attack_id: str
    primary_attack_name: str
    confidence: float
