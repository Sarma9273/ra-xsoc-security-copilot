from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from .enums import (
    IncidentSource,
    NoveltyStatus,
    ReviewStatus,
    SeverityLevel,
)
from .exceptions import DomainValidationError


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(UTC)


def validate_non_empty(
    value: str,
    field_name: str,
) -> str:
    """Validate and normalise a required text value."""

    cleaned = value.strip()

    if not cleaned:
        raise DomainValidationError(f"{field_name} must not be empty.")

    return cleaned


def validate_score(
    value: float,
    field_name: str,
) -> float:
    """Ensure a score remains between zero and one."""

    if not 0.0 <= value <= 1.0:
        raise DomainValidationError(f"{field_name} must be between 0.0 and 1.0. Received: {value}")

    return float(value)


@dataclass(frozen=True, slots=True)
class MitreTechnique:
    """A MITRE ATT&CK technique connected to an attack category."""

    technique_id: str
    name: str
    tactic: str | None = None
    url: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "technique_id",
            validate_non_empty(
                self.technique_id,
                "technique_id",
            ),
        )

        object.__setattr__(
            self,
            "name",
            validate_non_empty(
                self.name,
                "name",
            ),
        )

        if not self.technique_id.upper().startswith("T"):
            raise DomainValidationError("MITRE technique_id must begin with 'T'.")


@dataclass(frozen=True, slots=True)
class AttackMatch:
    """A candidate attack returned by the retrieval engine."""

    attack_id: str
    name: str
    semantic_score: float
    keyword_score: float
    hybrid_score: float
    mitre_techniques: tuple[MitreTechnique, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "attack_id",
            validate_non_empty(
                self.attack_id,
                "attack_id",
            ),
        )

        object.__setattr__(
            self,
            "name",
            validate_non_empty(
                self.name,
                "name",
            ),
        )

        object.__setattr__(
            self,
            "semantic_score",
            validate_score(
                self.semantic_score,
                "semantic_score",
            ),
        )

        object.__setattr__(
            self,
            "keyword_score",
            validate_score(
                self.keyword_score,
                "keyword_score",
            ),
        )

        object.__setattr__(
            self,
            "hybrid_score",
            validate_score(
                self.hybrid_score,
                "hybrid_score",
            ),
        )


@dataclass(frozen=True, slots=True)
class ResponsePlaybook:
    """Structured response guidance for an incident type."""

    containment: tuple[str, ...] = ()
    investigation: tuple[str, ...] = ()
    recovery: tuple[str, ...] = ()
    prevention: tuple[str, ...] = ()
    detection_rules: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        all_sections = (
            self.containment,
            self.investigation,
            self.recovery,
            self.prevention,
            self.detection_rules,
        )

        for section in all_sections:
            for item in section:
                if not item.strip():
                    raise DomainValidationError("Playbook steps must not contain empty values.")


@dataclass(frozen=True, slots=True)
class IncidentInput:
    """Unstructured incident submitted for analysis."""

    description: str
    source: IncidentSource = IncidentSource.MANUAL
    incident_id: UUID = field(default_factory=uuid4)
    submitted_at: datetime = field(default_factory=utc_now)
    external_reference: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "description",
            validate_non_empty(
                self.description,
                "description",
            ),
        )

        if len(self.description) > 20_000:
            raise DomainValidationError("Incident description exceeds the 20,000-character limit.")

        if self.submitted_at.tzinfo is None:
            raise DomainValidationError("submitted_at must be timezone aware.")


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Complete explainable result returned by RA-XSOC."""

    incident_id: UUID
    primary_match: AttackMatch
    alternatives: tuple[AttackMatch, ...]
    severity: SeverityLevel
    novelty_status: NoveltyStatus
    confidence: float
    playbook: ResponsePlaybook
    explanation: tuple[str, ...]
    requires_review: bool
    model_version: str
    analysis_id: UUID = field(default_factory=uuid4)
    review_status: ReviewStatus = ReviewStatus.NOT_REQUIRED
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "confidence",
            validate_score(
                self.confidence,
                "confidence",
            ),
        )

        object.__setattr__(
            self,
            "model_version",
            validate_non_empty(
                self.model_version,
                "model_version",
            ),
        )

        if self.created_at.tzinfo is None:
            raise DomainValidationError("created_at must be timezone aware.")

        if self.requires_review and self.review_status is ReviewStatus.NOT_REQUIRED:
            object.__setattr__(
                self,
                "review_status",
                ReviewStatus.PENDING,
            )

        if not self.explanation:
            raise DomainValidationError("AnalysisResult must include at least one explanation.")


@dataclass(frozen=True, slots=True)
class AnalystFeedback:
    """Human approval, correction, or rejection."""

    analysis_id: UUID
    analyst_id: UUID
    status: ReviewStatus
    comments: str
    corrected_attack_id: str | None = None
    feedback_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "comments",
            validate_non_empty(
                self.comments,
                "comments",
            ),
        )

        allowed_statuses = {
            ReviewStatus.APPROVED,
            ReviewStatus.CORRECTED,
            ReviewStatus.REJECTED,
        }

        if self.status not in allowed_statuses:
            raise DomainValidationError("Feedback status must be approved, corrected, or rejected.")

        if self.status is ReviewStatus.CORRECTED and not self.corrected_attack_id:
            raise DomainValidationError("corrected_attack_id is required when status is corrected.")
