
from __future__ import annotations

from ra_xsoc_engine.domain.enums import (
    NoveltyStatus,
    ReviewStatus,
    SeverityLevel,
)
from ra_xsoc_engine.domain.exceptions import (
    AnalysisError,
    DomainValidationError,
)
from ra_xsoc_engine.domain.models import (
    AnalysisResult,
    IncidentInput,
)
from ra_xsoc_engine.domain.ports import (
    AttackRetriever,
    PlaybookRepository,
)


class IncidentAnalysisService:
    """Orchestrate retrieval, confidence assessment, and response guidance."""

    def __init__(
        self,
        *,
        retriever: AttackRetriever,
        playbook_repository: PlaybookRepository,
        confidence_threshold: float = 0.70,
        model_version: str = "ra-xsoc-v2",
    ) -> None:
        if not 0.0 <= confidence_threshold <= 1.0:
            raise DomainValidationError(
                "confidence_threshold must be between 0.0 and 1.0."
            )

        if not model_version.strip():
            raise DomainValidationError(
                "model_version must not be empty."
            )

        self._retriever = retriever
        self._playbook_repository = playbook_repository
        self._confidence_threshold = confidence_threshold
        self._model_version = model_version.strip()

    def analyze(
        self,
        incident: IncidentInput,
        limit: int = 3,
    ) -> AnalysisResult:
        """Analyze one incident and return an explainable result."""

        if limit <= 0:
            raise DomainValidationError(
                "limit must be greater than zero."
            )

        try:
            matches = self._retriever.retrieve(
                incident,
                limit=limit,
            )
        except (DomainValidationError, AnalysisError):
            raise
        except Exception as error:
            raise AnalysisError(
                "Unable to retrieve attack candidates."
            ) from error

        if not matches:
            raise AnalysisError(
                "No attack candidates were returned for the incident."
            )

        primary_match = matches[0]
        alternatives = tuple(matches[1:])

        confidence = primary_match.hybrid_score

        if confidence >= self._confidence_threshold:
            novelty_status = NoveltyStatus.KNOWN
            requires_review = False
            review_status = ReviewStatus.NOT_REQUIRED
        else:
            novelty_status = NoveltyStatus.POSSIBLY_NOVEL
            requires_review = True
            review_status = ReviewStatus.PENDING

        try:
            playbook = self._playbook_repository.get_by_attack_id(
                primary_match.attack_id,
            )
        except (DomainValidationError, AnalysisError):
            raise
        except Exception as error:
            raise AnalysisError(
                "Unable to load the response playbook."
            ) from error

        explanation = self._build_explanation(
            primary_match=primary_match,
            confidence=confidence,
            novelty_status=novelty_status,
            alternatives=alternatives,
        )

        return AnalysisResult(
            incident_id=incident.incident_id,
            primary_match=primary_match,
            alternatives=alternatives,
            severity=self._derive_severity(confidence),
            novelty_status=novelty_status,
            confidence=confidence,
            playbook=playbook,
            explanation=explanation,
            requires_review=requires_review,
            model_version=self._model_version,
            review_status=review_status,
        )

    @staticmethod
    def _derive_severity(
        confidence: float,
    ) -> SeverityLevel:
        """Derive an analysis severity from confidence.

        Retrieval currently exposes confidence evidence rather than a
        severity field. Until severity propagation is added to AttackMatch,
        the analyzer uses a conservative deterministic policy.
        """

        if confidence >= 0.85:
            return SeverityLevel.HIGH

        if confidence >= 0.50:
            return SeverityLevel.MEDIUM

        return SeverityLevel.LOW

    @staticmethod
    def _build_explanation(
        *,
        primary_match: object,
        confidence: float,
        novelty_status: NoveltyStatus,
        alternatives: tuple[object, ...],
    ) -> tuple[str, ...]:
        """Build concise, deterministic analyst-facing explanations."""

        attack_id = primary_match.attack_id
        attack_name = primary_match.name

        explanations = [
            (
                f"Primary classification is {attack_name} "
                f"({attack_id}) with a hybrid retrieval score of "
                f"{confidence:.3f}."
            ),
            (
                f"The classification is assessed as "
                f"{novelty_status.value.replace('_', ' ')}."
            ),
            (
                f"Semantic evidence contributed "
                f"{primary_match.semantic_score:.3f}, while lexical "
                f"evidence contributed {primary_match.keyword_score:.3f}."
            ),
        ]

        if alternatives:
            alternative_ids = ", ".join(
                match.attack_id
                for match in alternatives
            )

            explanations.append(
                f"Alternative retrieved attack candidates: {alternative_ids}."
            )

        return tuple(explanations)
