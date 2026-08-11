from collections.abc import Sequence
from typing import Protocol

from .models import (
    AnalysisResult,
    AnalystFeedback,
    AttackMatch,
    IncidentInput,
    ResponsePlaybook,
)


class EmbeddingService(Protocol):
    """Converts text into numerical embedding vectors."""

    def embed(
        self,
        texts: Sequence[str],
    ) -> Sequence[Sequence[float]]: ...


class AttackRetriever(Protocol):
    """Retrieves probable attacks for an incident."""

    def retrieve(
        self,
        incident: IncidentInput,
        limit: int = 3,
    ) -> tuple[AttackMatch, ...]: ...


class PlaybookRepository(Protocol):
    """Provides playbooks for attack categories."""

    def get_by_attack_id(
        self,
        attack_id: str,
    ) -> ResponsePlaybook: ...


class IncidentAnalyzer(Protocol):
    """Runs the complete analysis workflow."""

    def analyze(
        self,
        incident: IncidentInput,
    ) -> AnalysisResult: ...


class FeedbackRepository(Protocol):
    """Stores analyst feedback."""

    def save(
        self,
        feedback: AnalystFeedback,
    ) -> None: ...
