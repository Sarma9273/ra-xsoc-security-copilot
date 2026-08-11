from __future__ import annotations

import re
from collections.abc import Sequence

from ra_xsoc_engine.domain.exceptions import DomainValidationError
from ra_xsoc_engine.domain.models import AttackMatch

_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")


class KeywordScorer:
    """Calculate lexical overlap between incident text and attack signals."""

    def score(
        self,
        incident_text: str,
        candidate_text: str,
    ) -> float:
        if not incident_text.strip():
            raise DomainValidationError(
                "incident_text must not be empty."
            )

        if not candidate_text.strip():
            raise DomainValidationError(
                "candidate_text must not be empty."
            )

        incident_tokens = self._tokens(incident_text)
        candidate_tokens = self._tokens(candidate_text)

        if not incident_tokens or not candidate_tokens:
            return 0.0

        overlap = incident_tokens.intersection(candidate_tokens)

        return len(overlap) / len(incident_tokens)

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return set(
            _TOKEN_PATTERN.findall(
                text.lower(),
            )
        )


class HybridRanker:
    """Combine semantic and keyword evidence into a bounded score."""

    def __init__(
        self,
        *,
        semantic_weight: float = 0.7,
        keyword_weight: float = 0.3,
    ) -> None:
        if semantic_weight < 0.0:
            raise DomainValidationError(
                "semantic_weight must not be negative."
            )

        if keyword_weight < 0.0:
            raise DomainValidationError(
                "keyword_weight must not be negative."
            )

        total = semantic_weight + keyword_weight

        if total <= 0.0:
            raise DomainValidationError(
                "At least one ranking weight must be greater than zero."
            )

        self._semantic_weight = semantic_weight / total
        self._keyword_weight = keyword_weight / total

    def rank(
        self,
        matches: Sequence[AttackMatch],
        keyword_scores: Sequence[float],
    ) -> tuple[AttackMatch, ...]:
        if len(matches) != len(keyword_scores):
            raise DomainValidationError(
                "The number of matches must equal the number of keyword scores."
            )

        ranked: list[AttackMatch] = []

        for match, keyword_score in zip(
            matches,
            keyword_scores,
            strict=True,
        ):
            if not 0.0 <= keyword_score <= 1.0:
                raise DomainValidationError(
                    "keyword_score must be between 0.0 and 1.0."
                )

            hybrid_score = (
                self._semantic_weight * match.semantic_score
                + self._keyword_weight * keyword_score
            )

            ranked.append(
                AttackMatch(
                    attack_id=match.attack_id,
                    name=match.name,
                    semantic_score=match.semantic_score,
                    keyword_score=keyword_score,
                    hybrid_score=hybrid_score,
                    mitre_techniques=match.mitre_techniques,
                )
            )

        ranked.sort(
            key=lambda match: (
                -match.hybrid_score,
                -match.semantic_score,
                match.attack_id,
            )
        )

        return tuple(ranked)