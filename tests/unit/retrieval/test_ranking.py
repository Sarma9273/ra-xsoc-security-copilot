from __future__ import annotations

import pytest
from ra_xsoc_engine.domain.exceptions import DomainValidationError
from ra_xsoc_engine.domain.models import AttackMatch
from ra_xsoc_engine.retrieval.ranking import (
    HybridRanker,
    KeywordScorer,
)


def build_match(
    attack_id: str,
    semantic_score: float,
) -> AttackMatch:
    return AttackMatch(
        attack_id=attack_id,
        name=attack_id.upper(),
        semantic_score=semantic_score,
        keyword_score=0.0,
        hybrid_score=semantic_score,
    )


def test_keyword_scorer_detects_token_overlap() -> None:
    scorer = KeywordScorer()

    score = scorer.score(
        "suspicious phishing email credential theft",
        "phishing email credential theft",
    )

    assert score == pytest.approx(0.8)


def test_keyword_scorer_is_case_insensitive() -> None:
    scorer = KeywordScorer()

    score = scorer.score(
        "PHISHING EMAIL",
        "phishing email",
    )

    assert score == pytest.approx(1.0)


def test_keyword_scorer_returns_zero_without_overlap() -> None:
    scorer = KeywordScorer()

    score = scorer.score(
        "database backup",
        "phishing email",
    )

    assert score == 0.0


@pytest.mark.parametrize(
    "incident_text,candidate_text",
    [
        ("", "phishing"),
        ("   ", "phishing"),
        ("phishing", ""),
        ("phishing", "   "),
    ],
)
def test_keyword_scorer_rejects_empty_text(
    incident_text: str,
    candidate_text: str,
) -> None:
    scorer = KeywordScorer()

    with pytest.raises(
        DomainValidationError,
        match="must not be empty",
    ):
        scorer.score(
            incident_text,
            candidate_text,
        )


def test_hybrid_ranker_combines_scores() -> None:
    ranker = HybridRanker(
        semantic_weight=0.7,
        keyword_weight=0.3,
    )

    result = ranker.rank(
        (
            build_match(
                "phishing",
                0.8,
            ),
        ),
        (0.6,),
    )

    assert result[0].semantic_score == pytest.approx(0.8)
    assert result[0].keyword_score == pytest.approx(0.6)
    assert result[0].hybrid_score == pytest.approx(0.74)


def test_hybrid_ranker_orders_by_hybrid_score() -> None:
    ranker = HybridRanker()

    result = ranker.rank(
        (
            build_match(
                "phishing",
                0.70,
            ),
            build_match(
                "ransomware",
                0.80,
        ),
        ),
        (
            1.0,
            0.1,
        ),
    )

    assert [match.attack_id for match in result] == [
        "phishing",
        "ransomware",
    ]


def test_hybrid_ranker_uses_attack_id_as_final_tiebreaker() -> None:
    ranker = HybridRanker()

    result = ranker.rank(
        (
            build_match(
                "ransomware",
                0.8,
            ),
            build_match(
                "phishing",
                0.8,
            ),
        ),
        (
            0.5,
            0.5,
        ),
    )

    assert [match.attack_id for match in result] == [
        "phishing",
        "ransomware",
    ]


def test_hybrid_ranker_rejects_mismatched_lengths() -> None:
    ranker = HybridRanker()

    with pytest.raises(
        DomainValidationError,
        match="number of matches",
    ):
        ranker.rank(
            (
                build_match(
                    "phishing",
                    0.8,
                ),
            ),
            (),
        )


def test_hybrid_ranker_rejects_invalid_keyword_score() -> None:
    ranker = HybridRanker()

    with pytest.raises(
        DomainValidationError,
        match="between 0.0 and 1.0",
    ):
        ranker.rank(
            (
                build_match(
                    "phishing",
                    0.8,
                ),
            ),
            (1.5,),
        )


def test_hybrid_ranker_normalizes_weights() -> None:
    ranker = HybridRanker(
        semantic_weight=7.0,
        keyword_weight=3.0,
    )

    result = ranker.rank(
        (
            build_match(
                "phishing",
                1.0,
            ),
        ),
        (0.0,),
    )

    assert result[0].hybrid_score == pytest.approx(0.7)