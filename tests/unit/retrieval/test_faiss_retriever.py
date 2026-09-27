from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import faiss
import numpy as np
import pytest
from ra_xsoc_engine.domain.exceptions import (
    DomainValidationError,
)
from ra_xsoc_engine.domain.models import (
    IncidentInput,
)
from ra_xsoc_engine.retrieval import (
    FAISSAttackRetriever,
)


def build_artifacts(
    tmp_path: Path,
) -> tuple[Path, Path]:
    artifact_directory = tmp_path / "artifacts"
    corpus_directory = tmp_path / "corpus"

    artifact_directory.mkdir()
    corpus_directory.mkdir()

    vectors = np.asarray(
        [
            [1.0, 0.0, 0.0],
            [0.0, 1.0, 0.0],
        ],
        dtype=np.float32,
    )

    index = faiss.IndexFlatIP(3)
    index.add(vectors)

    faiss.write_index(
        index,
        str(artifact_directory / "index.faiss"),
    )

    (artifact_directory / "document_mapping.json").write_text(
        json.dumps(
            {
                "0": "retrieval:phishing:1.0",
                "1": "retrieval:ransomware:1.0",
            }
        ),
        encoding="utf-8",
    )

    documents = (
        {
            "document_id": "retrieval:phishing:1.0",
            "attack_id": "phishing",
            "title": "PHISHING",
            "framework_labels": [
                "MITRE ATT&CK | T1566 | Phishing",
            ],
        },
        {
            "document_id": "retrieval:ransomware:1.0",
            "attack_id": "ransomware",
            "title": "RANSOMWARE",
            "framework_labels": [
                "MITRE ATT&CK | T1486 | Data Encrypted for Impact",
            ],
        },
    )

    for document in documents:
        (corpus_directory / f"{document['attack_id']}.json").write_text(
            json.dumps(document),
            encoding="utf-8",
        )

    return artifact_directory, corpus_directory


def build_embedding_service(
    vector: tuple[float, ...],
) -> Mock:
    service = Mock()
    service.embed.return_value = (vector,)
    return service


def test_retriever_returns_top_match(
    tmp_path: Path,
) -> None:
    artifact_directory, corpus_directory = build_artifacts(
        tmp_path,
    )

    embedding_service = build_embedding_service(
        (1.0, 0.0, 0.0),
    )

    retriever = FAISSAttackRetriever(
        artifact_directory=artifact_directory,
        corpus_directory=corpus_directory,
        embedding_service=embedding_service,
    )

    matches = retriever.retrieve(
        IncidentInput(
            description="A suspicious email attempts to steal credentials.",
        ),
        limit=1,
    )

    assert len(matches) == 1
    assert matches[0].attack_id == "phishing"
    assert matches[0].name == "PHISHING"
    assert matches[0].semantic_score == pytest.approx(1.0)


def test_retriever_returns_requested_number_of_matches(
    tmp_path: Path,
) -> None:
    artifact_directory, corpus_directory = build_artifacts(
        tmp_path,
    )

    embedding_service = build_embedding_service(
        (1.0, 0.0, 0.0),
    )

    retriever = FAISSAttackRetriever(
        artifact_directory=artifact_directory,
        corpus_directory=corpus_directory,
        embedding_service=embedding_service,
    )

    matches = retriever.retrieve(
        IncidentInput(
            description="Suspicious activity.",
        ),
        limit=2,
    )

    assert len(matches) == 2
    assert [match.attack_id for match in matches] == [
        "phishing",
        "ransomware",
    ]


def test_retriever_extracts_mitre_technique(
    tmp_path: Path,
) -> None:
    artifact_directory, corpus_directory = build_artifacts(
        tmp_path,
    )

    embedding_service = build_embedding_service(
        (1.0, 0.0, 0.0),
    )

    retriever = FAISSAttackRetriever(
        artifact_directory=artifact_directory,
        corpus_directory=corpus_directory,
        embedding_service=embedding_service,
    )

    matches = retriever.retrieve(
        IncidentInput(
            description="Phishing incident.",
        ),
        limit=1,
    )

    assert len(matches[0].mitre_techniques) == 1
    assert matches[0].mitre_techniques[0].technique_id == "T1566"


def test_retriever_rejects_non_positive_limit(
    tmp_path: Path,
) -> None:
    artifact_directory, corpus_directory = build_artifacts(
        tmp_path,
    )

    embedding_service = build_embedding_service(
        (1.0, 0.0, 0.0),
    )

    retriever = FAISSAttackRetriever(
        artifact_directory=artifact_directory,
        corpus_directory=corpus_directory,
        embedding_service=embedding_service,
    )

    with pytest.raises(
        DomainValidationError,
        match="limit",
    ):
        retriever.retrieve(
            IncidentInput(
                description="Incident.",
            ),
            limit=0,
        )


def test_retriever_rejects_missing_index(
    tmp_path: Path,
) -> None:
    artifact_directory = tmp_path / "artifacts"
    corpus_directory = tmp_path / "corpus"

    artifact_directory.mkdir()
    corpus_directory.mkdir()

    embedding_service = build_embedding_service(
        (1.0, 0.0, 0.0),
    )

    with pytest.raises(
        DomainValidationError,
        match="FAISS index does not exist",
    ):
        FAISSAttackRetriever(
            artifact_directory=artifact_directory,
            corpus_directory=corpus_directory,
            embedding_service=embedding_service,
        )


def test_retriever_rejects_mapping_count_mismatch(
    tmp_path: Path,
) -> None:
    artifact_directory, corpus_directory = build_artifacts(
        tmp_path,
    )

    (artifact_directory / "document_mapping.json").write_text(
        json.dumps(
            {
                "0": "retrieval:phishing:1.0",
            }
        ),
        encoding="utf-8",
    )

    embedding_service = build_embedding_service(
        (1.0, 0.0, 0.0),
    )

    with pytest.raises(
        DomainValidationError,
        match="count",
    ):
        FAISSAttackRetriever(
            artifact_directory=artifact_directory,
            corpus_directory=corpus_directory,
            embedding_service=embedding_service,
        )

def test_retriever_populates_and_uses_keyword_score(
    tmp_path: Path,
) -> None:
    artifact_directory, corpus_directory = build_artifacts(tmp_path)
    documents = {
        "document_id": "retrieval:phishing:1.0",
        "attack_id": "phishing",
        "title": "PHISHING",
        "retrieval_text": "suspicious email credential phishing login",
        "framework_labels": [],
    }
    (corpus_directory / "phishing.json").write_text(
        json.dumps(documents),
        encoding="utf-8",
    )
    (corpus_directory / "ransomware.json").write_text(
        json.dumps({
            "document_id": "retrieval:ransomware:1.0",
            "attack_id": "ransomware",
            "title": "RANSOMWARE",
            "retrieval_text": "encrypted files impact",
            "framework_labels": [],
        }),
        encoding="utf-8",
    )
    retriever = FAISSAttackRetriever(
        artifact_directory=artifact_directory,
        corpus_directory=corpus_directory,
        embedding_service=build_embedding_service((1.0, 0.0, 0.0)),
    )
    matches = retriever.retrieve(
        IncidentInput(description="suspicious email credential phishing"),
        limit=2,
    )
    assert matches[0].keyword_score > 0.0
    assert matches[0].hybrid_score == pytest.approx(
        0.7 * matches[0].semantic_score + 0.3 * matches[0].keyword_score
    )
