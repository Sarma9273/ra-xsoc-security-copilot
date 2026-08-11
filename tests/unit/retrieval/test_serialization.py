import json
from pathlib import Path

import pytest
from ra_xsoc_engine.domain.enums import (
    SeverityLevel,
)
from ra_xsoc_engine.domain.exceptions import (
    KnowledgeBaseError,
)
from ra_xsoc_engine.domain.retrieval import (
    RetrievalDocument,
)
from ra_xsoc_engine.knowledge_base import (
    NormalizedKnowledgeBaseRepository,
)
from ra_xsoc_engine.retrieval import (
    write_retrieval_corpus,
)


def build_document(
    attack_id: str,
) -> RetrievalDocument:
    return RetrievalDocument(
        document_id=(f"retrieval:{attack_id}:1.0"),
        attack_id=attack_id,
        title=attack_id.upper(),
        retrieval_text=(f"INCIDENT TYPE:\n{attack_id.upper()}\n"),
        severity=SeverityLevel.HIGH,
        framework_labels=("MITRE ATT&CK | T1566 | Phishing",),
        source_filename=(f"{attack_id}.txt"),
        source_record_sha256="a" * 64,
        content_sha256="b" * 64,
        knowledge_schema_version="1.0",
    )


def normalized_payload(
    attack_id: str,
) -> dict[str, object]:
    return {
        "attack_id": attack_id,
        "incident_type": attack_id.upper(),
        "description": "Example attack description.",
        "severity": "high",
        "framework_references": [
            {
                "framework": "MITRE ATT&CK",
                "name": "Phishing",
                "raw_value": "T1566 - Phishing",
                "reference_id": "T1566",
            }
        ],
        "indicators": ["Suspicious indicator"],
        "containment": ["Contain the incident"],
        "investigation": ["Investigate the incident"],
        "recovery": ["Recover the system"],
        "prevention": ["Prevent recurrence"],
        "detection_rules": ["Detection rule"],
        "affected_assets": ["User account"],
        "references": [],
        "tools": [],
        "real_world_examples": [],
        "keywords": [],
        "source_filename": f"{attack_id}.txt",
        "source_sha256": "a" * 64,
        "source_encoding": "utf-8",
        "schema_version": "1.0",
    }


def test_normalized_repository_loads_record(
    tmp_path: Path,
) -> None:
    payload = normalized_payload("phishing")

    (tmp_path / "phishing.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    records = NormalizedKnowledgeBaseRepository(tmp_path).load_all()

    assert len(records) == 1

    assert records[0].attack_id == "phishing"


def test_normalized_repository_rejects_missing_dir(
    tmp_path: Path,
) -> None:
    missing_directory = tmp_path / "missing"

    with pytest.raises(
        KnowledgeBaseError,
        match="does not exist",
    ):
        (NormalizedKnowledgeBaseRepository(missing_directory).load_all())


def test_normalized_repository_rejects_bad_json(
    tmp_path: Path,
) -> None:
    (tmp_path / "broken.json").write_text(
        "{invalid-json",
        encoding="utf-8",
    )

    with pytest.raises(
        KnowledgeBaseError,
        match="Invalid JSON",
    ):
        (NormalizedKnowledgeBaseRepository(tmp_path).load_all())


def test_serialization_writes_document_files(
    tmp_path: Path,
) -> None:
    documents = (
        build_document("phishing"),
        build_document("ransomware"),
    )

    corpus_path, manifest_path = write_retrieval_corpus(
        documents,
        tmp_path,
        "c" * 64,
    )

    assert corpus_path.exists()
    assert manifest_path.exists()

    assert (tmp_path / "phishing.json").exists()

    assert (tmp_path / "ransomware.json").exists()


def test_jsonl_contains_one_line_per_document(
    tmp_path: Path,
) -> None:
    documents = (
        build_document("phishing"),
        build_document("ransomware"),
    )

    corpus_path, _ = write_retrieval_corpus(
        documents,
        tmp_path,
        "c" * 64,
    )

    lines = corpus_path.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 2

    payloads = [json.loads(line) for line in lines]

    assert [payload["attack_id"] for payload in payloads] == [
        "phishing",
        "ransomware",
    ]


def test_manifest_contains_checksum_and_count(
    tmp_path: Path,
) -> None:
    documents = (build_document("phishing"),)

    _, manifest_path = write_retrieval_corpus(
        documents,
        tmp_path,
        "c" * 64,
    )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["document_count"] == 1

    assert manifest["corpus_checksum"] == "c" * 64
