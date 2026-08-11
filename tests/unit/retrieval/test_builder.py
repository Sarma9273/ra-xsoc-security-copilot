from hashlib import sha256

import pytest
from ra_xsoc_engine.domain.enums import (
    SeverityLevel,
)
from ra_xsoc_engine.domain.exceptions import (
    DomainValidationError,
)
from ra_xsoc_engine.domain.knowledge import (
    AttackKnowledgeRecord,
    ThreatFrameworkReference,
)
from ra_xsoc_engine.retrieval import (
    RetrievalCorpusBuilder,
)


def build_sample_record(
    *,
    attack_id: str = "phishing",
    incident_type: str = "PHISHING",
    description: str = ("A deceptive message attempts to steal user credentials."),
) -> AttackKnowledgeRecord:
    return AttackKnowledgeRecord(
        attack_id=attack_id,
        incident_type=incident_type,
        description=description,
        severity=SeverityLevel.HIGH,
        framework_references=(
            ThreatFrameworkReference(
                framework="MITRE ATT&CK",
                reference_id="T1566",
                name="Phishing",
                raw_value="T1566 - Phishing",
            ),
        ),
        indicators=(
            "Suspicious sender domain",
            "Credential-harvesting page",
        ),
        containment=("containment-secret-value",),
        investigation=("investigation-secret-value",),
        recovery=("recovery-secret-value",),
        prevention=("prevention-secret-value",),
        detection_rules=("Alert on lookalike domains",),
        affected_assets=("User email accounts",),
        references=("reference-secret-value",),
        tools=("tool-secret-value",),
        real_world_examples=("example-secret-value",),
        keywords=("keyword-secret-value",),
        source_filename=(f"{attack_id}.txt"),
        source_sha256="a" * 64,
        source_encoding="utf-8",
    )


def test_builder_creates_document() -> None:
    builder = RetrievalCorpusBuilder()

    document = builder.build_document(build_sample_record())

    assert document.attack_id == "phishing"

    assert document.document_id == ("retrieval:phishing:1.0")

    assert document.title == "PHISHING"


def test_retrieval_text_contains_signals() -> None:
    builder = RetrievalCorpusBuilder()

    document = builder.build_document(build_sample_record())

    assert "PHISHING" in document.retrieval_text

    assert "Suspicious sender domain" in document.retrieval_text

    assert "Alert on lookalike domains" in document.retrieval_text

    assert "T1566" in document.retrieval_text


def test_retrieval_text_excludes_playbook() -> None:
    builder = RetrievalCorpusBuilder()

    document = builder.build_document(build_sample_record())

    excluded_values = (
        "containment-secret-value",
        "investigation-secret-value",
        "recovery-secret-value",
        "prevention-secret-value",
        "reference-secret-value",
        "tool-secret-value",
        "example-secret-value",
        "keyword-secret-value",
    )

    for value in excluded_values:
        assert value not in document.retrieval_text


def test_document_generation_is_deterministic() -> None:
    builder = RetrievalCorpusBuilder()
    record = build_sample_record()

    first = builder.build_document(record)
    second = builder.build_document(record)

    assert first.retrieval_text == second.retrieval_text

    assert first.content_sha256 == second.content_sha256


def test_corpus_is_sorted_by_attack_id() -> None:
    builder = RetrievalCorpusBuilder()

    records = (
        build_sample_record(
            attack_id="ransomware",
            incident_type="RANSOMWARE",
        ),
        build_sample_record(
            attack_id="phishing",
            incident_type="PHISHING",
        ),
    )

    documents = builder.build_corpus(records)

    assert [document.attack_id for document in documents] == [
        "phishing",
        "ransomware",
    ]


def test_duplicate_attack_id_is_rejected() -> None:
    builder = RetrievalCorpusBuilder()

    records = (
        build_sample_record(),
        build_sample_record(),
    )

    with pytest.raises(
        DomainValidationError,
        match="Duplicate attack_id",
    ):
        builder.build_corpus(records)


def test_corpus_checksum_is_order_independent() -> None:
    builder = RetrievalCorpusBuilder()

    first = builder.build_document(
        build_sample_record(
            attack_id="phishing",
            incident_type="PHISHING",
        )
    )

    second = builder.build_document(
        build_sample_record(
            attack_id="ransomware",
            incident_type="RANSOMWARE",
        )
    )

    forward_checksum = builder.corpus_checksum((first, second))

    reverse_checksum = builder.corpus_checksum((second, first))

    assert forward_checksum == reverse_checksum


def test_content_change_changes_checksum() -> None:
    builder = RetrievalCorpusBuilder()

    first = builder.build_document(
        build_sample_record(description=("A fake email steals credentials."))
    )

    second = builder.build_document(
        build_sample_record(description=("A fake website steals credentials."))
    )

    assert first.content_sha256 != second.content_sha256


def test_content_checksum_matches_stored_retrieval_text() -> None:
    """Checksum must match the exact text stored in the document."""

    builder = RetrievalCorpusBuilder()

    document = builder.build_document(build_sample_record())

    recalculated_checksum = sha256(document.retrieval_text.encode("utf-8")).hexdigest()

    assert document.content_sha256 == recalculated_checksum

    assert document.retrieval_text == document.retrieval_text.strip()
