from __future__ import annotations

import pytest

from ra_xsoc_engine.domain.enums import SeverityLevel
from ra_xsoc_engine.domain.exceptions import AnalysisError
from ra_xsoc_engine.domain.knowledge import (
    AttackKnowledgeRecord,
    ThreatFrameworkReference,
)
from ra_xsoc_engine.playbooks.repository import (
    KnowledgeBasePlaybookRepository,
)


def build_record(
    attack_id: str = "phishing",
) -> AttackKnowledgeRecord:
    return AttackKnowledgeRecord(
        attack_id=attack_id,
        incident_type="Phishing",
        description="A phishing attack.",
        severity=SeverityLevel.HIGH,
        framework_references=(
            ThreatFrameworkReference(
                framework="MITRE ATT&CK",
                name="Phishing",
                raw_value="T1566 - Phishing",
                reference_id="T1566",
            ),
        ),
        indicators=(
            "Suspicious sender domain",
        ),
        containment=(
            "Disable the compromised account.",
        ),
        investigation=(
            "Review authentication logs.",
        ),
        recovery=(
            "Reset credentials.",
        ),
        prevention=(
            "Enable phishing-resistant MFA.",
        ),
        detection_rules=(
            "Alert on suspicious sender domains.",
        ),
        affected_assets=(
            "User account",
        ),
        source_filename="phishing.txt",
        source_sha256="a" * 64,
        source_encoding="utf-8",
    )


def test_repository_returns_playbook_from_attack_record() -> None:
    repository = KnowledgeBasePlaybookRepository(
        (build_record(),)
    )

    result = repository.get_by_attack_id("phishing")

    assert result.containment == (
        "Disable the compromised account.",
    )
    assert result.investigation == (
        "Review authentication logs.",
    )
    assert result.recovery == (
        "Reset credentials.",
    )
    assert result.prevention == (
        "Enable phishing-resistant MFA.",
    )
    assert result.detection_rules == (
        "Alert on suspicious sender domains.",
    )


def test_repository_rejects_unknown_attack_id() -> None:
    repository = KnowledgeBasePlaybookRepository(
        (build_record(),)
    )

    with pytest.raises(
        AnalysisError,
        match="No playbook exists",
    ):
        repository.get_by_attack_id("ransomware")


def test_repository_rejects_empty_attack_id() -> None:
    repository = KnowledgeBasePlaybookRepository(
        (build_record(),)
    )

    with pytest.raises(
        AnalysisError,
        match="attack_id must not be empty",
    ):
        repository.get_by_attack_id("   ")


def test_repository_rejects_duplicate_attack_ids() -> None:
    repository_records = (
        build_record("phishing"),
        build_record("phishing"),
    )

    with pytest.raises(
        AnalysisError,
        match="Duplicate playbook attack ID",
    ):
        KnowledgeBasePlaybookRepository(repository_records)


def test_repository_supports_multiple_attack_categories() -> None:
    repository = KnowledgeBasePlaybookRepository(
        (
            build_record("phishing"),
            build_record("ransomware"),
        )
    )

    phishing = repository.get_by_attack_id("phishing")
    ransomware = repository.get_by_attack_id("ransomware")

    assert phishing == ransomware