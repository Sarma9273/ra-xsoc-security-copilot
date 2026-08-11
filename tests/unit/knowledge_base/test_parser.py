from hashlib import sha256
from pathlib import Path

import pytest
from ra_xsoc_engine.domain.enums import (
    SeverityLevel,
)
from ra_xsoc_engine.domain.exceptions import (
    KnowledgeBaseError,
)
from ra_xsoc_engine.knowledge_base import (
    FileKnowledgeBaseRepository,
    TxtKnowledgeBaseParser,
    write_normalized_records,
)

BASE_RECORD = """
INCIDENT TYPE: PHISHING
Description:
A deceptive email attempts to steal credentials.
MITRE ATT&CK:
T1566 – Phishing
Severity:
High
Indicators:
- Suspicious sender domain
Containment:
- Block the sender
Investigation:
- Review mail headers
Recovery:
- Reset exposed credentials
Prevention:
- Enable phishing-resistant MFA
Detection Rules:
- Alert on lookalike domains
Affected Assets:
- User accounts
References:
- Internal SOC playbook
"""


def parse_text(
    text: str = BASE_RECORD,
):
    parser = TxtKnowledgeBaseParser()

    digest = sha256(text.encode("utf-8")).hexdigest()

    return parser.parse_text(
        text,
        attack_id="phishing",
        source_filename="phishing.txt",
        source_sha256=digest,
    )


def test_parser_parses_standard_record() -> None:
    record = parse_text()

    assert record.attack_id == "phishing"
    assert record.incident_type == "PHISHING"
    assert record.severity is SeverityLevel.HIGH

    assert record.framework_references[0].reference_id == "T1566"

    assert record.indicators == ("Suspicious sender domain",)


def test_parser_parses_mitre_subtechnique() -> None:
    text = BASE_RECORD.replace(
        "T1566 – Phishing",
        "T1110.004 – Credential Stuffing",
    )

    record = parse_text(text)

    assert record.framework_references[0].reference_id == "T1110.004"


def test_parser_accepts_emerging_ai_threat() -> None:
    text = BASE_RECORD.replace(
        "T1566 – Phishing",
        "Emerging AI Threat",
    )

    record = parse_text(text)
    reference = record.framework_references[0]

    assert reference.framework == "Emerging AI Threat"

    assert reference.reference_id is None


def test_parser_reads_optional_sections() -> None:
    text = (
        BASE_RECORD
        + """
        Common Tools Used by Attackers:
        * Evilginx
        Real World Examples:
        * Credential-harvesting campaign
        Keywords:
        * fake login
        """
    )

    record = parse_text(text)

    assert record.tools == ("Evilginx",)

    assert record.real_world_examples == ("Credential-harvesting campaign",)

    assert record.keywords == ("fake login",)


def test_parser_rejects_missing_section() -> None:
    text = BASE_RECORD.replace(
        ("Detection Rules:\n- Alert on lookalike domains\n"),
        "",
    )

    with pytest.raises(
        KnowledgeBaseError,
        match="detection",
    ):
        parse_text(text)


def test_parser_rejects_bad_severity() -> None:
    text = BASE_RECORD.replace(
        "High",
        "Extreme",
        1,
    )

    with pytest.raises(
        KnowledgeBaseError,
        match="Unsupported severity",
    ):
        parse_text(text)


def test_repository_loads_multiple_files(
    tmp_path: Path,
) -> None:
    (tmp_path / "phishing.txt").write_text(
        BASE_RECORD,
        encoding="utf-8",
    )

    ransomware = BASE_RECORD.replace(
        "PHISHING",
        "RANSOMWARE",
    ).replace(
        "T1566 – Phishing",
        "T1486 – Data Encrypted for Impact",
    )

    (tmp_path / "ransomware.txt").write_text(
        ransomware,
        encoding="utf-8",
    )

    records = FileKnowledgeBaseRepository(tmp_path).load_all()

    assert [record.attack_id for record in records] == [
        "phishing",
        "ransomware",
    ]


def test_normalized_records_are_written(
    tmp_path: Path,
) -> None:
    record = parse_text()

    manifest = write_normalized_records(
        (record,),
        tmp_path,
    )

    assert manifest.exists()

    assert (tmp_path / "phishing.json").exists()
