import json
from collections.abc import Sequence
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ra_xsoc_engine.domain.knowledge import (
    AttackKnowledgeRecord,
)


def record_to_dict(
    record: AttackKnowledgeRecord,
) -> dict[str, Any]:
    """Convert a record to JSON-compatible data."""

    payload = asdict(record)
    payload["severity"] = record.severity.value

    return payload


def write_normalized_records(
    records: Sequence[AttackKnowledgeRecord],
    output_directory: Path,
) -> Path:
    """Write normalized records and a manifest."""

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    manifest_records: list[dict[str, Any]] = []

    for record in records:
        destination = output_directory / f"{record.attack_id}.json"

        destination.write_text(
            json.dumps(
                record_to_dict(record),
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        manifest_records.append(
            {
                "attack_id": record.attack_id,
                "incident_type": record.incident_type,
                "severity": record.severity.value,
                "source_filename": record.source_filename,
                "source_sha256": record.source_sha256,
                "normalized_file": destination.name,
            }
        )

    manifest_path = output_directory / "manifest.json"

    manifest_payload = {
        "schema_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "record_count": len(records),
        "records": manifest_records,
    }

    manifest_path.write_text(
        json.dumps(
            manifest_payload,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return manifest_path
