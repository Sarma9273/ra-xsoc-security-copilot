from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

from ra_xsoc_engine.domain.enums import (
    SeverityLevel,
)
from ra_xsoc_engine.domain.exceptions import (
    KnowledgeBaseError,
)
from ra_xsoc_engine.domain.knowledge import (
    AttackKnowledgeRecord,
    ThreatFrameworkReference,
)


class NormalizedKnowledgeBaseRepository:
    """Load validated knowledge records from JSON."""

    excluded_files: ClassVar[frozenset[str]] = frozenset(
        {
            "manifest.json",
            "validation_summary.json",
        }
    )

    def __init__(
        self,
        directory: Path,
    ) -> None:
        self._directory = directory

    def load_all(
        self,
    ) -> tuple[
        AttackKnowledgeRecord,
        ...,
    ]:
        if not self._directory.is_dir():
            raise KnowledgeBaseError(
                f"Normalized knowledge-base directory does not exist: {self._directory}"
            )

        files = sorted(
            path for path in self._directory.glob("*.json") if path.name not in self.excluded_files
        )

        if not files:
            raise KnowledgeBaseError(f"No normalized JSON records were found in {self._directory}.")

        records: list[AttackKnowledgeRecord] = []

        seen_attack_ids: set[str] = set()

        for path in files:
            record = self._load_file(path)

            if record.attack_id in seen_attack_ids:
                raise KnowledgeBaseError(
                    f"Duplicate normalized attack_id detected: {record.attack_id}"
                )

            seen_attack_ids.add(record.attack_id)

            records.append(record)

        return tuple(records)

    def _load_file(
        self,
        path: Path,
    ) -> AttackKnowledgeRecord:
        try:
            payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise KnowledgeBaseError(f"Invalid JSON in normalized record: {path.name}") from error

        try:
            references_payload = payload["framework_references"]

            if not isinstance(
                references_payload,
                list,
            ):
                raise TypeError("framework_references must be a list.")

            framework_references = tuple(self._build_reference(item) for item in references_payload)

            return AttackKnowledgeRecord(
                attack_id=str(payload["attack_id"]),
                incident_type=str(payload["incident_type"]),
                description=str(payload["description"]),
                severity=SeverityLevel(str(payload["severity"])),
                framework_references=(framework_references),
                indicators=self._string_tuple(
                    payload,
                    "indicators",
                ),
                containment=self._string_tuple(
                    payload,
                    "containment",
                ),
                investigation=self._string_tuple(
                    payload,
                    "investigation",
                ),
                recovery=self._string_tuple(
                    payload,
                    "recovery",
                ),
                prevention=self._string_tuple(
                    payload,
                    "prevention",
                ),
                detection_rules=(
                    self._string_tuple(
                        payload,
                        "detection_rules",
                    )
                ),
                affected_assets=(
                    self._string_tuple(
                        payload,
                        "affected_assets",
                    )
                ),
                references=self._string_tuple(
                    payload,
                    "references",
                ),
                tools=self._string_tuple(
                    payload,
                    "tools",
                ),
                real_world_examples=(
                    self._string_tuple(
                        payload,
                        "real_world_examples",
                    )
                ),
                keywords=self._string_tuple(
                    payload,
                    "keywords",
                ),
                source_filename=str(payload["source_filename"]),
                source_sha256=str(payload["source_sha256"]),
                source_encoding=str(payload["source_encoding"]),
                schema_version=str(
                    payload.get(
                        "schema_version",
                        "1.0",
                    )
                ),
            )
        except (
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            raise KnowledgeBaseError(
                f"Normalized record has an invalid structure: {path.name}"
            ) from error

    @staticmethod
    def _build_reference(
        payload: object,
    ) -> ThreatFrameworkReference:
        if not isinstance(payload, dict):
            raise TypeError("Framework reference must be an object.")

        reference_id_value = payload.get("reference_id")

        reference_id = str(reference_id_value) if reference_id_value is not None else None

        return ThreatFrameworkReference(
            framework=str(payload["framework"]),
            name=str(payload["name"]),
            raw_value=str(payload["raw_value"]),
            reference_id=reference_id,
        )

    @staticmethod
    def _string_tuple(
        payload: dict[str, Any],
        field_name: str,
    ) -> tuple[str, ...]:
        value = payload.get(
            field_name,
            [],
        )

        if not isinstance(value, list):
            raise TypeError(f"{field_name} must be a list.")

        if not all(isinstance(item, str) for item in value):
            raise TypeError(f"{field_name} must contain only strings.")

        return tuple(value)
