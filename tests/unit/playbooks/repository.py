from __future__ import annotations

from collections.abc import Sequence

from ra_xsoc_engine.domain.exceptions import AnalysisError
from ra_xsoc_engine.domain.knowledge import AttackKnowledgeRecord
from ra_xsoc_engine.domain.models import ResponsePlaybook


class KnowledgeBasePlaybookRepository:
    """Provide response playbooks from normalized knowledge records."""

    def __init__(
        self,
        records: Sequence[AttackKnowledgeRecord],
    ) -> None:
        self._records: dict[str, AttackKnowledgeRecord] = {}

        for record in records:
            if record.attack_id in self._records:
                raise AnalysisError(
                    f"Duplicate playbook attack ID: {record.attack_id}"
                )

            self._records[record.attack_id] = record

    def get_by_attack_id(
        self,
        attack_id: str,
    ) -> ResponsePlaybook:
        """Return response guidance for an attack category."""

        cleaned_attack_id = attack_id.strip()

        if not cleaned_attack_id:
            raise AnalysisError(
                "attack_id must not be empty."
            )

        record = self._records.get(cleaned_attack_id)

        if record is None:
            raise AnalysisError(
                f"No playbook exists for attack ID: {cleaned_attack_id}"
            )

        return ResponsePlaybook(
            containment=record.containment,
            investigation=record.investigation,
            recovery=record.recovery,
            prevention=record.prevention,
            detection_rules=record.detection_rules,
        )