from __future__ import annotations
from collections.abc import Sequence
from ra_xsoc_engine.domain.exceptions import AnalysisError
from ra_xsoc_engine.domain.knowledge import AttackKnowledgeRecord
from ra_xsoc_engine.domain.models import ResponsePlaybook
class KnowledgeBasePlaybookRepository:
    """Provide response playbooks from validated attack knowledge records."""
    def __init__(
        self,
        records: Sequence[AttackKnowledgeRecord],
    ) -> None:
        self._records = tuple(records)
        seen_attack_ids: set[str] = set()
        for record in self._records:
            if record.attack_id in seen_attack_ids:
                raise AnalysisError(
                    f"Duplicate playbook attack ID: {record.attack_id}"
                )
            seen_attack_ids.add(record.attack_id)
    def get_by_attack_id(
        self,
        attack_id: str,
    ) -> ResponsePlaybook:
        """Return the response playbook for an attack category."""
        cleaned_attack_id = attack_id.strip()
        if not cleaned_attack_id:
            raise AnalysisError(
                "attack_id must not be empty."
            )
        for record in self._records:
            if record.attack_id == cleaned_attack_id:
                return ResponsePlaybook(
                    containment=record.containment,
                    investigation=record.investigation,
                    recovery=record.recovery,
                    prevention=record.prevention,
                    detection_rules=record.detection_rules,
                )
        raise AnalysisError(
            f"No playbook exists for attack ID: {cleaned_attack_id}"
        )
