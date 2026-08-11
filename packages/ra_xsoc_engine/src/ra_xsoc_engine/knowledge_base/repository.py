from pathlib import Path

from ra_xsoc_engine.domain.exceptions import (
    KnowledgeBaseError,
)
from ra_xsoc_engine.domain.knowledge import (
    AttackKnowledgeRecord,
)

from .parser import TxtKnowledgeBaseParser


class FileKnowledgeBaseRepository:
    """Load validated records from a TXT directory."""

    def __init__(
        self,
        directory: Path,
        parser: TxtKnowledgeBaseParser | None = None,
    ) -> None:
        self._directory = directory
        self._parser = parser or TxtKnowledgeBaseParser()

    def load_all(
        self,
    ) -> tuple[
        AttackKnowledgeRecord,
        ...,
    ]:
        if not self._directory.is_dir():
            raise KnowledgeBaseError(f"Knowledge-base directory does not exist: {self._directory}")

        files = sorted(self._directory.glob("*.txt"))

        if not files:
            raise KnowledgeBaseError(f"No TXT knowledge-base files found in {self._directory}.")

        records: list[AttackKnowledgeRecord] = []

        seen_attack_ids: set[str] = set()

        for path in files:
            record = self._parser.parse_file(path)

            if record.attack_id in seen_attack_ids:
                raise KnowledgeBaseError(f"Duplicate attack_id detected: {record.attack_id}")

            seen_attack_ids.add(record.attack_id)

            records.append(record)

        return tuple(records)
