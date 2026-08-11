from collections.abc import Sequence
from hashlib import sha256

from ra_xsoc_engine.domain.exceptions import (
    DomainValidationError,
)
from ra_xsoc_engine.domain.knowledge import (
    AttackKnowledgeRecord,
    ThreatFrameworkReference,
)
from ra_xsoc_engine.domain.retrieval import (
    RetrievalDocument,
)


class RetrievalCorpusBuilder:
    """Create deterministic retrieval documents."""

    retrieval_schema_version = "1.0"

    def build_document(
        self,
        record: AttackKnowledgeRecord,
    ) -> RetrievalDocument:
        """Create one focused retrieval document."""

        framework_labels = self._build_framework_labels(record.framework_references)

        # Important:
        # The exact canonical text is created first.
        # The checksum is calculated from that same exact text.
        retrieval_text = self._build_retrieval_text(
            record,
            framework_labels,
        )

        content_sha256 = sha256(retrieval_text.encode("utf-8")).hexdigest()

        document_id = f"retrieval:{record.attack_id}:{self.retrieval_schema_version}"

        return RetrievalDocument(
            document_id=document_id,
            attack_id=record.attack_id,
            title=record.incident_type,
            retrieval_text=retrieval_text,
            severity=record.severity,
            framework_labels=framework_labels,
            source_filename=record.source_filename,
            source_record_sha256=(record.source_sha256),
            content_sha256=content_sha256,
            knowledge_schema_version=(record.schema_version),
            retrieval_schema_version=(self.retrieval_schema_version),
        )

    def build_corpus(
        self,
        records: Sequence[AttackKnowledgeRecord],
    ) -> tuple[RetrievalDocument, ...]:
        """Create a stable corpus ordered by attack ID."""

        ordered_records = sorted(
            records,
            key=lambda record: record.attack_id,
        )

        seen_attack_ids: set[str] = set()
        documents: list[RetrievalDocument] = []

        for record in ordered_records:
            if record.attack_id in seen_attack_ids:
                raise DomainValidationError(
                    f"Duplicate attack_id found while building retrieval corpus: {record.attack_id}"
                )

            seen_attack_ids.add(record.attack_id)

            documents.append(self.build_document(record))

        return tuple(documents)

    @staticmethod
    def corpus_checksum(
        documents: Sequence[RetrievalDocument],
    ) -> str:
        """Create one stable checksum for the corpus."""

        ordered_documents = sorted(
            documents,
            key=lambda document: document.document_id,
        )

        canonical_lines = [
            (f"{document.document_id}\t{document.content_sha256}") for document in ordered_documents
        ]

        canonical_value = "\n".join(canonical_lines) + "\n"

        return sha256(canonical_value.encode("utf-8")).hexdigest()

    def _build_retrieval_text(
        self,
        record: AttackKnowledgeRecord,
        framework_labels: tuple[str, ...],
    ) -> str:
        """Format classification-focused text."""

        lines: list[str] = []

        self._add_single_value_section(
            lines,
            "INCIDENT TYPE",
            record.incident_type,
        )

        self._add_single_value_section(
            lines,
            "DESCRIPTION",
            record.description,
        )

        self._add_list_section(
            lines,
            "THREAT FRAMEWORK",
            framework_labels,
        )

        self._add_list_section(
            lines,
            "INDICATORS",
            record.indicators,
        )

        self._add_list_section(
            lines,
            "DETECTION RULES",
            record.detection_rules,
        )

        self._add_list_section(
            lines,
            "AFFECTED ASSETS",
            record.affected_assets,
        )

        # No trailing newline is added.
        # This exact value is stored and hashed.
        return "\n".join(lines).strip()

    @staticmethod
    def _add_single_value_section(
        lines: list[str],
        heading: str,
        value: str,
    ) -> None:
        lines.append(f"{heading}:")
        lines.append(value.strip())
        lines.append("")

    @staticmethod
    def _add_list_section(
        lines: list[str],
        heading: str,
        values: Sequence[str],
    ) -> None:
        lines.append(f"{heading}:")

        for value in values:
            lines.append(f"- {value.strip()}")

        lines.append("")

    @staticmethod
    def _build_framework_labels(
        references: Sequence[ThreatFrameworkReference],
    ) -> tuple[str, ...]:
        labels: list[str] = []
        seen_labels: set[str] = set()

        for reference in references:
            label = RetrievalCorpusBuilder._framework_label(reference)

            if label not in seen_labels:
                seen_labels.add(label)
                labels.append(label)

        return tuple(labels)

    @staticmethod
    def _framework_label(
        reference: ThreatFrameworkReference,
    ) -> str:
        if reference.reference_id:
            return f"{reference.framework} | {reference.reference_id} | {reference.name}"

        if reference.name.strip().lower() == reference.framework.strip().lower():
            return reference.framework

        return f"{reference.framework} | {reference.name}"
