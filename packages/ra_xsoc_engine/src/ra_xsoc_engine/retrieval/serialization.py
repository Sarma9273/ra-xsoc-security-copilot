from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ra_xsoc_engine.domain.retrieval import (
    RetrievalDocument,
)


def retrieval_document_to_dict(
    document: RetrievalDocument,
) -> dict[str, Any]:
    """Convert a retrieval document to JSON data."""

    return {
        "document_id": document.document_id,
        "attack_id": document.attack_id,
        "title": document.title,
        "retrieval_text": document.retrieval_text,
        "severity": document.severity.value,
        "framework_labels": list(document.framework_labels),
        "source_filename": document.source_filename,
        "source_record_sha256": document.source_record_sha256,
        "content_sha256": document.content_sha256,
        "knowledge_schema_version": document.knowledge_schema_version,
        "retrieval_schema_version": document.retrieval_schema_version,
    }


def write_retrieval_corpus(
    documents: Sequence[RetrievalDocument],
    output_directory: Path,
    corpus_checksum: str,
) -> tuple[Path, Path]:
    """Write document JSON files and corpus metadata."""

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    ordered_documents = sorted(
        documents,
        key=lambda document: document.attack_id,
    )

    manifest_records: list[dict[str, Any]] = []

    jsonl_lines: list[str] = []

    for document in ordered_documents:
        payload = retrieval_document_to_dict(document)

        destination = output_directory / f"{document.attack_id}.json"

        destination.write_text(
            json.dumps(
                payload,
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        jsonl_lines.append(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
            )
        )

        manifest_records.append(
            {
                "document_id": document.document_id,
                "attack_id": document.attack_id,
                "content_sha256": document.content_sha256,
                "source_record_sha256": document.source_record_sha256,
                "normalized_file": destination.name,
            }
        )

    corpus_path = output_directory / "corpus.jsonl"

    corpus_path.write_text(
        "\n".join(jsonl_lines) + "\n",
        encoding="utf-8",
    )

    manifest_path = output_directory / "manifest.json"

    manifest = {
        "retrieval_schema_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "document_count": len(ordered_documents),
        "corpus_checksum": corpus_checksum,
        "corpus_file": corpus_path.name,
        "records": manifest_records,
    }

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    return corpus_path, manifest_path
