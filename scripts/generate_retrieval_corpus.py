from __future__ import annotations

import json
from argparse import ArgumentParser
from datetime import UTC, datetime
from pathlib import Path

from ra_xsoc_engine.knowledge_base import (
    NormalizedKnowledgeBaseRepository,
)
from ra_xsoc_engine.retrieval import (
    RetrievalCorpusBuilder,
    write_retrieval_corpus,
)

GENERATED_METADATA_FILES = {
    "manifest.json",
    "validation_summary.json",
}


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(description=("Generate the deterministic RA-XSOC retrieval corpus."))

    parser.add_argument(
        "source",
        type=Path,
        help=("Directory containing normalized knowledge JSON records."),
    )

    parser.add_argument(
        "output",
        type=Path,
        help=("Directory for generated retrieval documents."),
    )

    return parser


def clean_previous_output(
    output_directory: Path,
) -> None:
    """Remove only previously generated corpus files."""

    if not output_directory.exists():
        return

    for path in output_directory.iterdir():
        if path.suffix == ".json" or path.name == "corpus.jsonl":
            path.unlink()


def main() -> int:
    arguments = build_parser().parse_args()

    repository = NormalizedKnowledgeBaseRepository(arguments.source)

    records = repository.load_all()

    builder = RetrievalCorpusBuilder()

    documents = builder.build_corpus(records)

    corpus_checksum = builder.corpus_checksum(documents)

    clean_previous_output(arguments.output)

    corpus_path, manifest_path = write_retrieval_corpus(
        documents,
        arguments.output,
        corpus_checksum,
    )

    text_lengths = [len(document.retrieval_text) for document in documents]

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "source_record_count": len(records),
        "retrieval_document_count": len(documents),
        "unique_document_ids": len({document.document_id for document in documents}),
        "retrieval_schema_version": "1.0",
        "corpus_checksum": corpus_checksum,
        "minimum_text_length": min(text_lengths),
        "maximum_text_length": max(text_lengths),
        "average_text_length": round(
            sum(text_lengths) / len(text_lengths),
            2,
        ),
        "corpus_file": str(corpus_path),
        "manifest_file": str(manifest_path),
        "classification_fields": [
            "incident_type",
            "description",
            "framework_references",
            "indicators",
            "detection_rules",
            "affected_assets",
        ],
        "excluded_playbook_fields": [
            "containment",
            "investigation",
            "recovery",
            "prevention",
            "references",
            "tools",
            "real_world_examples",
            "keywords",
        ],
    }

    summary_path = arguments.output / "validation_summary.json"

    summary_path.write_text(
        json.dumps(
            summary,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print("=" * 76)

    print("RA-XSOC RETRIEVAL CORPUS GENERATION")

    print("=" * 76)

    print(
        "Source records:",
        len(records),
    )

    print(
        "Retrieval documents:",
        len(documents),
    )

    print(
        "Unique document IDs:",
        summary["unique_document_ids"],
    )

    print(
        "Corpus checksum:",
        corpus_checksum,
    )

    print(
        "Corpus file:",
        corpus_path,
    )

    print(
        "Manifest:",
        manifest_path,
    )

    print(
        "Validation summary:",
        summary_path,
    )

    if len(records) != 30:
        raise RuntimeError(f"Expected 30 source records, but loaded {len(records)}.")

    if len(documents) != 30:
        raise RuntimeError(f"Expected 30 retrieval documents, but generated {len(documents)}.")

    if summary["unique_document_ids"] != 30:
        raise RuntimeError("Retrieval document IDs are not unique.")

    print("\nAll 30 retrieval documents generated successfully.")

    print("The normalized source records were not modified.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
