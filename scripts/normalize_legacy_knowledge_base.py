import json
from argparse import ArgumentParser
from collections import Counter
from pathlib import Path

from ra_xsoc_engine.knowledge_base import (
    FileKnowledgeBaseRepository,
    write_normalized_records,
)


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        description=("Validate and normalize legacy CyberGPT TXT knowledge files.")
    )

    parser.add_argument(
        "source",
        type=Path,
        help="Directory containing legacy TXT files.",
    )

    parser.add_argument(
        "output",
        type=Path,
        help="Directory for normalized JSON files.",
    )

    return parser


def main() -> int:
    arguments = build_parser().parse_args()

    records = FileKnowledgeBaseRepository(arguments.source).load_all()

    manifest_path = write_normalized_records(
        records,
        arguments.output,
    )

    severity_counts = Counter(record.severity.value for record in records)

    conventional_mitre = sum(
        1
        for record in records
        if any(reference.framework == "MITRE ATT&CK" for reference in record.framework_references)
    )

    emerging_ai = sum(
        1
        for record in records
        if any(
            reference.framework == "Emerging AI Threat" for reference in record.framework_references
        )
    )

    tools_count = sum(bool(record.tools) for record in records)

    examples_count = sum(bool(record.real_world_examples) for record in records)

    keywords_count = sum(bool(record.keywords) for record in records)

    summary = {
        "record_count": len(records),
        "severity_counts": dict(severity_counts),
        "conventional_mitre_records": conventional_mitre,
        "emerging_ai_records": emerging_ai,
        "records_with_tools": tools_count,
        "records_with_real_world_examples": examples_count,
        "records_with_keywords": keywords_count,
        "manifest": str(manifest_path),
    }

    summary_path = arguments.output / "validation_summary.json"

    summary_path.write_text(
        json.dumps(
            summary,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("=" * 72)
    print("RA-XSOC KNOWLEDGE-BASE NORMALIZATION")
    print("=" * 72)

    for key, value in summary.items():
        print(f"{key}: {value}")

    if len(records) != 30:
        raise RuntimeError(f"Expected 30 records, but parsed {len(records)}.")

    print("\nAll 30 records validated successfully.")
    print("No original TXT files were modified.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
