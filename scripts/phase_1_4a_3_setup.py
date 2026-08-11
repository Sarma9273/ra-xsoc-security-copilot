
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import ast
import json
import shutil
import subprocess
import sys
import textwrap


V2_ROOT = Path(
    "/content/drive/MyDrive/My_Projects/"
    "Product_Company_Career_Roadmap/"
    "06_CyberGPT_V2"
)

PROJECT_ROOT = (
    V2_ROOT
    / "15_V2_Source"
    / "ra-xsoc-security-copilot"
)

PACKAGE_ROOT = (
    PROJECT_ROOT
    / "packages"
    / "ra_xsoc_engine"
    / "src"
    / "ra_xsoc_engine"
)

PORTS_FILE = PACKAGE_ROOT / "domain" / "ports.py"
ORDERING_FILE = PACKAGE_ROOT / "embedding" / "ordering.py"
EMBEDDING_INIT_FILE = PACKAGE_ROOT / "embedding" / "__init__.py"
TEST_FILE = (
    PROJECT_ROOT
    / "tests"
    / "unit"
    / "embedding"
    / "test_ordering.py"
)
DOC_FILE = (
    PROJECT_ROOT
    / "docs"
    / "architecture"
    / "EMBEDDING_SERVICE.md"
)
RESULTS_DIR = V2_ROOT / "09_Testing" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

for required_path in (
    PROJECT_ROOT,
    PACKAGE_ROOT,
    PORTS_FILE,
):
    if not required_path.exists():
        raise FileNotFoundError(
            f"Required path not found:\n{required_path}"
        )

print("=" * 84)
print(
    "PHASE 1.4A.3 — "
    "EMBEDDING SERVICE CONTRACT AND ORDERING"
)
print("=" * 84)


ports_source = PORTS_FILE.read_text(encoding="utf-8")
ports_tree = ast.parse(ports_source)

class_names = {
    node.name
    for node in ports_tree.body
    if isinstance(node, ast.ClassDef)
}

if "EmbeddingService" not in class_names:
    raise RuntimeError(
        "EmbeddingService was not found in "
        "domain/ports.py. Review the existing "
        "domain contract before adding another."
    )

print("\nExisting EmbeddingService port: VERIFIED")


timestamp = datetime.now(timezone.utc).strftime(
    "%Y%m%d_%H%M%S"
)

BACKUP_DIR = (
    RESULTS_DIR
    / "phase_1_4a_3_backups"
    / timestamp
)


def write_safely(
    path: Path,
    content: str,
) -> str:
    normalized = (
        textwrap.dedent(content).lstrip().rstrip()
        + "\n"
    )

    if path.suffix == ".py":
        ast.parse(normalized)

    if (
        path.exists()
        and path.read_text(encoding="utf-8")
        == normalized
    ):
        print(
            "UNCHANGED:",
            path.relative_to(PROJECT_ROOT),
        )
        return "unchanged"

    status = "created"

    if path.exists():
        backup_path = (
            BACKUP_DIR
            / path.relative_to(PROJECT_ROOT)
        )
        backup_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        shutil.copy2(path, backup_path)
        status = "updated"

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    path.write_text(
        normalized,
        encoding="utf-8",
    )

    print(
        status.upper() + ":",
        path.relative_to(PROJECT_ROOT),
    )
    return status


ORDERING_SOURCE = r"""
from __future__ import annotations

from collections.abc import Sequence
from hashlib import sha256
from typing import Protocol, TypeVar

from ra_xsoc_engine.domain.exceptions import (
    DomainValidationError,
)


class EmbeddableDocument(Protocol):
    document_id: str
    retrieval_text: str


_DocumentT = TypeVar(
    "_DocumentT",
    bound=EmbeddableDocument,
)


def order_documents(
    documents: Sequence[_DocumentT],
) -> tuple[_DocumentT, ...]:
    if not documents:
        raise DomainValidationError(
            "At least one document is required."
        )

    document_ids: list[str] = []

    for document in documents:
        document_id = document.document_id
        retrieval_text = document.retrieval_text

        if (
            not document_id
            or document_id != document_id.strip()
        ):
            raise DomainValidationError(
                "document_id must be non-empty "
                "and free of surrounding whitespace."
            )

        if (
            not retrieval_text
            or retrieval_text
            != retrieval_text.strip()
        ):
            raise DomainValidationError(
                "retrieval_text must be non-empty "
                "and canonicalized."
            )

        document_ids.append(document_id)

    if len(set(document_ids)) != len(document_ids):
        raise DomainValidationError(
            "document_id values must be unique."
        )

    return tuple(
        sorted(
            documents,
            key=lambda document:
                document.document_id,
        )
    )


def prepare_embedding_inputs(
    documents: Sequence[_DocumentT],
) -> tuple[
    tuple[str, ...],
    tuple[str, ...],
]:
    ordered_documents = order_documents(documents)

    return (
        tuple(
            document.document_id
            for document in ordered_documents
        ),
        tuple(
            document.retrieval_text
            for document in ordered_documents
        ),
    )


def document_ids_checksum(
    document_ids: Sequence[str],
) -> str:
    if not document_ids:
        raise DomainValidationError(
            "document_ids must not be empty."
        )

    ids = tuple(document_ids)

    if any(
        not document_id
        or document_id != document_id.strip()
        for document_id in ids
    ):
        raise DomainValidationError(
            "document_ids must be non-empty "
            "and canonicalized."
        )

    if len(set(ids)) != len(ids):
        raise DomainValidationError(
            "document_ids must be unique."
        )

    if ids != tuple(sorted(ids)):
        raise DomainValidationError(
            "document_ids must already be "
            "in deterministic sorted order."
        )

    canonical_value = "\n".join(ids) + "\n"

    return sha256(
        canonical_value.encode("utf-8")
    ).hexdigest()


def ordered_document_ids_checksum(
    documents: Sequence[_DocumentT],
) -> str:
    document_ids, _ = prepare_embedding_inputs(
        documents
    )

    return document_ids_checksum(document_ids)
"""

INIT_SOURCE = r"""
from ra_xsoc_engine.embedding.ordering import (
    EmbeddableDocument,
    document_ids_checksum,
    order_documents,
    ordered_document_ids_checksum,
    prepare_embedding_inputs,
)

__all__ = [
    "EmbeddableDocument",
    "document_ids_checksum",
    "order_documents",
    "ordered_document_ids_checksum",
    "prepare_embedding_inputs",
]
"""

TEST_SOURCE = r"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from ra_xsoc_engine.domain.exceptions import (
    DomainValidationError,
)
from ra_xsoc_engine.embedding.ordering import (
    document_ids_checksum,
    order_documents,
    ordered_document_ids_checksum,
    prepare_embedding_inputs,
)


@dataclass(
    frozen=True,
    slots=True,
)
class FakeDocument:
    document_id: str
    retrieval_text: str


def build_documents(
) -> tuple[FakeDocument, ...]:
    return (
        FakeDocument(
            document_id="retrieval:z:1.0",
            retrieval_text="Text Z",
        ),
        FakeDocument(
            document_id="retrieval:a:1.0",
            retrieval_text="Text A",
        ),
    )


def test_documents_are_sorted_by_document_id(
) -> None:
    ordered = order_documents(build_documents())

    assert [
        document.document_id
        for document in ordered
    ] == [
        "retrieval:a:1.0",
        "retrieval:z:1.0",
    ]


def test_ids_and_texts_remain_aligned(
) -> None:
    document_ids, texts = (
        prepare_embedding_inputs(
            build_documents()
        )
    )

    assert document_ids == (
        "retrieval:a:1.0",
        "retrieval:z:1.0",
    )

    assert texts == (
        "Text A",
        "Text Z",
    )


def test_duplicate_document_id_is_rejected(
) -> None:
    duplicate_documents = (
        FakeDocument(
            document_id="retrieval:a:1.0",
            retrieval_text="Text A",
        ),
        FakeDocument(
            document_id="retrieval:a:1.0",
            retrieval_text="Text B",
        ),
    )

    with pytest.raises(DomainValidationError):
        order_documents(duplicate_documents)


@pytest.mark.parametrize(
    "document",
    [
        FakeDocument(
            document_id="",
            retrieval_text="Text A",
        ),
        FakeDocument(
            document_id=" retrieval:a:1.0",
            retrieval_text="Text A",
        ),
        FakeDocument(
            document_id="retrieval:a:1.0",
            retrieval_text="",
        ),
        FakeDocument(
            document_id="retrieval:a:1.0",
            retrieval_text=" Text A",
        ),
    ],
)
def test_invalid_document_content_is_rejected(
    document: FakeDocument,
) -> None:
    with pytest.raises(DomainValidationError):
        order_documents((document,))


def test_checksum_is_independent_of_input_order(
) -> None:
    forward_checksum = (
        ordered_document_ids_checksum(
            build_documents()
        )
    )

    reverse_checksum = (
        ordered_document_ids_checksum(
            tuple(reversed(build_documents()))
        )
    )

    assert forward_checksum == reverse_checksum


def test_checksum_requires_sorted_ids(
) -> None:
    with pytest.raises(DomainValidationError):
        document_ids_checksum(
            (
                "retrieval:z:1.0",
                "retrieval:a:1.0",
            )
        )
"""

DOCUMENTATION_SOURCE = "\n".join(
    [
        "# Embedding Service and Deterministic Ordering",
        "",
        "## Purpose",
        "",
        (
            "The domain already exposes an "
            "`EmbeddingService` port. Phase 1.4A.3 "
            "adds deterministic preparation utilities "
            "without coupling the domain to "
            "SentenceTransformers."
        ),
        "",
        "## Ordering contract",
        "",
        (
            "Documents are validated and sorted by "
            "`document_id` before embedding."
        ),
        "",
        "The utility guarantees that:",
        "",
        "- Document IDs are non-empty and unique.",
        "- Retrieval text is canonicalized.",
        "- IDs and texts remain positionally aligned.",
        "- Input order cannot change artifact identity.",
        "- Ordered IDs receive a stable SHA-256 checksum.",
        "",
        "## Pipeline boundary",
        "",
        "    Retrieval documents",
        "            ↓",
        "    deterministic ordering",
        "            ↓",
        "    aligned IDs and texts",
        "            ↓",
        "    EmbeddingService port",
        "            ↓",
        "    EmbeddingVectorBatch",
        "",
        (
            "The SentenceTransformer adapter will be "
            "implemented in Phase 1.4B."
        ),
    ]
)

file_status = {
    "ordering": write_safely(
        ORDERING_FILE,
        ORDERING_SOURCE,
    ),
    "package_init": write_safely(
        EMBEDDING_INIT_FILE,
        INIT_SOURCE,
    ),
    "tests": write_safely(
        TEST_FILE,
        TEST_SOURCE,
    ),
    "documentation": write_safely(
        DOC_FILE,
        DOCUMENTATION_SOURCE,
    ),
}


def run_step(
    title: str,
    command: list[str],
) -> str:
    print("\n" + "=" * 84)
    print(title)
    print("=" * 84)

    process = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    output = process.stdout or ""
    print(output)

    if process.returncode != 0:
        raise RuntimeError(f"{title} failed.")

    return output


run_step(
    "INSTALL UPDATED PROJECT",
    [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "-e",
        ".[dev,ai]",
    ],
)

generated_files = [
    str(ORDERING_FILE.relative_to(PROJECT_ROOT)),
    str(
        EMBEDDING_INIT_FILE.relative_to(
            PROJECT_ROOT
        )
    ),
    str(TEST_FILE.relative_to(PROJECT_ROOT)),
]

run_step(
    "RUFF REPAIR",
    [
        sys.executable,
        "-m",
        "ruff",
        "check",
        *generated_files,
        "--fix",
    ],
)

run_step(
    "RUFF FORMAT",
    [
        sys.executable,
        "-m",
        "ruff",
        "format",
        *generated_files,
    ],
)

test_output = run_step(
    "PHASE 1.4A.3 TESTS",
    [
        sys.executable,
        "-m",
        "pytest",
        "tests/unit/embedding/test_ordering.py",
        "-vv",
        "--import-mode=importlib",
    ],
)

run_step(
    "RUFF FINAL CHECK",
    [
        sys.executable,
        "-m",
        "ruff",
        "check",
        *generated_files,
    ],
)

run_step(
    "MYPY STRICT CHECK",
    [
        sys.executable,
        "-m",
        "mypy",
        "packages/ra_xsoc_engine/src",
    ],
)


report_path = (
    RESULTS_DIR
    / (
        "phase_1_4a_3_ordering_"
        f"{timestamp}.json"
    )
)

report = {
    "generated_at": datetime.now(
        timezone.utc
    ).isoformat(),
    "phase": "1.4A.3",
    "embedding_service_port": "verified",
    "file_status": file_status,
    "test_result_contains_passed": (
        "passed" in test_output.lower()
    ),
    "status": "passed",
}

report_path.write_text(
    json.dumps(report, indent=2) + "\n",
    encoding="utf-8",
)


print("\n" + "=" * 84)
print("PHASE 1.4A.3 COMPLETE")
print("=" * 84)

print("EmbeddingService port: VERIFIED")
print("Deterministic ordering: PASSED")
print("ID/text alignment: PASSED")
print("Document-ID checksum: PASSED")
print("Ruff: PASSED")
print("Mypy: PASSED")

print("\nReport saved:")
print(report_path)
