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
        raise DomainValidationError("At least one document is required.")

    document_ids: list[str] = []

    for document in documents:
        document_id = document.document_id
        retrieval_text = document.retrieval_text

        if not document_id or document_id != document_id.strip():
            raise DomainValidationError(
                "document_id must be non-empty and free of surrounding whitespace."
            )

        if not retrieval_text or retrieval_text != retrieval_text.strip():
            raise DomainValidationError("retrieval_text must be non-empty and canonicalized.")

        document_ids.append(document_id)

    if len(set(document_ids)) != len(document_ids):
        raise DomainValidationError("document_id values must be unique.")

    return tuple(
        sorted(
            documents,
            key=lambda document: document.document_id,
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
        tuple(document.document_id for document in ordered_documents),
        tuple(document.retrieval_text for document in ordered_documents),
    )


def document_ids_checksum(
    document_ids: Sequence[str],
) -> str:
    if not document_ids:
        raise DomainValidationError("document_ids must not be empty.")

    ids = tuple(document_ids)

    if any(not document_id or document_id != document_id.strip() for document_id in ids):
        raise DomainValidationError("document_ids must be non-empty and canonicalized.")

    if len(set(ids)) != len(ids):
        raise DomainValidationError("document_ids must be unique.")

    if ids != tuple(sorted(ids)):
        raise DomainValidationError("document_ids must already be in deterministic sorted order.")

    canonical_value = "\n".join(ids) + "\n"

    return sha256(canonical_value.encode("utf-8")).hexdigest()


def ordered_document_ids_checksum(
    documents: Sequence[_DocumentT],
) -> str:
    document_ids, _ = prepare_embedding_inputs(documents)

    return document_ids_checksum(document_ids)
