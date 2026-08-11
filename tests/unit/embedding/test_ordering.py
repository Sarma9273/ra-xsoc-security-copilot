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


def build_documents() -> tuple[FakeDocument, ...]:
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


def test_documents_are_sorted_by_document_id() -> None:
    ordered = order_documents(build_documents())

    assert [document.document_id for document in ordered] == [
        "retrieval:a:1.0",
        "retrieval:z:1.0",
    ]


def test_ids_and_texts_remain_aligned() -> None:
    document_ids, texts = prepare_embedding_inputs(build_documents())

    assert document_ids == (
        "retrieval:a:1.0",
        "retrieval:z:1.0",
    )

    assert texts == (
        "Text A",
        "Text Z",
    )


def test_duplicate_document_id_is_rejected() -> None:
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


def test_checksum_is_independent_of_input_order() -> None:
    forward_checksum = ordered_document_ids_checksum(build_documents())

    reverse_checksum = ordered_document_ids_checksum(tuple(reversed(build_documents())))

    assert forward_checksum == reverse_checksum


def test_checksum_requires_sorted_ids() -> None:
    with pytest.raises(DomainValidationError):
        document_ids_checksum(
            (
                "retrieval:z:1.0",
                "retrieval:a:1.0",
            )
        )
