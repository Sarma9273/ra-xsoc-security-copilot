from __future__ import annotations

from unittest.mock import Mock, patch

import numpy as np
import pytest
from ra_xsoc_engine.domain.embedding import EmbeddingConfiguration
from ra_xsoc_engine.domain.exceptions import DomainValidationError
from ra_xsoc_engine.embedding.sentence_transformer import (
    SentenceTransformerEmbeddingService,
)


def build_configuration(
    *,
    expected_dimension: int | None = 3,
) -> EmbeddingConfiguration:
    return EmbeddingConfiguration(
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        expected_dimension=expected_dimension,
    )


def build_mock_model(
    *,
    dimension: int = 3,
) -> Mock:
    model = Mock()
    model.get_sentence_embedding_dimension.return_value = dimension
    return model


def test_service_loads_model_and_detects_dimension() -> None:
    model = build_mock_model(dimension=3)

    with patch(
        "ra_xsoc_engine.embedding.sentence_transformer.SentenceTransformer",
        return_value=model,
    ) as constructor:
        service = SentenceTransformerEmbeddingService(
            build_configuration(expected_dimension=3)
        )

    constructor.assert_called_once_with(
        "sentence-transformers/all-MiniLM-L6-v2",
        device="cpu",
        revision=None,
    )

    assert service.dimension == 3


def test_embed_returns_float_vectors() -> None:
    model = build_mock_model(dimension=3)

    model.encode.return_value = np.asarray(
        [
            [1.0, 0.0, 0.0],
            [0.0, 1.0, 0.0],
        ],
        dtype=np.float32,
    )

    with patch(
        "ra_xsoc_engine.embedding.sentence_transformer.SentenceTransformer",
        return_value=model,
    ):
        service = SentenceTransformerEmbeddingService(
            build_configuration(expected_dimension=3)
        )

    vectors = service.embed(
        (
            "first incident",
            "second incident",
        )
    )

    assert vectors == (
        (1.0, 0.0, 0.0),
        (0.0, 1.0, 0.0),
    )


def test_embed_passes_configuration_to_model() -> None:
    model = build_mock_model(dimension=3)

    model.encode.return_value = np.asarray(
        [[1.0, 0.0, 0.0]],
        dtype=np.float32,
    )

    with patch(
        "ra_xsoc_engine.embedding.sentence_transformer.SentenceTransformer",
        return_value=model,
    ):
        service = SentenceTransformerEmbeddingService(
            EmbeddingConfiguration(
                model_name="sentence-transformers/all-MiniLM-L6-v2",
                batch_size=16,
                normalize_embeddings=True,
                expected_dimension=3,
            )
        )

    service.embed(("incident text",))

    model.encode.assert_called_once_with(
        ["incident text"],
        batch_size=16,
        normalize_embeddings=True,
        convert_to_numpy=True,
        show_progress_bar=False,
    )


def test_empty_input_returns_empty_tuple() -> None:
    model = build_mock_model(dimension=3)

    with patch(
        "ra_xsoc_engine.embedding.sentence_transformer.SentenceTransformer",
        return_value=model,
    ):
        service = SentenceTransformerEmbeddingService(
            build_configuration(expected_dimension=3)
        )

    assert service.embed(()) == ()

    model.encode.assert_not_called()


@pytest.mark.parametrize(
    "texts",
    [
        ("",),
        ("   ",),
        ("\t",),
    ],
)
def test_empty_text_is_rejected(
    texts: tuple[str, ...],
) -> None:
    model = build_mock_model(dimension=3)

    with patch(
        "ra_xsoc_engine.embedding.sentence_transformer.SentenceTransformer",
        return_value=model,
    ):
        service = SentenceTransformerEmbeddingService(
            build_configuration(expected_dimension=3)
        )

    with pytest.raises(DomainValidationError):
        service.embed(texts)


def test_dimension_mismatch_is_rejected() -> None:
    model = build_mock_model(dimension=3)

    with patch(
        "ra_xsoc_engine.embedding.sentence_transformer.SentenceTransformer",
        return_value=model,
    ), pytest.raises(DomainValidationError):
        SentenceTransformerEmbeddingService(
            build_configuration(expected_dimension=384)
        )


def test_non_finite_embeddings_are_rejected() -> None:
    model = build_mock_model(dimension=3)

    model.encode.return_value = np.asarray(
        [
            [1.0, np.nan, 0.0],
        ],
        dtype=np.float32,
    )

    with patch(
        "ra_xsoc_engine.embedding.sentence_transformer.SentenceTransformer",
        return_value=model,
    ):
        service = SentenceTransformerEmbeddingService(
            build_configuration(expected_dimension=3)
        )

    with pytest.raises(DomainValidationError):
        service.embed(("incident",))


def test_embed_documents_returns_validated_batch() -> None:
    model = build_mock_model(dimension=3)

    model.encode.return_value = np.asarray(
        [
            [1.0, 0.0, 0.0],
            [0.0, 1.0, 0.0],
        ],
        dtype=np.float32,
    )

    with patch(
        "ra_xsoc_engine.embedding.sentence_transformer.SentenceTransformer",
        return_value=model,
    ):
        service = SentenceTransformerEmbeddingService(
            build_configuration(expected_dimension=3)
        )

    batch = service.embed_documents(
        (
            "retrieval:a:1.0",
            "retrieval:b:1.0",
        ),
        (
            "incident A",
            "incident B",
        ),
    )

    assert batch.count == 2
    assert batch.dimension == 3
    assert batch.normalized is True
    assert batch.document_ids == (
        "retrieval:a:1.0",
        "retrieval:b:1.0",
    )