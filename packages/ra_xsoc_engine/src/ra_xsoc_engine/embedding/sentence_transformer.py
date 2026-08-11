from __future__ import annotations

from collections.abc import Sequence

import numpy as np
from sentence_transformers import SentenceTransformer

from ra_xsoc_engine.domain.embedding import (
    EmbeddingConfiguration,
    EmbeddingVectorBatch,
)
from ra_xsoc_engine.domain.exceptions import DomainValidationError
from ra_xsoc_engine.domain.ports import EmbeddingService


class SentenceTransformerEmbeddingService:
    """SentenceTransformer-backed implementation of EmbeddingService."""

    def __init__(
        self,
        configuration: EmbeddingConfiguration,
    ) -> None:
        self._configuration = configuration

        self._model = SentenceTransformer(
            configuration.model_name,
            device=configuration.device,
            revision=configuration.model_revision,
        )

        dimension = self._model.get_sentence_embedding_dimension()

        if dimension is None or dimension <= 0:
            raise DomainValidationError(
                "SentenceTransformer did not expose a valid embedding dimension."
            )

        self._dimension = dimension

        expected_dimension = configuration.expected_dimension

        if (
            expected_dimension is not None
            and expected_dimension != self._dimension
        ):
            raise DomainValidationError(
                "Configured embedding dimension does not match "
                f"the model dimension: expected {expected_dimension}, "
                f"received {self._dimension}."
            )

    @property
    def configuration(self) -> EmbeddingConfiguration:
        """Return the embedding configuration."""

        return self._configuration

    @property
    def dimension(self) -> int:
        """Return the model embedding dimension."""

        return self._dimension

    def embed(
        self,
        texts: Sequence[str],
    ) -> Sequence[Sequence[float]]:
        """Generate embeddings for a sequence of texts."""

        if not texts:
            return ()

        normalized_texts: list[str] = []

        for position, text in enumerate(texts):
            if not isinstance(text, str):
                raise DomainValidationError(
                    f"Embedding input at position {position} must be a string."
                )

            if not text.strip():
                raise DomainValidationError(
                    f"Embedding input at position {position} must not be empty."
                )

            normalized_texts.append(text)

        embeddings = self._model.encode(
            normalized_texts,
            batch_size=self._configuration.batch_size,
            normalize_embeddings=self._configuration.normalize_embeddings,
            convert_to_numpy=True,
            show_progress_bar=False,
        )

        vectors = np.asarray(
            embeddings,
            dtype=np.float32,
        )

        if vectors.ndim != 2:
            raise DomainValidationError(
                "SentenceTransformer returned an invalid embedding shape: "
                f"{vectors.shape}."
            )

        if vectors.shape[0] != len(normalized_texts):
            raise DomainValidationError(
                "SentenceTransformer returned an unexpected number of vectors."
            )

        if vectors.shape[1] != self._dimension:
            raise DomainValidationError(
                "SentenceTransformer returned an unexpected embedding dimension: "
                f"expected {self._dimension}, received {vectors.shape[1]}."
            )

        if not np.isfinite(vectors).all():
            raise DomainValidationError(
                "SentenceTransformer returned non-finite embedding values."
            )

        return tuple(
            tuple(float(value) for value in vector)
            for vector in vectors
        )

    def embed_documents(
        self,
        document_ids: Sequence[str],
        texts: Sequence[str],
    ) -> EmbeddingVectorBatch:
        """Embed ordered document text and return a validated vector batch."""

        if len(document_ids) != len(texts):
            raise DomainValidationError(
                "The number of document IDs must equal the number of texts."
            )

        if not document_ids:
            raise DomainValidationError(
                "At least one document is required."
            )

        vectors = self.embed(texts)

        return EmbeddingVectorBatch(
            document_ids=tuple(document_ids),
            vectors=tuple(
                tuple(vector)
                for vector in vectors
            ),
            dimension=self._dimension,
            normalized=self._configuration.normalize_embeddings,
        )


def assert_embedding_service_contract() -> None:
    """Static/runtime documentation guard for the domain protocol."""

    service: EmbeddingService = SentenceTransformerEmbeddingService.__new__(
        SentenceTransformerEmbeddingService
    )

    del service