from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from math import isclose, isfinite, sqrt
from pathlib import PurePosixPath
from typing import ClassVar

from ra_xsoc_engine.domain.exceptions import (
    DomainValidationError,
)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _require_non_empty(
    field_name: str,
    value: str,
) -> None:
    if not value or value != value.strip():
        raise DomainValidationError(
            f"{field_name} must be non-empty and must not contain surrounding whitespace."
        )


def _require_positive_integer(
    field_name: str,
    value: int,
) -> None:
    if value <= 0:
        raise DomainValidationError(f"{field_name} must be greater than zero.")


def _require_sha256(
    field_name: str,
    value: str,
) -> None:
    if not _SHA256_PATTERN.fullmatch(value):
        raise DomainValidationError(f"{field_name} must be a lowercase 64-character SHA-256 value.")


@dataclass(
    frozen=True,
    slots=True,
)
class EmbeddingConfiguration:
    """Configuration governing vector generation."""

    model_name: str
    model_revision: str | None = None
    device: str = "cpu"
    batch_size: int = 32
    normalize_embeddings: bool = True
    similarity_metric: str = "cosine"
    faiss_index_type: str = "IndexFlatIP"
    vector_dtype: str = "float32"
    expected_dimension: int | None = None
    schema_version: str = "1.0"

    supported_similarity_metrics: ClassVar[frozenset[str]] = frozenset(
        {
            "cosine",
        }
    )

    supported_faiss_index_types: ClassVar[frozenset[str]] = frozenset(
        {
            "IndexFlatIP",
        }
    )

    supported_vector_dtypes: ClassVar[frozenset[str]] = frozenset(
        {
            "float32",
        }
    )

    def __post_init__(
        self,
    ) -> None:
        _require_non_empty(
            "model_name",
            self.model_name,
        )

        _require_non_empty(
            "device",
            self.device,
        )

        _require_non_empty(
            "schema_version",
            self.schema_version,
        )

        _require_positive_integer(
            "batch_size",
            self.batch_size,
        )

        if self.model_revision is not None:
            _require_non_empty(
                "model_revision",
                self.model_revision,
            )

        if self.expected_dimension is not None:
            _require_positive_integer(
                "expected_dimension",
                self.expected_dimension,
            )

        if self.similarity_metric not in self.supported_similarity_metrics:
            raise DomainValidationError(f"Unsupported similarity metric: {self.similarity_metric}")

        if self.faiss_index_type not in self.supported_faiss_index_types:
            raise DomainValidationError(f"Unsupported FAISS index type: {self.faiss_index_type}")

        if self.vector_dtype not in self.supported_vector_dtypes:
            raise DomainValidationError(f"Unsupported vector dtype: {self.vector_dtype}")

        if (
            self.similarity_metric == "cosine"
            and self.faiss_index_type == "IndexFlatIP"
            and not self.normalize_embeddings
        ):
            raise DomainValidationError(
                "Cosine search with IndexFlatIP requires normalized embeddings."
            )


@dataclass(
    frozen=True,
    slots=True,
)
class EmbeddingVectorBatch:
    """A validated batch of document vectors."""

    document_ids: tuple[
        str,
        ...,
    ]

    vectors: tuple[
        tuple[
            float,
            ...,
        ],
        ...,
    ]

    dimension: int
    normalized: bool

    def __post_init__(
        self,
    ) -> None:
        _require_positive_integer(
            "dimension",
            self.dimension,
        )

        if not self.document_ids:
            raise DomainValidationError("document_ids must not be empty.")

        if len(self.document_ids) != len(self.vectors):
            raise DomainValidationError(
                "The number of document IDs must equal the number of vectors."
            )

        if len(set(self.document_ids)) != len(self.document_ids):
            raise DomainValidationError("document_ids must be unique within one vector batch.")

        for document_id in self.document_ids:
            _require_non_empty(
                "document_id",
                document_id,
            )

        for position, vector in enumerate(self.vectors):
            if len(vector) != self.dimension:
                raise DomainValidationError(
                    "Vector dimension mismatch "
                    f"at position {position}: "
                    f"expected {self.dimension}, "
                    f"received {len(vector)}."
                )

            if not all(isfinite(value) for value in vector):
                raise DomainValidationError("Embedding vectors must contain only finite numbers.")

            if self.normalized:
                vector_norm = sqrt(sum(value * value for value in vector))

                if not isclose(
                    vector_norm,
                    1.0,
                    rel_tol=1e-4,
                    abs_tol=1e-4,
                ):
                    raise DomainValidationError(
                        "A normalized batch contains a vector whose L2 norm is not approximately 1."
                    )

    @property
    def count(
        self,
    ) -> int:
        """Return the number of vectors."""

        return len(self.vectors)


@dataclass(
    frozen=True,
    slots=True,
)
class ArtifactFileDescriptor:
    """Integrity metadata for a persisted artifact."""

    role: str
    relative_path: str
    sha256: str
    size_bytes: int

    supported_roles: ClassVar[frozenset[str]] = frozenset(
        {
            "faiss_index",
            "document_mapping",
            "embedding_vectors",
        }
    )

    def __post_init__(
        self,
    ) -> None:
        _require_non_empty(
            "role",
            self.role,
        )

        _require_non_empty(
            "relative_path",
            self.relative_path,
        )

        _require_sha256(
            "sha256",
            self.sha256,
        )

        if self.role not in self.supported_roles:
            raise DomainValidationError(f"Unsupported artifact role: {self.role}")

        if self.size_bytes < 0:
            raise DomainValidationError("size_bytes must not be negative.")

        artifact_path = PurePosixPath(self.relative_path)

        if artifact_path.is_absolute():
            raise DomainValidationError("Artifact paths must be relative.")

        if ".." in artifact_path.parts:
            raise DomainValidationError(
                "Artifact paths must not contain parent-directory traversal."
            )


@dataclass(
    frozen=True,
    slots=True,
)
class EmbeddingArtifactManifest:
    """Metadata required to reload vectors safely."""

    created_at_utc: str
    corpus_checksum: str
    document_ids_checksum: str
    retrieval_schema_version: str
    configuration: EmbeddingConfiguration
    embedding_dimension: int
    document_count: int

    artifacts: tuple[
        ArtifactFileDescriptor,
        ...,
    ]

    schema_version: str = "1.0"

    required_artifact_roles: ClassVar[frozenset[str]] = frozenset(
        {
            "faiss_index",
            "document_mapping",
            "embedding_vectors",
        }
    )

    def __post_init__(
        self,
    ) -> None:
        _require_non_empty(
            "created_at_utc",
            self.created_at_utc,
        )

        _require_non_empty(
            "retrieval_schema_version",
            self.retrieval_schema_version,
        )

        _require_non_empty(
            "schema_version",
            self.schema_version,
        )

        _require_sha256(
            "corpus_checksum",
            self.corpus_checksum,
        )

        _require_sha256(
            "document_ids_checksum",
            self.document_ids_checksum,
        )

        _require_positive_integer(
            "embedding_dimension",
            self.embedding_dimension,
        )

        _require_positive_integer(
            "document_count",
            self.document_count,
        )

        try:
            created_at = datetime.fromisoformat(self.created_at_utc)
        except ValueError as error:
            raise DomainValidationError(
                "created_at_utc must be a valid ISO-8601 datetime."
            ) from error

        if created_at.tzinfo is None or created_at.utcoffset() is None:
            raise DomainValidationError("created_at_utc must include timezone information.")

        roles = tuple(artifact.role for artifact in self.artifacts)

        if len(set(roles)) != len(roles):
            raise DomainValidationError("Artifact roles must be unique.")

        if frozenset(roles) != self.required_artifact_roles:
            raise DomainValidationError(
                "The manifest must contain "
                "exactly the FAISS index, "
                "document mapping and "
                "embedding-vector artifacts."
            )

        expected_dimension = self.configuration.expected_dimension

        if expected_dimension is not None and expected_dimension != self.embedding_dimension:
            raise DomainValidationError(
                "Manifest embedding dimension does not match the configured expected dimension."
            )

    def artifact_for(
        self,
        role: str,
    ) -> ArtifactFileDescriptor:
        """Return one artifact by role."""

        for artifact in self.artifacts:
            if artifact.role == role:
                return artifact

        raise DomainValidationError(f"Artifact role was not found: {role}")
