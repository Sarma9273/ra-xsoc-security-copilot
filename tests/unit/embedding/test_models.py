from __future__ import annotations

from math import inf
from typing import Any

import pytest
from ra_xsoc_engine.domain.embedding import (
    ArtifactFileDescriptor,
    EmbeddingArtifactManifest,
    EmbeddingConfiguration,
    EmbeddingVectorBatch,
)
from ra_xsoc_engine.domain.exceptions import (
    DomainValidationError,
)


def build_configuration(
    *,
    expected_dimension: int | None = 2,
) -> EmbeddingConfiguration:
    return EmbeddingConfiguration(
        model_name=("sentence-transformers/all-MiniLM-L6-v2"),
        expected_dimension=(expected_dimension),
    )


def build_artifacts() -> tuple[
    ArtifactFileDescriptor,
    ...,
]:
    return (
        ArtifactFileDescriptor(
            role="faiss_index",
            relative_path="index.faiss",
            sha256="a" * 64,
            size_bytes=100,
        ),
        ArtifactFileDescriptor(
            role="document_mapping",
            relative_path=("document_mapping.json"),
            sha256="b" * 64,
            size_bytes=200,
        ),
        ArtifactFileDescriptor(
            role="embedding_vectors",
            relative_path=("embedding_vectors.npy"),
            sha256="c" * 64,
            size_bytes=300,
        ),
    )


def build_manifest(
    *,
    expected_dimension: int | None = 2,
    embedding_dimension: int = 2,
    artifacts: tuple[
        ArtifactFileDescriptor,
        ...,
    ]
    | None = None,
    created_at_utc: str = ("2026-07-24T12:00:00+00:00"),
) -> EmbeddingArtifactManifest:
    return EmbeddingArtifactManifest(
        created_at_utc=created_at_utc,
        corpus_checksum="d" * 64,
        document_ids_checksum="e" * 64,
        retrieval_schema_version="1.0",
        configuration=build_configuration(expected_dimension=(expected_dimension)),
        embedding_dimension=(embedding_dimension),
        document_count=30,
        artifacts=(artifacts if artifacts is not None else build_artifacts()),
    )


def test_embedding_configuration_is_valid() -> None:
    configuration = build_configuration()

    assert configuration.batch_size == 32

    assert configuration.normalize_embeddings

    assert configuration.faiss_index_type == "IndexFlatIP"

    assert configuration.vector_dtype == "float32"


@pytest.mark.parametrize(
    "overrides",
    [
        {
            "model_name": "",
        },
        {
            "model_name": "example-model",
            "batch_size": 0,
        },
        {
            "model_name": "example-model",
            "similarity_metric": "euclidean",
        },
        {
            "model_name": "example-model",
            "normalize_embeddings": False,
        },
    ],
)
def test_configuration_rejects_invalid_values(
    overrides: dict[
        str,
        Any,
    ],
) -> None:
    with pytest.raises(DomainValidationError):
        EmbeddingConfiguration(**overrides)


def test_vector_batch_accepts_unit_vectors() -> None:
    batch = EmbeddingVectorBatch(
        document_ids=(
            "retrieval:a:1.0",
            "retrieval:b:1.0",
        ),
        vectors=(
            (
                1.0,
                0.0,
            ),
            (
                0.0,
                1.0,
            ),
        ),
        dimension=2,
        normalized=True,
    )

    assert batch.count == 2


@pytest.mark.parametrize(
    ("document_ids,vectors,dimension,normalized"),
    [
        (
            ("retrieval:a:1.0",),
            (
                (
                    1.0,
                    0.0,
                ),
                (
                    0.0,
                    1.0,
                ),
            ),
            2,
            True,
        ),
        (
            (
                "retrieval:a:1.0",
                "retrieval:a:1.0",
            ),
            (
                (
                    1.0,
                    0.0,
                ),
                (
                    0.0,
                    1.0,
                ),
            ),
            2,
            True,
        ),
        (
            ("retrieval:a:1.0",),
            (
                (
                    1.0,
                    0.0,
                    0.0,
                ),
            ),
            2,
            True,
        ),
        (
            ("retrieval:a:1.0",),
            (
                (
                    inf,
                    0.0,
                ),
            ),
            2,
            False,
        ),
        (
            ("retrieval:a:1.0",),
            (
                (
                    1.0,
                    1.0,
                ),
            ),
            2,
            True,
        ),
    ],
)
def test_vector_batch_rejects_invalid_values(
    document_ids: tuple[
        str,
        ...,
    ],
    vectors: tuple[
        tuple[
            float,
            ...,
        ],
        ...,
    ],
    dimension: int,
    normalized: bool,
) -> None:
    with pytest.raises(DomainValidationError):
        EmbeddingVectorBatch(
            document_ids=document_ids,
            vectors=vectors,
            dimension=dimension,
            normalized=normalized,
        )


@pytest.mark.parametrize(
    "relative_path,sha256",
    [
        (
            "../index.faiss",
            "a" * 64,
        ),
        (
            "index.faiss",
            "not-a-checksum",
        ),
    ],
)
def test_artifact_rejects_invalid_values(
    relative_path: str,
    sha256: str,
) -> None:
    with pytest.raises(DomainValidationError):
        ArtifactFileDescriptor(
            role="faiss_index",
            relative_path=(relative_path),
            sha256=sha256,
            size_bytes=100,
        )


def test_manifest_accepts_required_artifacts() -> None:
    manifest = build_manifest()

    assert manifest.artifact_for("faiss_index").relative_path == "index.faiss"


@pytest.mark.parametrize(
    "kwargs",
    [
        {
            "artifacts": build_artifacts()[:2],
        },
        {
            "expected_dimension": 384,
            "embedding_dimension": 2,
        },
        {
            "created_at_utc": "2026-07-24T12:00:00",
        },
    ],
)
def test_manifest_rejects_invalid_values(
    kwargs: dict[
        str,
        Any,
    ],
) -> None:
    with pytest.raises(DomainValidationError):
        build_manifest(**kwargs)
