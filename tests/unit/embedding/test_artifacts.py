from __future__ import annotations

import json
from pathlib import Path

import faiss
import numpy as np
import pytest
from ra_xsoc_engine.domain.embedding import (
    EmbeddingConfiguration,
    EmbeddingVectorBatch,
)
from ra_xsoc_engine.domain.exceptions import DomainValidationError
from ra_xsoc_engine.embedding.artifacts import (
    EmbeddingArtifactBuilder,
)


def build_configuration() -> EmbeddingConfiguration:
    return EmbeddingConfiguration(
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        expected_dimension=3,
        batch_size=16,
        normalize_embeddings=True,
        similarity_metric="cosine",
        faiss_index_type="IndexFlatIP",
        vector_dtype="float32",
    )


def build_batch() -> EmbeddingVectorBatch:
    return EmbeddingVectorBatch(
        document_ids=(
            "retrieval:a:1.0",
            "retrieval:b:1.0",
        ),
        vectors=(
            (
                1.0,
                0.0,
                0.0,
            ),
            (
                0.0,
                1.0,
                0.0,
            ),
        ),
        dimension=3,
        normalized=True,
    )


def test_builder_writes_required_artifacts(
    tmp_path: Path,
) -> None:
    builder = EmbeddingArtifactBuilder(
        configuration=build_configuration(),
    )

    manifest = builder.write(
        vector_batch=build_batch(),
        output_directory=tmp_path,
        corpus_checksum="a" * 64,
        retrieval_schema_version="1.0",
    )

    assert (tmp_path / "embedding_vectors.npy").exists()
    assert (tmp_path / "document_mapping.json").exists()
    assert (tmp_path / "index.faiss").exists()
    assert (tmp_path / "manifest.json").exists()

    assert manifest.document_count == 2
    assert manifest.embedding_dimension == 3


def test_vectors_are_persisted_as_float32(
    tmp_path: Path,
) -> None:
    builder = EmbeddingArtifactBuilder(
        configuration=build_configuration(),
    )

    builder.write(
        vector_batch=build_batch(),
        output_directory=tmp_path,
        corpus_checksum="a" * 64,
        retrieval_schema_version="1.0",
    )

    vectors = np.load(
        tmp_path / "embedding_vectors.npy",
    )

    assert vectors.dtype == np.float32
    assert vectors.shape == (2, 3)


def test_document_mapping_matches_vector_positions(
    tmp_path: Path,
) -> None:
    builder = EmbeddingArtifactBuilder(
        configuration=build_configuration(),
    )

    builder.write(
        vector_batch=build_batch(),
        output_directory=tmp_path,
        corpus_checksum="a" * 64,
        retrieval_schema_version="1.0",
    )

    mapping = json.loads(
        (tmp_path / "document_mapping.json").read_text(
            encoding="utf-8",
        )
    )

    assert mapping == {
        "0": "retrieval:a:1.0",
        "1": "retrieval:b:1.0",
    }


def test_faiss_index_uses_expected_dimension_and_count(
    tmp_path: Path,
) -> None:
    builder = EmbeddingArtifactBuilder(
        configuration=build_configuration(),
    )

    builder.write(
        vector_batch=build_batch(),
        output_directory=tmp_path,
        corpus_checksum="a" * 64,
        retrieval_schema_version="1.0",
    )

    index = faiss.read_index(
        str(tmp_path / "index.faiss"),
    )

    assert index.d == 3
    assert index.ntotal == 2
    assert isinstance(index, faiss.IndexFlatIP)


def test_manifest_contains_all_required_artifact_roles(
    tmp_path: Path,
) -> None:
    builder = EmbeddingArtifactBuilder(
        configuration=build_configuration(),
    )

    manifest = builder.write(
        vector_batch=build_batch(),
        output_directory=tmp_path,
        corpus_checksum="a" * 64,
        retrieval_schema_version="1.0",
    )

    roles = {
        artifact.role
        for artifact in manifest.artifacts
    }

    assert roles == {
        "faiss_index",
        "document_mapping",
        "embedding_vectors",
    }


def test_manifest_records_artifact_sizes_and_checksums(
    tmp_path: Path,
) -> None:
    builder = EmbeddingArtifactBuilder(
        configuration=build_configuration(),
    )

    manifest = builder.write(
        vector_batch=build_batch(),
        output_directory=tmp_path,
        corpus_checksum="a" * 64,
        retrieval_schema_version="1.0",
    )

    for artifact in manifest.artifacts:
        path = tmp_path / artifact.relative_path

        assert path.exists()
        assert artifact.size_bytes == path.stat().st_size
        assert len(artifact.sha256) == 64


def test_invalid_corpus_checksum_is_rejected(
    tmp_path: Path,
) -> None:
    builder = EmbeddingArtifactBuilder(
        configuration=build_configuration(),
    )

    with pytest.raises(DomainValidationError):
        builder.write(
            vector_batch=build_batch(),
            output_directory=tmp_path,
            corpus_checksum="not-a-checksum",
            retrieval_schema_version="1.0",
        )


def test_dimension_mismatch_is_rejected(
    tmp_path: Path,
) -> None:
    configuration = EmbeddingConfiguration(
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        expected_dimension=384,
    )

    builder = EmbeddingArtifactBuilder(
        configuration=configuration,
    )

    batch = EmbeddingVectorBatch(
        document_ids=("retrieval:a:1.0",),
        vectors=(
            (
                1.0,
                0.0,
                0.0,
            ),
        ),
        dimension=3,
        normalized=True,
    )

    with pytest.raises(DomainValidationError):
        builder.write(
            vector_batch=batch,
            output_directory=tmp_path,
            corpus_checksum="a" * 64,
            retrieval_schema_version="1.0",
        )