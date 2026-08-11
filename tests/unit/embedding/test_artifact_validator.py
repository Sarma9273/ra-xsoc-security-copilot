from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest
from ra_xsoc_engine.domain.embedding import (
    EmbeddingArtifactManifest,
)
from ra_xsoc_engine.domain.exceptions import DomainValidationError
from ra_xsoc_engine.embedding.artifact_validator import (
    EmbeddingArtifactValidator,
)
from ra_xsoc_engine.embedding.artifacts import (
    EmbeddingArtifactBuilder,
)

from tests.unit.embedding.test_artifacts import (
    build_batch,
    build_configuration,
)


def build_artifacts(
    tmp_path: Path,
) -> EmbeddingArtifactManifest:
    """Create a complete valid embedding artifact set."""

    builder = EmbeddingArtifactBuilder(
        configuration=build_configuration(),
    )

    return builder.write(
        vector_batch=build_batch(),
        output_directory=tmp_path,
        corpus_checksum="a" * 64,
        retrieval_schema_version="1.0",
    )


def test_validator_accepts_valid_artifacts(
    tmp_path: Path,
) -> None:
    """A valid artifact set must pass validation."""

    manifest = build_artifacts(tmp_path)

    validated = EmbeddingArtifactValidator().validate(
        tmp_path,
    )

    assert validated.corpus_checksum == manifest.corpus_checksum
    assert validated.document_count == 2
    assert validated.embedding_dimension == 3


def test_validator_rejects_missing_manifest(
    tmp_path: Path,
) -> None:
    """Validation must fail when the manifest is missing."""

    with pytest.raises(
        DomainValidationError,
        match="manifest was not found",
    ):
        EmbeddingArtifactValidator().validate(
            tmp_path,
        )


def test_validator_rejects_missing_artifact(
    tmp_path: Path,
) -> None:
    """Validation must fail when a required artifact is missing."""

    build_artifacts(tmp_path)

    (tmp_path / "index.faiss").unlink()

    with pytest.raises(
        DomainValidationError,
        match="artifact is missing",
    ):
        EmbeddingArtifactValidator().validate(
            tmp_path,
        )


def test_validator_rejects_modified_artifact(
    tmp_path: Path,
) -> None:
    """Validation must detect byte-level artifact tampering."""

    build_artifacts(tmp_path)

    path = tmp_path / "embedding_vectors.npy"

    data = bytearray(
        path.read_bytes(),
    )

    data[-1] ^= 0xFF

    path.write_bytes(data)

    with pytest.raises(
        DomainValidationError,
        match="checksum mismatch",
    ):
        EmbeddingArtifactValidator().validate(
            tmp_path,
        )


def test_validator_rejects_mapping_mismatch(
    tmp_path: Path,
) -> None:
    """Validation must reject a modified document mapping."""

    build_artifacts(tmp_path)

    mapping_path = tmp_path / "document_mapping.json"

    mapping = json.loads(
        mapping_path.read_text(
            encoding="utf-8",
        )
    )

    mapping["0"] = "retrieval:tampered:1.0"

    mapping_path.write_text(
        json.dumps(
            mapping,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        DomainValidationError,
        match="Artifact size mismatch|Artifact checksum mismatch",
    ):
        EmbeddingArtifactValidator().validate(
            tmp_path,
        )


def test_validator_rejects_wrong_vector_shape(
    tmp_path: Path,
) -> None:
    """Validation must reject vectors whose persisted shape was altered."""

    build_artifacts(tmp_path)

    np.save(
        tmp_path / "embedding_vectors.npy",
        np.ones(
            (2, 4),
            dtype=np.float32,
        ),
    )

    with pytest.raises(
        DomainValidationError,
        match="Artifact size mismatch|Artifact checksum mismatch",
    ):
        EmbeddingArtifactValidator().validate(
            tmp_path,
        )


def test_validator_rejects_wrong_vector_dimension(
    tmp_path: Path,
) -> None:
    """Validation must reject vectors with an altered dimension."""

    build_artifacts(tmp_path)

    vectors = np.load(
        tmp_path / "embedding_vectors.npy",
    )

    vectors = vectors[:, :2]

    np.save(
        tmp_path / "embedding_vectors.npy",
        vectors,
    )

    with pytest.raises(
        DomainValidationError,
        match="Artifact size mismatch|Artifact checksum mismatch",
    ):
        EmbeddingArtifactValidator().validate(
            tmp_path,
        )


def test_validator_rejects_non_float32_vectors(
    tmp_path: Path,
) -> None:
    """Validation must reject vectors persisted with the wrong dtype."""

    build_artifacts(tmp_path)

    np.save(
        tmp_path / "embedding_vectors.npy",
        np.ones(
            (2, 3),
            dtype=np.float64,
        ),
    )

    with pytest.raises(
        DomainValidationError,
        match="Artifact size mismatch|Artifact checksum mismatch",
    ):
        EmbeddingArtifactValidator().validate(
            tmp_path,
        )