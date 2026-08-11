from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

import faiss
import numpy as np

from ra_xsoc_engine.domain.embedding import EmbeddingArtifactManifest
from ra_xsoc_engine.domain.exceptions import DomainValidationError


class EmbeddingArtifactValidator:
    """Validate persisted embedding and FAISS artifacts before loading."""

    INDEX_FILENAME = "index.faiss"
    MAPPING_FILENAME = "document_mapping.json"
    VECTORS_FILENAME = "embedding_vectors.npy"
    MANIFEST_FILENAME = "manifest.json"

    def validate(
        self,
        artifact_directory: Path,
    ) -> EmbeddingArtifactManifest:
        """Validate all persisted artifacts and return the manifest."""

        if not artifact_directory.is_dir():
            raise DomainValidationError(
                f"Embedding artifact directory does not exist: {artifact_directory}"
            )

        manifest_path = artifact_directory / self.MANIFEST_FILENAME

        if not manifest_path.is_file():
            raise DomainValidationError(
                f"Embedding artifact manifest was not found: {manifest_path}"
            )

        manifest = self._load_manifest(manifest_path)

        self._validate_artifact_files(
            artifact_directory,
            manifest,
        )

        mapping = self._load_mapping(
            artifact_directory / self.MAPPING_FILENAME,
        )

        vectors = self._load_vectors(
            artifact_directory / self.VECTORS_FILENAME,
        )

        index = self._load_faiss_index(
            artifact_directory / self.INDEX_FILENAME,
        )

        self._validate_mapping(
            mapping,
            manifest,
        )

        self._validate_vectors(
            vectors,
            manifest,
        )

        self._validate_index(
            index,
            manifest,
        )

        return manifest

    @staticmethod
    def _load_manifest(
        path: Path,
    ) -> EmbeddingArtifactManifest:
        try:
            payload: dict[str, Any] = json.loads(
                path.read_text(
                    encoding="utf-8",
                )
            )
        except (OSError, json.JSONDecodeError) as error:
            raise DomainValidationError(
                f"Could not load embedding artifact manifest: {path}"
            ) from error

        try:
            configuration_payload = payload["configuration"]

            from ra_xsoc_engine.domain.embedding import (
                ArtifactFileDescriptor,
                EmbeddingConfiguration,
            )

            configuration = EmbeddingConfiguration(
                model_name=configuration_payload["model_name"],
                model_revision=configuration_payload.get("model_revision"),
                device=configuration_payload["device"],
                batch_size=configuration_payload["batch_size"],
                normalize_embeddings=configuration_payload[
                    "normalize_embeddings"
                ],
                similarity_metric=configuration_payload["similarity_metric"],
                faiss_index_type=configuration_payload["faiss_index_type"],
                vector_dtype=configuration_payload["vector_dtype"],
                expected_dimension=configuration_payload.get(
                    "expected_dimension"
                ),
                schema_version=configuration_payload["schema_version"],
            )

            artifacts = tuple(
                ArtifactFileDescriptor(
                    role=artifact["role"],
                    relative_path=artifact["relative_path"],
                    sha256=artifact["sha256"],
                    size_bytes=artifact["size_bytes"],
                )
                for artifact in payload["artifacts"]
            )

            return EmbeddingArtifactManifest(
                created_at_utc=payload["created_at_utc"],
                corpus_checksum=payload["corpus_checksum"],
                document_ids_checksum=payload["document_ids_checksum"],
                retrieval_schema_version=payload[
                    "retrieval_schema_version"
                ],
                configuration=configuration,
                embedding_dimension=payload["embedding_dimension"],
                document_count=payload["document_count"],
                artifacts=artifacts,
                schema_version=payload.get(
                    "schema_version",
                    "1.0",
                ),
            )

        except (KeyError, TypeError, ValueError) as error:
            raise DomainValidationError(
                f"Embedding artifact manifest has an invalid structure: {path}"
            ) from error

    @staticmethod
    def _validate_artifact_files(
        artifact_directory: Path,
        manifest: EmbeddingArtifactManifest,
    ) -> None:
        for artifact in manifest.artifacts:
            path = artifact_directory / artifact.relative_path

            if not path.is_file():
                raise DomainValidationError(
                    f"Required embedding artifact is missing: {path.name}"
                )

            data = path.read_bytes()

            actual_size = len(data)

            if actual_size != artifact.size_bytes:
                raise DomainValidationError(
                    f"Artifact size mismatch for {artifact.relative_path}: "
                    f"expected {artifact.size_bytes}, "
                    f"received {actual_size}."
                )

            actual_sha256 = sha256(data).hexdigest()

            if actual_sha256 != artifact.sha256:
                raise DomainValidationError(
                    f"Artifact checksum mismatch for {artifact.relative_path}."
                )

    @staticmethod
    def _load_mapping(
        path: Path,
    ) -> dict[str, str]:
        try:
            payload = json.loads(
                path.read_text(
                    encoding="utf-8",
                )
            )
        except (OSError, json.JSONDecodeError) as error:
            raise DomainValidationError(
                f"Could not load document mapping: {path}"
            ) from error

        if not isinstance(payload, dict):
            raise DomainValidationError(
                "Document mapping must contain a JSON object."
            )

        mapping: dict[str, str] = {}

        for position, document_id in payload.items():
            if not isinstance(position, str):
                raise DomainValidationError(
                    "Document mapping positions must be strings."
                )

            if not isinstance(document_id, str) or not document_id.strip():
                raise DomainValidationError(
                    "Document mapping IDs must be non-empty strings."
                )

            mapping[position] = document_id

        return mapping

    @staticmethod
    def _load_vectors(
        path: Path,
    ) -> np.ndarray:
        try:
            vectors = np.load(
                path,
                allow_pickle=False,
            )
        except (OSError, ValueError) as error:
            raise DomainValidationError(
                f"Could not load embedding vectors: {path}"
            ) from error

        if not isinstance(vectors, np.ndarray):
            raise DomainValidationError(
                "Embedding vectors must be a NumPy array."
            )

        if vectors.dtype != np.float32:
            raise DomainValidationError(
                f"Embedding vectors must use float32, received {vectors.dtype}."
            )

        if vectors.ndim != 2:
            raise DomainValidationError(
                "Embedding vectors must be a two-dimensional array."
            )

        if not np.isfinite(vectors).all():
            raise DomainValidationError(
                "Embedding vectors must contain only finite values."
            )

        return vectors

    @staticmethod
    def _load_faiss_index(
        path: Path,
    ) -> faiss.Index:
        try:
            return faiss.read_index(str(path))
        except Exception as error:
            raise DomainValidationError(
                f"Could not load FAISS index: {path}"
            ) from error

    @staticmethod
    def _validate_mapping(
        mapping: dict[str, str],
        manifest: EmbeddingArtifactManifest,
    ) -> None:
        expected_positions = {
            str(position)
            for position in range(manifest.document_count)
        }

        if set(mapping) != expected_positions:
            raise DomainValidationError(
                "Document mapping positions do not match the manifest "
                "document count."
            )

        document_ids = tuple(
            mapping[str(position)]
            for position in range(manifest.document_count)
        )

        if len(set(document_ids)) != len(document_ids):
            raise DomainValidationError(
                "Document mapping contains duplicate document IDs."
            )

        canonical_value = "\n".join(document_ids) + "\n"

        actual_checksum = sha256(
            canonical_value.encode("utf-8")
        ).hexdigest()

        if actual_checksum != manifest.document_ids_checksum:
            raise DomainValidationError(
                "Document mapping checksum does not match the manifest."
            )

    @staticmethod
    def _validate_vectors(
        vectors: np.ndarray,
        manifest: EmbeddingArtifactManifest,
    ) -> None:
        expected_shape = (
            manifest.document_count,
            manifest.embedding_dimension,
        )

        if vectors.shape != expected_shape:
            raise DomainValidationError(
                "Embedding vector shape does not match the manifest: "
                f"expected {expected_shape}, "
                f"received {vectors.shape}."
            )

        if manifest.configuration.normalize_embeddings:
            norms = np.linalg.norm(
                vectors,
                axis=1,
            )

            if not np.allclose(
                norms,
                1.0,
                rtol=1e-4,
                atol=1e-4,
            ):
                raise DomainValidationError(
                    "Persisted vectors are configured as normalized "
                    "but contain vectors whose L2 norm is not approximately 1."
                )

    @staticmethod
    def _validate_index(
        index: faiss.Index,
        manifest: EmbeddingArtifactManifest,
    ) -> None:
        if index.d != manifest.embedding_dimension:
            raise DomainValidationError(
                "FAISS index dimension does not match the manifest: "
                f"expected {manifest.embedding_dimension}, "
                f"received {index.d}."
            )

        if index.ntotal != manifest.document_count:
            raise DomainValidationError(
                "FAISS index document count does not match the manifest: "
                f"expected {manifest.document_count}, "
                f"received {index.ntotal}."
            )

        if (
            manifest.configuration.faiss_index_type == "IndexFlatIP"
            and not isinstance(index, faiss.IndexFlatIP)
        ):
            raise DomainValidationError(
                "Persisted FAISS index is not the configured IndexFlatIP."
            )