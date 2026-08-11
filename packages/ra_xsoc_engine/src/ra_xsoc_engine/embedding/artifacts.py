from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

import faiss
import numpy as np

from ra_xsoc_engine.domain.embedding import (
    ArtifactFileDescriptor,
    EmbeddingArtifactManifest,
    EmbeddingConfiguration,
    EmbeddingVectorBatch,
)
from ra_xsoc_engine.domain.exceptions import DomainValidationError


class EmbeddingArtifactBuilder:
    """Persist an embedding batch and its FAISS retrieval artifacts."""

    INDEX_FILENAME = "index.faiss"
    MAPPING_FILENAME = "document_mapping.json"
    VECTORS_FILENAME = "embedding_vectors.npy"
    MANIFEST_FILENAME = "manifest.json"

    def __init__(
        self,
        configuration: EmbeddingConfiguration,
    ) -> None:
        self._configuration = configuration

    def write(
        self,
        *,
        vector_batch: EmbeddingVectorBatch,
        output_directory: Path,
        corpus_checksum: str,
        retrieval_schema_version: str,
    ) -> EmbeddingArtifactManifest:
        """Write vectors, document mapping, FAISS index and manifest."""

        self._validate_inputs(
            vector_batch=vector_batch,
            corpus_checksum=corpus_checksum,
            retrieval_schema_version=retrieval_schema_version,
        )

        output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        vectors = np.asarray(
            vector_batch.vectors,
            dtype=np.float32,
        )

        vectors_path = output_directory / self.VECTORS_FILENAME
        mapping_path = output_directory / self.MAPPING_FILENAME
        index_path = output_directory / self.INDEX_FILENAME
        manifest_path = output_directory / self.MANIFEST_FILENAME

        np.save(
            vectors_path,
            vectors,
        )

        mapping = {
            str(position): document_id
            for position, document_id in enumerate(
                vector_batch.document_ids
            )
        }

        mapping_path.write_text(
            json.dumps(
                mapping,
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )

        index = faiss.IndexFlatIP(
            vector_batch.dimension,
        )

        index.add(vectors)

        faiss.write_index(
            index,
            str(index_path),
        )

        artifacts = (
            self._describe_artifact(
                role="faiss_index",
                path=index_path,
            ),
            self._describe_artifact(
                role="document_mapping",
                path=mapping_path,
            ),
            self._describe_artifact(
                role="embedding_vectors",
                path=vectors_path,
            ),
        )

        manifest = EmbeddingArtifactManifest(
            created_at_utc=datetime.now(UTC).isoformat(),
            corpus_checksum=corpus_checksum,
            document_ids_checksum=self._document_ids_checksum(
                vector_batch.document_ids,
            ),
            retrieval_schema_version=retrieval_schema_version,
            configuration=self._configuration,
            embedding_dimension=vector_batch.dimension,
            document_count=vector_batch.count,
            artifacts=artifacts,
        )

        manifest_path.write_text(
            json.dumps(
                self._manifest_to_dict(manifest),
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        return manifest

    def _validate_inputs(
        self,
        *,
        vector_batch: EmbeddingVectorBatch,
        corpus_checksum: str,
        retrieval_schema_version: str,
    ) -> None:
        if len(corpus_checksum) != 64:
            raise DomainValidationError(
                "corpus_checksum must contain exactly 64 hexadecimal characters."
            )

        if any(
            character not in "0123456789abcdef"
            for character in corpus_checksum.lower()
        ):
            raise DomainValidationError(
                "corpus_checksum must be a valid SHA-256 hexadecimal checksum."
            )

        if not retrieval_schema_version or (
            retrieval_schema_version != retrieval_schema_version.strip()
        ):
            raise DomainValidationError(
                "retrieval_schema_version must be non-empty and canonicalized."
            )

        expected_dimension = self._configuration.expected_dimension

        if (
            expected_dimension is not None
            and expected_dimension != vector_batch.dimension
        ):
            raise DomainValidationError(
                "Embedding vector dimension does not match configuration: "
                f"expected {expected_dimension}, "
                f"received {vector_batch.dimension}."
            )

        if vector_batch.normalized != self._configuration.normalize_embeddings:
            raise DomainValidationError(
                "Vector batch normalization state does not match "
                "the embedding configuration."
            )

    @staticmethod
    def _document_ids_checksum(
        document_ids: tuple[str, ...],
    ) -> str:
        canonical_value = "\n".join(document_ids) + "\n"

        return sha256(
            canonical_value.encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _describe_artifact(
        *,
        role: str,
        path: Path,
    ) -> ArtifactFileDescriptor:
        data = path.read_bytes()

        return ArtifactFileDescriptor(
            role=role,
            relative_path=path.name,
            sha256=sha256(data).hexdigest(),
            size_bytes=len(data),
        )

    @staticmethod
    def _manifest_to_dict(
        manifest: EmbeddingArtifactManifest,
    ) -> dict[str, Any]:
        return {
            "schema_version": manifest.schema_version,
            "created_at_utc": manifest.created_at_utc,
            "corpus_checksum": manifest.corpus_checksum,
            "document_ids_checksum": manifest.document_ids_checksum,
            "retrieval_schema_version": manifest.retrieval_schema_version,
            "embedding_dimension": manifest.embedding_dimension,
            "document_count": manifest.document_count,
            "configuration": {
                "model_name": manifest.configuration.model_name,
                "model_revision": manifest.configuration.model_revision,
                "device": manifest.configuration.device,
                "batch_size": manifest.configuration.batch_size,
                "normalize_embeddings": (
                    manifest.configuration.normalize_embeddings
                ),
                "similarity_metric": (
                    manifest.configuration.similarity_metric
                ),
                "faiss_index_type": (
                    manifest.configuration.faiss_index_type
                ),
                "vector_dtype": (
                    manifest.configuration.vector_dtype
                ),
                "expected_dimension": (
                    manifest.configuration.expected_dimension
                ),
                "schema_version": (
                    manifest.configuration.schema_version
                ),
            },
            "artifacts": [
                {
                    "role": artifact.role,
                    "relative_path": artifact.relative_path,
                    "sha256": artifact.sha256,
                    "size_bytes": artifact.size_bytes,
                }
                for artifact in manifest.artifacts
            ],
        }