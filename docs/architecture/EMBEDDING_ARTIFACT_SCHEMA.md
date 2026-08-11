# Embedding and Artifact Domain Schema

## Purpose

Phase 1.4 introduces semantic-vector generation and a persisted FAISS search index.

The domain layer defines validation rules without importing NumPy, FAISS, PyTorch or SentenceTransformers.

## Domain models

- `EmbeddingConfiguration`: model and vector-generation rules.
- `EmbeddingVectorBatch`: ordered IDs and validated vectors.
- `ArtifactFileDescriptor`: path, role, checksum and byte size.
- `EmbeddingArtifactManifest`: compatibility and integrity metadata.

## Initial search design

- Cosine similarity
- L2-normalized vectors
- FAISS `IndexFlatIP`
- `float32` vector storage

## Planned persisted files

    embedding_artifacts/
    ├── index.faiss
    ├── document_mapping.json
    ├── embedding_vectors.npy
    └── embedding_manifest.json

## Rebuild conditions

- Retrieval corpus checksum changed
- Ordered document-ID checksum changed
- Embedding model or revision changed
- Embedding dimension changed
- Normalization, similarity metric, index type or vector dtype changed
- Any persisted artifact failed integrity verification
