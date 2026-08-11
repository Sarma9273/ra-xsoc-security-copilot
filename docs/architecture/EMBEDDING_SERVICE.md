# Embedding Service and Deterministic Ordering

## Purpose

The domain already exposes an `EmbeddingService` port. Phase 1.4A.3 adds deterministic preparation utilities without coupling the domain to SentenceTransformers.

## Ordering contract

Documents are validated and sorted by `document_id` before embedding.

The utility guarantees that:

- Document IDs are non-empty and unique.
- Retrieval text is canonicalized.
- IDs and texts remain positionally aligned.
- Input order cannot change artifact identity.
- Ordered IDs receive a stable SHA-256 checksum.

## Pipeline boundary

    Retrieval documents
            ↓
    deterministic ordering
            ↓
    aligned IDs and texts
            ↓
    EmbeddingService port
            ↓
    EmbeddingVectorBatch

The SentenceTransformer adapter will be implemented in Phase 1.4B.
