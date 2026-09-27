# Embedding Service and Deterministic Ordering

## Purpose

The domain exposes an `EmbeddingService` port, while the concrete SentenceTransformer adapter lives at the infrastructure boundary. Deterministic preparation utilities keep document ordering and artifact identity stable without coupling the domain to a specific ML library.

## Ordering contract

Documents are validated and sorted by `document_id` before embedding.

The utility guarantees that:

- Document IDs are non-empty and unique.
- Retrieval text is canonicalized.
- IDs and texts remain positionally aligned.
- Input order cannot change artifact identity.
- Ordered IDs receive a stable SHA-256 checksum.

## Pipeline boundary

```
Retrieval documents
        ↓
deterministic ordering
        ↓
aligned IDs and texts
        ↓
EmbeddingService port
        ↓
SentenceTransformer adapter
        ↓
EmbeddingVectorBatch
```

The production/research implementation is already present and is exercised by the retrieval corpus and embedding generation pipeline.
