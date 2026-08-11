# RA-XSOC Retrieval Corpus

## Purpose

The retrieval corpus is the deterministic collection of
focused attack documents that will later be embedded with
SentenceTransformers and indexed using FAISS.

## Source

The corpus is created from the validated normalized knowledge
records in schema version 1.0.

The normalized records remain unchanged.

## Generated artifacts

- one JSON file per attack
- corpus.jsonl
- manifest.json
- validation_summary.json

## Classification text

The retrieval text includes:

- incident type
- description
- threat-framework mappings
- indicators
- detection rules
- affected assets

Generic playbook and supporting information are excluded from
classification text.

## Determinism

The same source records and retrieval schema must produce:

- the same ordered retrieval documents
- the same content checksums
- the same corpus checksum

## Next stage

Phase 1.4 will convert retrieval text into normalized embedding
vectors and construct a persisted FAISS index.
