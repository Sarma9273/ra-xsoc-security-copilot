# RA-XSOC Retrieval Document

## Purpose

A RetrievalDocument is a focused searchable version of an
AttackKnowledgeRecord.

The complete knowledge record remains available for response
guidance, reporting and analyst explanation.

## Included in retrieval text

- incident type
- description
- threat-framework references
- indicators
- detection rules
- affected assets

## Excluded from retrieval text

- containment
- investigation
- recovery
- prevention
- references
- tools
- real-world examples
- keywords

These fields remain in the complete knowledge record.

They are excluded from the first classification corpus because
generic response instructions may appear across many attack
categories and reduce retrieval precision.

## Determinism

The same AttackKnowledgeRecord must always produce:

- the same retrieval text
- the same document ID
- the same content checksum

## Provenance

Every RetrievalDocument preserves:

- source filename
- source-record SHA-256 checksum
- knowledge schema version
- retrieval schema version
