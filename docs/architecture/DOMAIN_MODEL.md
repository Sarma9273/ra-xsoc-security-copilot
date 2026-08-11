# RA-XSOC Domain Model

## Purpose

The domain layer defines the central security concepts used by
RA-XSOC.

It does not depend on:

- Streamlit
- React
- FastAPI
- PostgreSQL
- SQLAlchemy
- FAISS
- SentenceTransformers

## Core Flow

IncidentInput
    ↓
AttackRetriever
    ↓
AttackMatch
    ↓
Severity and Novelty Assessment
    ↓
ResponsePlaybook
    ↓
AnalysisResult
    ↓
AnalystFeedback

## Main Objects

### IncidentInput

Represents unstructured security information submitted for analysis.

### AttackMatch

Represents a probable attack category and its semantic, keyword,
and hybrid scores.

### MitreTechnique

Represents a MITRE ATT&CK technique associated with a match.

### ResponsePlaybook

Contains structured containment, investigation, recovery,
prevention, and detection guidance.

### AnalysisResult

Contains matches, confidence, severity, novelty status,
explanations, and review requirements.

### AnalystFeedback

Records whether an analyst approved, corrected, or rejected
an analysis.

## Architectural Rule

Infrastructure must depend on the domain layer.

The domain layer must never depend on infrastructure.
