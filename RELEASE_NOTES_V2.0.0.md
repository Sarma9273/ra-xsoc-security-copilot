# RA-XSOC-X v2.0.0

## Release status

RA-XSOC-X V2.0.0 is the verified V2.0 engineering baseline for evidence-driven security investigation intelligence.

## Included

- SentenceTransformer + FAISS semantic retrieval
- lexical fallback retrieval
- evidence normalization and incident state
- competing hypotheses and investigation planning
- evidence verification
- security knowledge graph
- MITRE ATT&CK verification path
- analyst feedback and experience memory
- investigation replay
- HTML/PDF investigation reports
- FastAPI analysis and case/feedback/report APIs
- authentication and role-based authorization
- React/Vite analyst frontend
- deterministic synthetic GitHub Pages demonstration
- automated Python and frontend CI
- dependency/security scanning
- reproducible retrieval evaluation

## Verification boundary

The fixed 30-case benchmark demonstrates reproducibility of the versioned retrieval evaluation. It is not a held-out or real-world detection-accuracy claim.

The GitHub Pages demonstration is synthetic and read-only. The V2.0 release does not claim autonomous containment, arbitrary command execution, or live SIEM/EDR/network/identity telemetry ingestion.

## Next-stage scope

The following remain outside V2.0 and require additional infrastructure or evaluation:

- live telemetry connectors
- production hosting of FastAPI, FAISS, and PostgreSQL
- held-out/adversarial evaluation
- autonomous response/containment
