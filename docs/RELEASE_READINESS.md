# RA-XSOC-X Release Readiness

## Definition of 1000% completion

The project is considered release-complete only when every required engineering layer is present, reproducible, tested, documented, and demonstrable.

### Gates

- [x] Domain models and validation
- [x] Versioned knowledge base
- [x] Deterministic retrieval corpus
- [x] SentenceTransformer embeddings
- [x] Persisted FAISS artifact format and validation
- [x] Semantic retrieval
- [x] Lexical scoring and hybrid ranking
- [x] Explainable analysis API
- [x] Structured API error contract
- [x] Request correlation IDs
- [x] Browser demo engine
- [x] Human-review UX
- [x] Investigation planner
- [x] Novelty/evidence presentation
- [x] MITRE verification path
- [x] GitHub Pages deployment path
- [ ] Full backend investigation-state persistence
- [ ] Authentication/RBAC
- [x] Analyst case/history persistence
- [ ] Durable analyst feedback store
- [ ] PDF/HTML report generation
- [ ] Production database migrations
- [x] Security scanning and dependency policy
- [ ] Versioned benchmark results committed as release evidence
- [ ] Final release tag and reproducibility record

## Non-goals

SIEM/EDR connectors, multi-tenancy, automated containment, and production threat-intelligence integrations remain optional expansion tracks unless explicitly promoted into the release scope.
