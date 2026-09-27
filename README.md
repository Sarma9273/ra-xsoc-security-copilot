# RA-XSOC-X

**Evidence-Driven Adaptive Investigation Intelligence for Security Operations**

RA-XSOC-X extends the RA-XSOC V2 retrieval stack toward an evidence-driven investigation loop:

```
Incident → Evidence → State → Hypotheses → Investigation → Verification
        → ATT&CK Mapping → Human Review → Feedback → Experience Memory
```

## Verified release state

The current `master` head verified on **2026-09-28** is **`d22f81348000ae00f4632e568b286d4b74d40009`**.

The release gates for that exact baseline are green:

- Python CI
- Frontend lint/build
- Dependency/security scan
- GitHub Pages deployment

The fixed 30-case retrieval benchmark is a reproducibility check, not held-out real-world detection validation. See [verification evidence](docs/VERIFICATION_2026-09-27.md).

## Public demo

The demonstration is designed for **GitHub Pages** and runs its deterministic demo engine in the browser. The full Python/FastAPI research engine remains in this repository for local execution, experiments, and reproducible evaluation.

## Runtime boundaries

- The API uses SentenceTransformer + FAISS retrieval by default.
- Set `RA_XSOC_RETRIEVER=lexical` only for constrained deployments that intentionally cannot load the ML stack.
- Authentication is required outside `development` and `test` unless explicitly overridden with `RA_XSOC_AUTH_REQUIRED`.
- Analysis, case access, feedback, and reports are protected by role-based authorization.
- Retrieval-derived signals are decision support; they are not independent SIEM, EDR, network, identity, or authorization evidence.
- The current API does not claim autonomous containment or real-time external telemetry ingestion.

## Implemented research capabilities

- versioned security knowledge base
- SentenceTransformer + FAISS retrieval
- lexical fallback retrieval
- evidence normalization and incident state
- competing hypotheses
- information-gain investigation planning
- evidence verification
- security knowledge graph
- MITRE ATT&CK verification path
- analyst feedback and experience memory
- investigation replay
- HTML/PDF investigation reports

## Local research engine

```powershell
python -m pip install -e ".[dev,ai]"
python -m pip install -e ".\packages\ra_xsoc_api"
python .\scripts\generate_retrieval_corpus.py
python .\scripts\generate_embeddings.py
python -m pytest -q
```

## GitHub deployment

Enable **Settings → Pages → Build and deployment → GitHub Actions**. Pushes to `master` run CI and deploy the frontend automatically.

See [GitHub-only deployment](docs/DEPLOYMENT_GITHUB_PAGES.md).

## Safety

The demo is read-only and uses synthetic/demo scenarios. It does not perform containment, blocking, arbitrary command execution, or access to private SOC systems.

## Citation

See `CITATION.cff`.

## Reproducible research evaluation

A fixed 30-case benchmark is stored at `research/benchmarks/ra_xsoc_x_v1.json`. Run the local evaluator after generating the FAISS artifacts:

```powershell
python .\scripts\generate_retrieval_corpus.py
python .\scripts\generate_embeddings.py
python .\research\evaluate_retrieval.py
```

The evaluator records Top-1 accuracy, Recall@3, Recall@5, MRR, mean confidence, and per-case predictions under `research/results/`. The benchmark must remain unchanged when reporting a completed experiment; create a new benchmark version for new experiments.

## Known next-stage requirements

The following require additional infrastructure or a new evaluation dataset and therefore are not represented as completed by the current V2 baseline:

- live SIEM/EDR/network/identity telemetry connectors
- production hosting for FastAPI, FAISS, and PostgreSQL
- held-out/adversarial evaluation
- autonomous response/containment
