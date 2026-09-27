# RA-XSOC-X

**Evidence-Driven Adaptive Investigation Intelligence for Security Operations**

RA-XSOC-X extends the RA-XSOC V2 retrieval stack toward an evidence-driven investigation loop:

```
Incident → Evidence → State → Hypotheses → Investigation → Verification
        → ATT&CK Mapping → Human Review → Feedback → Experience Memory
```

## Verified release state

The current `master` head at the time of this verification is **`4ec788df7d2cf62d07ff1b1a6f9e132dd85f4c83`**.

The release gates associated with that commit are green:

- Python CI
- Frontend lint/build
- Reproducible retrieval benchmark
- Dependency/security scan
- GitHub Pages deployment

See [verification evidence](docs/VERIFICATION_2026-09-27.md).

## Public demo

The public demonstration is designed for **GitHub Pages** and runs its deterministic demo engine in the browser. It requires no paid server, account, API key, or continuously running computer.

The full Python/FastAPI research engine remains in this repository for local execution, experiments, and reproducible evaluation.

## Research engine

- versioned 30-record security knowledge base
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
- retrieval/evaluation scripts

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

The public demo is read-only and uses synthetic/demo scenarios. It does not perform containment, blocking, arbitrary command execution, or access to private SOC systems.

## Citation

See `CITATION.cff`.

## Reproducible research evaluation

A fixed 30-case benchmark is stored at `research/benchmarks/ra_xsoc_x_v1.json`. Run the local research evaluator after generating the FAISS artifacts:

```powershell
python .\scripts\generate_retrieval_corpus.py
python .\scripts\generate_embeddings.py
python .\research\evaluate_retrieval.py
```

The evaluator records Top-1 accuracy, Recall@3, Recall@5, MRR, mean confidence, and per-case predictions under `research/results/`. The benchmark is versioned and must not be modified when reporting a completed experiment; create a new benchmark version for new experiments.
