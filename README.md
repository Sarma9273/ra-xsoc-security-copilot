# RA-XSOC-X

**Evidence-Driven Adaptive Investigation Intelligence for Security Operations**

RA-XSOC-X extends the RA-XSOC V2 retrieval stack toward an evidence-driven investigation loop:

```
Incident → Evidence → State → Hypotheses → Investigation → Verification
        → ATT&CK Mapping → Human Review → Feedback → Experience Memory
```

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
- optional MITRE ATT&CK verification
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
