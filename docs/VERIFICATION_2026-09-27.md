# RA-XSOC-X Verification Evidence — 2026-09-27

## Verified commit

`b7c0b8dd87cd5688d897ef0d23affec6b71ccad1`

Change: corrected `research/evaluate_retrieval.py` to resolve the repository root with `Path(__file__).resolve().parents[1]`.

## GitHub Actions evidence

| Gate | Run | Result |
|---|---:|---|
| RA-XSOC-X CI | 36341979477 | PASS |
| RA-XSOC-X Security | 36341979476 | PASS |
| GitHub Pages deployment | 36341979406 | PASS |

All three runs target the same commit above.

## CI evidence

- Python test suite: **147 passed**, 1 warning in the verified run.
- Ruff check: passed.
- Retrieval corpus generation: **30 source records → 30 retrieval documents**.
- Corpus checksum: `e640a0e0285a922fca95bd3f9e742e9c4a8df64754772550470b34d9fecd6966`.
- Embedding generation: **30 documents**, **384-dimensional** vectors.
- Reproducible benchmark: executed successfully and produced `research/results/ra_xsoc_x_v1_results.json`.
- Frontend lint and production build: passed.

## Security evidence

The security workflow completed successfully, including Python dependency installation, `pip-audit`, and the repository secret-pattern scan.

## Deployment evidence

The GitHub Pages workflow completed successfully for the verified commit.

## Boundary

This document records repository/CI evidence. It does not claim a separately hosted production FastAPI deployment or a local machine E2E test beyond the runtime checks already represented in the project's test suite.
