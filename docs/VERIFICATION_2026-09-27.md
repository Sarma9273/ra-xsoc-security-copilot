# RA-XSOC-X Verification Evidence — 2026-09-27

## Verified release baseline

`c08725609840c3ca9cbce5e9ef835c810b01f6e7`

This record captures the automated gate results for the documented release baseline. Subsequent documentation-only commits may advance `master` without changing the verified application code.

## GitHub Actions evidence

| Gate | Run | Result |
|---|---:|---|
| RA-XSOC-X CI | 36343813885 | PASS |
| RA-XSOC-X Security | 36343813880 | PASS |
| GitHub Pages deployment | 36343813907 | PASS |

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
