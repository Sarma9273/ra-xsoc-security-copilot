# RA-XSOC-X Release Gate

A release is considered 1000% complete only when all gates below are verified.

## Engineering
- Full Python test suite passes.
- Frontend lint and production build pass.
- API contract tests pass against the same response schema consumed by the frontend.
- Lightweight and heavy retrieval paths are separately tested.
- Retrieval corpus and frozen benchmark are versioned.

## Investigation intelligence
- Incident normalization.
- Retrieval and lexical fallback.
- Evidence representation.
- Competing hypotheses.
- Novelty assessment.
- Investigation planning.
- MITRE verification.
- Human-review state.
- Analyst feedback / experience memory.
- Investigation replay or reproducibility evidence.
- Explicit UNDETERMINED state when evidence is insufficient.

## Safety
- Public demo uses synthetic scenarios.
- No arbitrary command execution.
- No automatic containment or blocking.
- No secrets committed to the repository.
- API returns request identifiers and hardened response headers.
- CORS is disabled by default.

## Research
- Frozen benchmark remains immutable.
- Evaluation protocol is versioned.
- Reported metrics identify benchmark and engine versions.
- New experiments create new result records rather than modifying prior benchmark definitions.

## Deployment
- GitHub Pages build succeeds.
- Python engine remains reproducible locally.
- Deployment architecture distinguishes the static public demo from the private/local Python runtime.

## Completion rule
Do not mark a gate complete from source inspection alone when runtime evidence is required. Record VERIFIED, OPEN, or NOT APPLICABLE for every gate.