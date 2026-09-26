# RA-XSOC-X Research Evaluation Protocol v1.0

## Research question

Can an evidence-driven, multi-hypothesis retrieval and verification architecture improve security-incident identification and investigation quality over a single top-1 retrieval decision?

## Evaluation layers

### Incident identification
- Top-1 accuracy
- Recall@3
- Recall@5
- Mean Reciprocal Rank (MRR)

### Evidence / investigation
Future labelled datasets should measure:
- evidence coverage
- hypothesis ranking quality
- contradiction detection
- investigation-step efficiency
- analyst interventions
- time to defensible conclusion

### Novelty
Novelty must be evaluated against a frozen reference corpus and a separately labelled set containing:
- known patterns
- unseen behavior
- known techniques in unseen combinations
- insufficient-evidence cases

Do not call an input a zero-day solely because retrieval similarity is low.

## Reproducibility

1. Freeze the benchmark version.
2. Generate the retrieval corpus.
3. Generate embedding artifacts with the recorded model/configuration.
4. Run `research/evaluate_retrieval.py`.
5. Preserve the JSON result under `research/results/`.
6. For a new dataset, create a new benchmark version rather than modifying v1.

## Current v1 scope

The v1 benchmark contains 30 representative incident narratives, one per curated knowledge-base category. It evaluates retrieval/identification only. It does **not** establish clinical-grade or production-grade incident truth, and its results must not be generalized beyond the benchmark population.

## Research extension path

The next publishable experiment should compare:
1. lexical retrieval baseline;
2. semantic retrieval baseline;
3. hybrid retrieval;
4. hybrid + competing hypotheses;
5. hybrid + verification + experience memory.

Use the same frozen test set for each condition and report confidence intervals where sample size permits.
