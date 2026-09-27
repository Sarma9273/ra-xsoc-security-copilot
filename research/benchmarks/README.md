# RA-XSOC-X Retrieval Evaluation

The versioned V1 benchmark contains 30 incident narratives mapped to the 30-record curated RA-XSOC corpus.

## What V1 establishes

V1 verifies that the persisted retrieval artifacts, corpus mapping, embedding configuration, ranking implementation, and evaluator are internally consistent for the fixed cases.

A perfect V1 score therefore means:

> The current retrieval pipeline correctly retrieves the expected corpus record for every fixed V1 fixture.

## What V1 does not establish

V1 is not an independent real-world detection benchmark. The cases are intentionally aligned with the curated corpus and do not represent an external SOC telemetry population.

It must not be reported as 100% real-world detection or classification accuracy.

## Required next evaluation

Future evaluation versions should contain held-out incident narratives that are not derived from the indexed retrieval text, plus adversarial/paraphrased cases and benign cases. Report corpus overlap, Top-K retrieval metrics, calibration, false-positive behavior, and confidence intervals where the sample size permits.

The benchmark version and corpus version must always be reported together.
