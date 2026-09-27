from __future__ import annotations

import json
from pathlib import Path
from statistics import mean

from ra_xsoc_engine.application.container import ApplicationContainer
from ra_xsoc_engine.domain.embedding import EmbeddingConfiguration
from ra_xsoc_engine.domain.models import IncidentInput

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "research" / "benchmarks" / "ra_xsoc_x_v1.json"
OUTPUT = ROOT / "research" / "results" / "ra_xsoc_x_v1_results.json"

def build_application() -> ApplicationContainer:
    return ApplicationContainer(
        knowledge_base_directory=ROOT / "data" / "knowledge_base" / "normalized",
        artifact_directory=ROOT / "data" / "artifacts" / "embeddings",
        corpus_directory=ROOT / "data" / "retrieval",
        embedding_configuration=EmbeddingConfiguration(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            model_revision=None,
            device="cpu",
            batch_size=8,
            normalize_embeddings=True,
            similarity_metric="cosine",
            faiss_index_type="IndexFlatIP",
            vector_dtype="float32",
            expected_dimension=384,
            schema_version="1.0",
        ),
    )

def main() -> None:
    benchmark = json.loads(BENCHMARK.read_text(encoding="utf-8"))
    app = build_application()
    rows = []
    top1 = top3 = top5 = 0
    reciprocal_ranks = []
    for case in benchmark["cases"]:
        result = app.analyzer.analyze(IncidentInput(description=case["description"]), limit=5)
        ids = [result.primary_match.attack_id, *[x.attack_id for x in result.alternatives]]
        try:
            rank = ids.index(case["expected_attack_id"]) + 1
        except ValueError:
            rank = None
        if rank == 1: top1 += 1
        if rank is not None and rank <= 3: top3 += 1
        if rank is not None and rank <= 5: top5 += 1
        reciprocal_ranks.append(1.0 / rank if rank else 0.0)
        rows.append({
            "case_id": case["case_id"],
            "expected_attack_id": case["expected_attack_id"],
            "predicted_attack_id": result.primary_match.attack_id,
            "rank": rank,
            "top5": rank is not None and rank <= 5,
            "confidence": result.confidence,
            "novelty_status": result.novelty_status.value,
        })
    n = len(rows)
    metrics = {
        "dataset_id": benchmark["dataset_id"],
        "dataset_version": benchmark["version"],
        "n": n,
        "top1_accuracy": top1 / n if n else 0.0,
        "recall_at_3": top3 / n if n else 0.0,
        "recall_at_5": top5 / n if n else 0.0,
        "mrr": mean(reciprocal_ranks) if reciprocal_ranks else 0.0,
        "mean_confidence": mean(x["confidence"] for x in rows) if rows else 0.0,
    }
    payload = {"metrics": metrics, "cases": rows}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))

if __name__ == "__main__":
    main()
