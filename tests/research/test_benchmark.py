import json
from pathlib import Path

BENCHMARK = Path(__file__).resolve().parents[2] / "research" / "benchmarks" / "ra_xsoc_x_v1.json"

def test_benchmark_is_frozen_and_complete():
    data = json.loads(BENCHMARK.read_text(encoding="utf-8"))
    assert data["dataset_id"] == "ra-xsoc-x-retrieval-benchmark-v1"
    assert data["version"] == "1.0"
    assert len(data["cases"]) == 30
    ids = [case["case_id"] for case in data["cases"]]
    expected = [f"RX{i:03d}" for i in range(1, 31)]
    assert ids == expected
    assert all(case["description"].strip() for case in data["cases"])
    assert all(case["expected_attack_id"].strip() for case in data["cases"])
