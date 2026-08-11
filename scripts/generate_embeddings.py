from __future__ import annotations

import json
from pathlib import Path

from ra_xsoc_engine.domain.embedding import (
    EmbeddingConfiguration,
    EmbeddingVectorBatch,
)
from ra_xsoc_engine.embedding.sentence_transformer import (
    SentenceTransformerEmbeddingService,
)
from ra_xsoc_engine.embedding.artifacts import (
    EmbeddingArtifactBuilder,
)


ROOT = Path(__file__).resolve().parents[1]

CORPUS_PATH = ROOT / "data" / "retrieval" / "corpus.jsonl"
OUTPUT_DIR = ROOT / "data" / "artifacts" / "embeddings"

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def load_corpus() -> list[dict]:
    documents = []

    with CORPUS_PATH.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()

            if line:
                documents.append(json.loads(line))

    return documents


def main() -> int:
    print("=" * 76)
    print("RA-XSOC EMBEDDING ARTIFACT GENERATION")
    print("=" * 76)

    documents = load_corpus()

    print(f"Corpus: {CORPUS_PATH}")
    print(f"Documents: {len(documents)}")
    print(f"Model: {MODEL_NAME}")

    if len(documents) != 30:
        raise RuntimeError(
            f"Expected 30 retrieval documents, got {len(documents)}"
        )

    document_ids = tuple(
        document["document_id"]
        for document in documents
    )

    texts = tuple(
        document["retrieval_text"]
        for document in documents
    )

    configuration = EmbeddingConfiguration(
        model_name=MODEL_NAME,
        model_revision=None,
        device="cpu",
        batch_size=32,
        normalize_embeddings=True,
        similarity_metric="cosine",
        faiss_index_type="IndexFlatIP",
        vector_dtype="float32",
        expected_dimension=384,
        schema_version="1.0",
    )

    print()
    print("Loading SentenceTransformer model...")

    embedding_service = SentenceTransformerEmbeddingService(
        configuration
    )

    print("Generating embeddings...")

    vectors = embedding_service.embed(texts)

    vector_batch = EmbeddingVectorBatch(
        document_ids=document_ids,
        vectors=tuple(
            tuple(float(value) for value in vector)
            for vector in vectors
        ),
        dimension=len(vectors[0]),
        normalized=True,
   )

    print()
    print(f"Embedding count: {vector_batch.count}")
    print(f"Embedding dimension: {vector_batch.dimension}")
    print(f"Normalized: {vector_batch.normalized}")

    if vector_batch.count != 30:
        raise RuntimeError(
            f"Expected 30 embeddings, got {vector_batch.count}"
        )

    if vector_batch.dimension != 384:
        raise RuntimeError(
            f"Expected dimension 384, got {vector_batch.dimension}"
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    corpus_manifest = (
        ROOT
        / "data"
        / "retrieval"
        / "manifest.json"
    )

    with corpus_manifest.open(
        "r",
        encoding="utf-8",
    ) as handle:
        manifest = json.load(handle)

    corpus_checksum = manifest["corpus_checksum"]

    builder = EmbeddingArtifactBuilder(
        configuration
    )

    artifact_manifest = builder.write(
        vector_batch=vector_batch,
        output_directory=OUTPUT_DIR,
        corpus_checksum=corpus_checksum,
        retrieval_schema_version="1.0",
    )

    print()
    print("=" * 76)
    print("EMBEDDING ARTIFACT GENERATION COMPLETE")
    print("=" * 76)

    print(f"Output directory: {OUTPUT_DIR}")
    print(f"Documents: {artifact_manifest.document_count}")
    print(f"Dimension: {artifact_manifest.embedding_dimension}")

    print()
    print("Artifacts:")

    for artifact in artifact_manifest.artifacts:
        print(
            f"  {artifact.role}: "
            f"{artifact.relative_path} "
            f"({artifact.size_bytes} bytes)"
        )

    print()
    print("SUCCESS")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())