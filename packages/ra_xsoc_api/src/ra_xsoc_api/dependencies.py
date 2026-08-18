from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from ra_xsoc_engine.application.container import ApplicationContainer
from ra_xsoc_engine.domain.embedding import EmbeddingConfiguration


PROJECT_ROOT = Path(__file__).resolve().parents[4]

KNOWLEDGE_BASE_DIRECTORY = (
    PROJECT_ROOT / "data" / "knowledge_base" / "normalized"
)

ARTIFACT_DIRECTORY = (
    PROJECT_ROOT / "data" / "artifacts" / "embeddings"
)

CORPUS_DIRECTORY = (
    PROJECT_ROOT / "data" / "retrieval"
)

@lru_cache(maxsize=1)
def get_application() -> ApplicationContainer:
    configuration = EmbeddingConfiguration(
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
    )

    return ApplicationContainer(
        knowledge_base_directory=KNOWLEDGE_BASE_DIRECTORY,
        artifact_directory=ARTIFACT_DIRECTORY,
        corpus_directory=CORPUS_DIRECTORY,
        embedding_configuration=configuration,
    )