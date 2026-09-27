from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from ra_xsoc_api.persistence import CaseStore

from ra_xsoc_api.postgres import PostgresCaseStore

from ra_xsoc_engine.analysis.analyzer import IncidentAnalysisService
from ra_xsoc_engine.knowledge_base.normalized_repository import NormalizedKnowledgeBaseRepository
from ra_xsoc_engine.playbooks.repository import KnowledgeBasePlaybookRepository
from ra_xsoc_engine.retrieval.lexical_retriever import LightweightAttackRetriever


PROJECT_ROOT = Path(__file__).resolve().parents[4]
KNOWLEDGE_BASE_DIRECTORY = PROJECT_ROOT / "data" / "knowledge_base" / "normalized"
ARTIFACT_DIRECTORY = PROJECT_ROOT / "data" / "artifacts" / "embeddings"
CORPUS_DIRECTORY = PROJECT_ROOT / "data" / "retrieval"


class LightweightApplication:
    """Small application facade used when the deployment cannot afford the ML model."""

    def __init__(self, analyzer: IncidentAnalysisService) -> None:
        self.analyzer = analyzer


def _heavy_ml_explicitly_enabled() -> bool:
    """Require an explicit opt-in before the heavyweight ML stack can load.

    This prevents stale Render environment variables such as an older
    ``RA_XSOC_DEPLOYMENT_PROFILE=full`` from accidentally re-enabling the
    SentenceTransformer/FAISS path on the free instance.
    """

    return os.getenv("RA_XSOC_RETRIEVER", "faiss").lower() != "lexical"


@lru_cache(maxsize=1)
def get_application():
    """Build the API application with lightweight retrieval by default."""

    if not _heavy_ml_explicitly_enabled():
        knowledge_base_repository = NormalizedKnowledgeBaseRepository(
            KNOWLEDGE_BASE_DIRECTORY
        )
        playbook_repository = KnowledgeBasePlaybookRepository(
            knowledge_base_repository.load_all()
        )
        analyzer = IncidentAnalysisService(
            retriever=LightweightAttackRetriever(corpus_directory=CORPUS_DIRECTORY),
            playbook_repository=playbook_repository,
        )
        return LightweightApplication(analyzer)

    # Heavy ML is an explicit opt-in for deployments with sufficient memory.
    from ra_xsoc_engine.application.container import ApplicationContainer
    from ra_xsoc_engine.domain.embedding import EmbeddingConfiguration

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


@lru_cache(maxsize=1)
def get_case_store():
    if os.getenv("RA_XSOC_DATABASE_URL"):
        return PostgresCaseStore()
    return CaseStore()
