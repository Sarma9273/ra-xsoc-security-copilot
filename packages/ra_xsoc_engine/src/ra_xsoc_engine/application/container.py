from __future__ import annotations

from pathlib import Path

from ra_xsoc_engine.analysis.analyzer import IncidentAnalysisService
from ra_xsoc_engine.domain.embedding import EmbeddingConfiguration
from ra_xsoc_engine.embedding.sentence_transformer import (
    SentenceTransformerEmbeddingService,
)
from ra_xsoc_engine.knowledge_base.normalized_repository import (
    NormalizedKnowledgeBaseRepository,
)
from ra_xsoc_engine.playbooks.repository import (
    KnowledgeBasePlaybookRepository,
)
from ra_xsoc_engine.retrieval.faiss_retriever import (
    FAISSAttackRetriever,
)


class ApplicationContainer:
    """Composition root for the RA-XSOC application."""

    def __init__(
        self,
        *,
        knowledge_base_directory: Path,
        artifact_directory: Path,
        corpus_directory: Path,
        embedding_configuration: EmbeddingConfiguration,
    ) -> None:
        self.embedding_service = (
            SentenceTransformerEmbeddingService(
                embedding_configuration
            )
        )

        self.retriever = FAISSAttackRetriever(
            artifact_directory=artifact_directory,
            corpus_directory=corpus_directory,
            embedding_service=self.embedding_service,
        )

        self.knowledge_base_repository = (
            NormalizedKnowledgeBaseRepository(
                knowledge_base_directory
            )
        )

        self.playbook_repository = (
            KnowledgeBasePlaybookRepository(
                self.knowledge_base_repository.load_all()
            )
        )

        self.analyzer = IncidentAnalysisService(
            retriever=self.retriever,
            playbook_repository=self.playbook_repository,
        )
        