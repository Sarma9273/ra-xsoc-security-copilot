from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

import faiss
import numpy as np

from ra_xsoc_engine.domain.exceptions import DomainValidationError, RetrievalError
from ra_xsoc_engine.domain.models import AttackMatch, IncidentInput, MitreTechnique
from ra_xsoc_engine.retrieval.ranking import HybridRanker, KeywordScorer


class QueryEmbeddingService(Protocol):
    """Provides embeddings for incident text."""

    def embed(
        self,
        texts: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]: ...


class FAISSAttackRetriever:
    """Retrieve attack candidates from a persisted FAISS artifact set."""

    INDEX_FILENAME = "index.faiss"
    MAPPING_FILENAME = "document_mapping.json"

    def __init__(
        self,
        *,
        artifact_directory: Path,
        corpus_directory: Path,
        embedding_service: QueryEmbeddingService,
    ) -> None:
        self._artifact_directory = artifact_directory
        self._corpus_directory = corpus_directory
        self._embedding_service = embedding_service
        self._keyword_scorer = KeywordScorer()
        self._hybrid_ranker = HybridRanker()

        self._index = self._load_index()
        self._mapping = self._load_mapping()

        if self._index.ntotal != len(self._mapping):
            raise DomainValidationError(
                "FAISS index count does not match document mapping count."
            )

    def retrieve(
        self,
        incident: IncidentInput,
        limit: int = 3,
    ) -> tuple[AttackMatch, ...]:
        """Retrieve the highest-scoring attack candidates."""

        if limit <= 0:
            raise DomainValidationError("limit must be greater than zero.")

        query_embeddings = self._embedding_service.embed(
            (incident.description,),
        )

        if len(query_embeddings) != 1:
            raise RetrievalError(
                "Embedding service must return exactly one query vector."
            )

        query_vector = np.asarray(
            query_embeddings[0],
            dtype=np.float32,
        )

        if query_vector.ndim != 1:
            raise RetrievalError("Query embedding must be one-dimensional.")

        if query_vector.shape[0] != self._index.d:
            raise RetrievalError(
                "Query embedding dimension does not match the FAISS index dimension."
            )

        query_matrix = np.asarray(
            [query_vector],
            dtype=np.float32,
        )

        scores, positions = self._index.search(
            query_matrix,
            min(limit, self._index.ntotal),
        )

        matches: list[AttackMatch] = []

        for score, position in zip(
            scores[0],
            positions[0],
            strict=True,
        ):
            if position < 0:
                continue

            document_id = self._mapping.get(str(int(position)))

            if document_id is None:
                raise RetrievalError(
                    f"FAISS returned unmapped document position: {position}"
                )

            document = self._load_document(document_id)

            semantic_score = self._normalize_similarity(float(score))

            matches.append(
                AttackMatch(
                    attack_id=document["attack_id"],
                    name=document["title"],
                    semantic_score=semantic_score,
                    keyword_score=self._keyword_scorer.score(
                        incident.description,
                        str(document.get("retrieval_text", "")),
                    ),
                    hybrid_score=semantic_score,
                    mitre_techniques=self._extract_mitre_techniques(
                        document.get("framework_labels", []),
                    ),
                )
            )

        keyword_scores = [match.keyword_score for match in matches]
        return self._hybrid_ranker.rank(matches, keyword_scores)

    def _load_index(self) -> faiss.Index:
        index_path = self._artifact_directory / self.INDEX_FILENAME

        if not index_path.is_file():
            raise DomainValidationError(
                f"FAISS index does not exist: {index_path}"
            )

        try:
            return faiss.read_index(str(index_path))
        except Exception as error:
            raise RetrievalError(
                f"Unable to load FAISS index: {index_path}"
            ) from error

    def _load_mapping(self) -> dict[str, str]:
        mapping_path = self._artifact_directory / self.MAPPING_FILENAME

        if not mapping_path.is_file():
            raise DomainValidationError(
                f"Document mapping does not exist: {mapping_path}"
            )

        try:
            payload = json.loads(
                mapping_path.read_text(
                    encoding="utf-8",
                )
            )
        except json.JSONDecodeError as error:
            raise RetrievalError(
                f"Invalid document mapping JSON: {mapping_path}"
            ) from error

        if not isinstance(payload, dict):
            raise DomainValidationError(
                "Document mapping must contain a JSON object."
            )

        mapping: dict[str, str] = {}

        for position, document_id in payload.items():
            if not isinstance(position, str):
                raise DomainValidationError(
                    "Document mapping positions must be strings."
                )

            if not isinstance(document_id, str) or not document_id.strip():
                raise DomainValidationError(
                    "Document mapping document IDs must be non-empty strings."
                )

            mapping[position] = document_id

        return mapping

    def _load_document(
        self,
        document_id: str,
    ) -> dict[str, object]:
        documents = list(
            self._corpus_directory.glob("*.json")
        )

        for path in documents:
            if path.name == "manifest.json":
                continue

            try:
                payload = json.loads(
                    path.read_text(
                        encoding="utf-8",
                    )
                )
            except json.JSONDecodeError as error:
                raise RetrievalError(
                    f"Invalid retrieval document JSON: {path}"
                ) from error

            if payload.get("document_id") == document_id:
                return payload

        raise RetrievalError(
            f"Retrieval document was not found for document ID: {document_id}"
        )

    @staticmethod
    def _normalize_similarity(
        score: float,
    ) -> float:
        """Convert cosine/IP similarity into the domain's 0..1 score range."""

        return max(
            0.0,
            min(
                1.0,
                score,
            ),
        )

    @staticmethod
    def _extract_mitre_techniques(
        framework_labels: object,
    ) -> tuple[MitreTechnique, ...]:
        if not isinstance(framework_labels, list):
            return ()

        techniques: list[MitreTechnique] = []

        for label in framework_labels:
            if not isinstance(label, str):
                continue

            parts = [
                part.strip()
                for part in label.split("|")
            ]

            if len(parts) != 3:
                continue

            framework, reference_id, name = parts

            if framework.upper() != "MITRE ATT&CK":
                continue

            if not reference_id.upper().startswith("T"):
                continue

            techniques.append(
                MitreTechnique(
                    technique_id=reference_id,
                    name=name,
                )
            )

        return tuple(techniques)