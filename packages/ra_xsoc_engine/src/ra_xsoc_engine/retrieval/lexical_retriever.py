from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Protocol

from ra_xsoc_engine.domain.exceptions import DomainValidationError, RetrievalError
from ra_xsoc_engine.domain.models import AttackMatch, IncidentInput, MitreTechnique


class LightweightAttackRetriever:
    """Resource-light corpus retriever for constrained deployments.

    Uses deterministic token overlap instead of loading a transformer model.
    This keeps the API suitable for small free-tier instances while preserving
    the same AttackMatch contract used by the analysis service.
    """

    def __init__(
        self,
        *,
        corpus_directory: Path,
    ) -> None:
        self._documents = self._load_documents(corpus_directory)
        if not self._documents:
            raise DomainValidationError("Retrieval corpus contains no documents.")

    def retrieve(
        self,
        incident: IncidentInput,
        limit: int = 3,
    ) -> tuple[AttackMatch, ...]:
        if limit <= 0:
            raise DomainValidationError("limit must be greater than zero.")

        query_tokens = self._tokenize(incident.description)
        if not query_tokens:
            raise DomainValidationError("Incident description contains no searchable terms.")

        scored: list[tuple[float, dict[str, object]]] = []
        for document in self._documents:
            document_tokens = document["tokens"]
            overlap = len(query_tokens & document_tokens)
            if overlap == 0:
                continue

            # Jaccard-style lexical score, deterministic and bounded to 0..1.
            score = overlap / len(query_tokens | document_tokens)
            scored.append((score, document))

        if not scored:
            # Always return a deterministic candidate so the analyst receives a
            # useful response instead of an infrastructure failure.
            scored = [(0.0, document) for document in self._documents]

        scored.sort(
            key=lambda item: (item[0], str(item[1]["attack_id"])),
            reverse=True,
        )

        matches: list[AttackMatch] = []
        for score, document in scored[:limit]:
            matches.append(
                AttackMatch(
                    attack_id=str(document["attack_id"]),
                    name=str(document["title"]),
                    semantic_score=float(score),
                    keyword_score=float(score),
                    hybrid_score=float(score),
                    mitre_techniques=self._extract_mitre_techniques(
                        document.get("framework_labels", []),
                    ),
                )
            )

        return tuple(matches)

    @classmethod
    def _load_documents(cls, corpus_directory: Path) -> list[dict[str, object]]:
        documents: list[dict[str, object]] = []
        for path in sorted(corpus_directory.glob("*.json")):
            if path.name == "manifest.json":
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as error:
                raise RetrievalError(f"Invalid retrieval document JSON: {path}") from error

            if not isinstance(payload, dict):
                raise DomainValidationError(f"Retrieval document must be an object: {path}")

            retrieval_text = str(payload.get("retrieval_text", ""))
            payload["tokens"] = cls._tokenize(retrieval_text)
            documents.append(payload)

        return documents

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        return {
            token
            for token in re.findall(r"[a-z0-9]{2,}", text.lower())
            if token not in {
                "the", "and", "for", "with", "from", "into", "that", "this",
                "are", "was", "were", "has", "have", "been", "using", "such",
            }
        }

    @staticmethod
    def _extract_mitre_techniques(framework_labels: object) -> tuple[MitreTechnique, ...]:
        if not isinstance(framework_labels, list):
            return ()

        techniques: list[MitreTechnique] = []
        for label in framework_labels:
            if not isinstance(label, str):
                continue
            parts = [part.strip() for part in label.split("|")]
            if len(parts) != 3:
                continue
            framework, reference_id, name = parts
            if framework.upper() != "MITRE ATT&CK" or not reference_id.upper().startswith("T"):
                continue
            techniques.append(MitreTechnique(technique_id=reference_id, name=name))

        return tuple(techniques)
