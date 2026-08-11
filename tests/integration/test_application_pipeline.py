from pathlib import Path

from ra_xsoc_engine.application.container import ApplicationContainer
from ra_xsoc_engine.domain.embedding import EmbeddingConfiguration
from ra_xsoc_engine.domain.models import IncidentInput


ROOT = Path(__file__).resolve().parents[2]

KNOWLEDGE_BASE_DIRECTORY = (
    ROOT / "data" / "knowledge_base" / "normalized"
)

ARTIFACT_DIRECTORY = (
    ROOT / "data" / "artifacts" / "embeddings"
)

CORPUS_DIRECTORY = (
    ROOT / "data" / "retrieval"
)


def test_real_application_pipeline():
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

    application = ApplicationContainer(
        knowledge_base_directory=KNOWLEDGE_BASE_DIRECTORY,
        artifact_directory=ARTIFACT_DIRECTORY,
        corpus_directory=CORPUS_DIRECTORY,
        embedding_configuration=configuration,
    )

    incident = IncidentInput(
        description=(
            "An employee received a suspicious phishing email "
            "containing a malicious login link requesting credentials."
        )
    )

    result = application.analyzer.analyze(
        incident,
        limit=5,
    )

    assert result.primary_match.attack_id == "phishing"
    assert result.primary_match.semantic_score > 0.0
    assert result.primary_match.hybrid_score > 0.0
    assert result.confidence == result.primary_match.hybrid_score
    assert result.playbook is not None
    assert result.explanation