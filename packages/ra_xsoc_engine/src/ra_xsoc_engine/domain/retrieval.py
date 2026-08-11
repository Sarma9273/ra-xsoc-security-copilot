from dataclasses import dataclass

from .enums import SeverityLevel
from .exceptions import DomainValidationError
from .models import validate_non_empty


def validate_sha256(
    value: str,
    field_name: str,
) -> str:
    """Validate and normalize a SHA-256 checksum."""

    normalized = value.strip().lower()

    if len(normalized) != 64:
        raise DomainValidationError(f"{field_name} must contain exactly 64 hexadecimal characters.")

    if any(character not in "0123456789abcdef" for character in normalized):
        raise DomainValidationError(f"{field_name} must be a valid SHA-256 hexadecimal checksum.")

    return normalized


@dataclass(frozen=True, slots=True)
class RetrievalDocument:
    """Focused searchable representation of one attack."""

    document_id: str
    attack_id: str
    title: str
    retrieval_text: str

    severity: SeverityLevel
    framework_labels: tuple[str, ...]

    source_filename: str
    source_record_sha256: str
    content_sha256: str

    knowledge_schema_version: str
    retrieval_schema_version: str = "1.0"

    def __post_init__(self) -> None:
        required_strings = {
            "document_id": self.document_id,
            "attack_id": self.attack_id,
            "title": self.title,
            "retrieval_text": self.retrieval_text,
            "source_filename": self.source_filename,
            "knowledge_schema_version": self.knowledge_schema_version,
            "retrieval_schema_version": self.retrieval_schema_version,
        }

        for field_name, value in required_strings.items():
            object.__setattr__(
                self,
                field_name,
                validate_non_empty(
                    value,
                    field_name,
                ),
            )

        if not self.framework_labels:
            raise DomainValidationError("framework_labels must contain at least one value.")

        normalized_labels: list[str] = []

        for label in self.framework_labels:
            normalized_labels.append(
                validate_non_empty(
                    label,
                    "framework_label",
                )
            )

        object.__setattr__(
            self,
            "framework_labels",
            tuple(normalized_labels),
        )

        object.__setattr__(
            self,
            "source_record_sha256",
            validate_sha256(
                self.source_record_sha256,
                "source_record_sha256",
            ),
        )

        object.__setattr__(
            self,
            "content_sha256",
            validate_sha256(
                self.content_sha256,
                "content_sha256",
            ),
        )
