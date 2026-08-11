from dataclasses import dataclass

from .enums import SeverityLevel
from .exceptions import DomainValidationError
from .models import validate_non_empty


@dataclass(frozen=True, slots=True)
class ThreatFrameworkReference:
    """Mapping to MITRE ATT&CK or another threat framework."""

    framework: str
    name: str
    raw_value: str
    reference_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "framework",
            validate_non_empty(
                self.framework,
                "framework",
            ),
        )

        object.__setattr__(
            self,
            "name",
            validate_non_empty(
                self.name,
                "name",
            ),
        )

        object.__setattr__(
            self,
            "raw_value",
            validate_non_empty(
                self.raw_value,
                "raw_value",
            ),
        )

        if self.reference_id is not None:
            object.__setattr__(
                self,
                "reference_id",
                validate_non_empty(
                    self.reference_id,
                    "reference_id",
                ).upper(),
            )


@dataclass(frozen=True, slots=True)
class AttackKnowledgeRecord:
    """Validated structured representation of one V1 TXT file."""

    attack_id: str
    incident_type: str
    description: str
    severity: SeverityLevel

    framework_references: tuple[
        ThreatFrameworkReference,
        ...,
    ]

    indicators: tuple[str, ...]
    containment: tuple[str, ...]
    investigation: tuple[str, ...]
    recovery: tuple[str, ...]
    prevention: tuple[str, ...]
    detection_rules: tuple[str, ...]
    affected_assets: tuple[str, ...]

    source_filename: str
    source_sha256: str
    source_encoding: str

    references: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    real_world_examples: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()

    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        required_text = {
            "attack_id": self.attack_id,
            "incident_type": self.incident_type,
            "description": self.description,
            "source_filename": self.source_filename,
            "source_encoding": self.source_encoding,
            "schema_version": self.schema_version,
        }

        for field_name, value in required_text.items():
            object.__setattr__(
                self,
                field_name,
                validate_non_empty(
                    value,
                    field_name,
                ),
            )

        if not self.attack_id.replace("_", "").isalnum():
            raise DomainValidationError(
                "attack_id may contain only letters, numbers, and underscores."
            )

        digest = self.source_sha256.lower().strip()

        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise DomainValidationError("source_sha256 must be a valid SHA-256 digest.")

        object.__setattr__(
            self,
            "source_sha256",
            digest,
        )

        required_collections: dict[
            str,
            tuple[object, ...],
        ] = {
            "framework_references": self.framework_references,
            "indicators": self.indicators,
            "containment": self.containment,
            "investigation": self.investigation,
            "recovery": self.recovery,
            "prevention": self.prevention,
            "detection_rules": self.detection_rules,
            "affected_assets": self.affected_assets,
        }

        for field_name, values in required_collections.items():
            if not values:
                raise DomainValidationError(f"{field_name} must contain at least one item.")

        text_collections = (
            self.indicators,
            self.containment,
            self.investigation,
            self.recovery,
            self.prevention,
            self.detection_rules,
            self.affected_assets,
            self.references,
            self.tools,
            self.real_world_examples,
            self.keywords,
        )

        for values in text_collections:
            for value in values:
                if not value.strip():
                    raise DomainValidationError(
                        "Knowledge-base collections must not contain empty values."
                    )
