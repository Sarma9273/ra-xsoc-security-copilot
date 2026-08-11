from __future__ import annotations

import re
from hashlib import sha256
from pathlib import Path

from ra_xsoc_engine.domain.enums import SeverityLevel
from ra_xsoc_engine.domain.exceptions import (
    KnowledgeBaseError,
)
from ra_xsoc_engine.domain.knowledge import (
    AttackKnowledgeRecord,
    ThreatFrameworkReference,
)

SECTION_ALIASES: dict[str, str] = {
    "description": "description",
    "overview": "description",
    "summary": "description",
    "mitre": "mitre",
    "mitre attack": "mitre",
    "mitre att&ck": "mitre",
    "mitre technique": "mitre",
    "mitre techniques": "mitre",
    "severity": "severity",
    "risk": "severity",
    "risk level": "severity",
    "priority": "severity",
    "indicators": "indicators",
    "indicators of compromise": "indicators",
    "iocs": "indicators",
    "containment": "containment",
    "containment steps": "containment",
    "immediate containment": "containment",
    "investigation": "investigation",
    "investigation steps": "investigation",
    "analysis": "investigation",
    "recovery": "recovery",
    "recovery steps": "recovery",
    "remediation": "recovery",
    "prevention": "prevention",
    "prevention steps": "prevention",
    "preventive measures": "prevention",
    "recommendations": "prevention",
    "detection": "detection",
    "detection rules": "detection",
    "detection guidance": "detection",
    "monitoring": "detection",
    "affected assets": "affected_assets",
    "affected systems": "affected_assets",
    "targets": "affected_assets",
    "references": "references",
    "reference": "references",
    "common tools used by attackers": "tools",
    "tools": "tools",
    "security tools": "tools",
    "real world examples": "real_world_examples",
    "real-world examples": "real_world_examples",
    "examples": "real_world_examples",
    "keywords": "keywords",
    "signature keywords": "keywords",
    "key terms": "keywords",
}


REQUIRED_SECTIONS = {
    "description",
    "mitre",
    "severity",
    "indicators",
    "containment",
    "investigation",
    "recovery",
    "prevention",
    "detection",
    "affected_assets",
    "references",
}


MITRE_ID_PATTERN = re.compile(
    r"\bT\d{4}(?:\.\d{3})?\b",
    re.IGNORECASE,
)

INCIDENT_TYPE_PATTERN = re.compile(
    r"^\s*INCIDENT\s+TYPE\s*:\s*"
    r"(?P<value>.+?)\s*$",
    re.IGNORECASE,
)

BULLET_PATTERN = re.compile(r"^\s*(?:[-*•]+|\d+[.)])\s*")

DASH_PATTERN = re.compile(r"\s+[–—-]\s+")


class TxtKnowledgeBaseParser:
    """Parse legacy CyberGPT TXT knowledge records."""

    supported_encodings = (
        "utf-8",
        "utf-8-sig",
        "cp1252",
        "latin-1",
    )

    def parse_file(
        self,
        path: Path,
    ) -> AttackKnowledgeRecord:
        if not path.is_file():
            raise KnowledgeBaseError(f"Knowledge-base file does not exist: {path}")

        text, encoding = self._read_text(path)
        digest = sha256(path.read_bytes()).hexdigest()

        return self.parse_text(
            text,
            attack_id=path.stem.lower(),
            source_filename=path.name,
            source_sha256=digest,
            source_encoding=encoding,
        )

    def parse_text(
        self,
        text: str,
        *,
        attack_id: str,
        source_filename: str,
        source_sha256: str,
        source_encoding: str = "utf-8",
    ) -> AttackKnowledgeRecord:
        if not text.strip():
            raise KnowledgeBaseError(f"Knowledge-base file is empty: {source_filename}")

        section_names = sorted(set(SECTION_ALIASES.values()))

        sections: dict[str, list[str]] = {section_name: [] for section_name in section_names}

        incident_type: str | None = None
        current_section: str | None = None

        normalized_text = text.replace("\r\n", "\n").replace("\r", "\n")

        for raw_line in normalized_text.split("\n"):
            stripped = raw_line.strip()

            if not stripped:
                continue

            incident_match = INCIDENT_TYPE_PATTERN.match(stripped)

            if incident_match:
                incident_type = incident_match.group("value").strip()
                continue

            heading = self._detect_heading(stripped)

            if heading is not None:
                current_section = heading
                continue

            if current_section is not None:
                item = self._clean_item(stripped)

                if item:
                    sections[current_section].append(item)

        if incident_type is None:
            raise KnowledgeBaseError(f"Missing 'INCIDENT TYPE:' heading in {source_filename}.")

        missing_sections = sorted(section for section in REQUIRED_SECTIONS if not sections[section])

        if missing_sections:
            raise KnowledgeBaseError(
                f"{source_filename} is missing required content for: " + ", ".join(missing_sections)
            )

        severity = self._parse_severity(
            sections["severity"][0],
            source_filename,
        )

        framework_references = self._parse_framework_references(
            sections["mitre"],
            source_filename,
        )

        return AttackKnowledgeRecord(
            attack_id=attack_id,
            incident_type=incident_type,
            description=" ".join(sections["description"]).strip(),
            severity=severity,
            framework_references=(framework_references),
            indicators=tuple(sections["indicators"]),
            containment=tuple(sections["containment"]),
            investigation=tuple(sections["investigation"]),
            recovery=tuple(sections["recovery"]),
            prevention=tuple(sections["prevention"]),
            detection_rules=tuple(sections["detection"]),
            affected_assets=tuple(sections["affected_assets"]),
            references=tuple(sections["references"]),
            tools=tuple(sections["tools"]),
            real_world_examples=tuple(sections["real_world_examples"]),
            keywords=tuple(sections["keywords"]),
            source_filename=source_filename,
            source_sha256=source_sha256,
            source_encoding=source_encoding,
        )

    @staticmethod
    def _normalise_heading(
        value: str,
    ) -> str:
        cleaned = value.strip()

        cleaned = re.sub(
            r"^[#*\-\s]+",
            "",
            cleaned,
        )

        cleaned = re.sub(
            r"[:\-–—]+\s*$",
            "",
            cleaned,
        )

        cleaned = re.sub(
            r"\s+",
            " ",
            cleaned,
        )

        return cleaned.strip().lower()

    def _detect_heading(
        self,
        line: str,
    ) -> str | None:
        is_heading_shape = (
            line.endswith(":")
            or line.startswith("#")
            or (len(line) <= 100 and line.upper() == line)
        )

        if not is_heading_shape:
            return None

        normalized = self._normalise_heading(line)

        return SECTION_ALIASES.get(normalized)

    @staticmethod
    def _clean_item(
        value: str,
    ) -> str:
        cleaned = BULLET_PATTERN.sub(
            "",
            value,
        ).strip()

        return re.sub(
            r"\s+",
            " ",
            cleaned,
        )

    @staticmethod
    def _parse_severity(
        value: str,
        source_filename: str,
    ) -> SeverityLevel:
        normalized = value.strip().lower()

        try:
            return SeverityLevel(normalized)
        except ValueError as error:
            raise KnowledgeBaseError(
                f"Unsupported severity '{value}' in {source_filename}."
            ) from error

    @staticmethod
    def _parse_framework_references(
        values: list[str],
        source_filename: str,
    ) -> tuple[
        ThreatFrameworkReference,
        ...,
    ]:
        references: list[ThreatFrameworkReference] = []

        for raw_value in values:
            technique_ids = MITRE_ID_PATTERN.findall(raw_value)

            if technique_ids:
                parts = DASH_PATTERN.split(
                    raw_value,
                    maxsplit=1,
                )

                name = parts[1].strip() if len(parts) == 2 else raw_value.strip()

                for technique_id in technique_ids:
                    references.append(
                        ThreatFrameworkReference(
                            framework=("MITRE ATT&CK"),
                            reference_id=(technique_id.upper()),
                            name=name,
                            raw_value=raw_value,
                        )
                    )

                continue

            if "emerging ai threat" in raw_value.lower():
                references.append(
                    ThreatFrameworkReference(
                        framework=("Emerging AI Threat"),
                        reference_id=None,
                        name=("Emerging AI Threat"),
                        raw_value=raw_value,
                    )
                )

                continue

            references.append(
                ThreatFrameworkReference(
                    framework="Unmapped",
                    reference_id=None,
                    name=raw_value,
                    raw_value=raw_value,
                )
            )

        if not references:
            raise KnowledgeBaseError(f"No framework mapping was found in {source_filename}.")

        return tuple(references)

    def _read_text(
        self,
        path: Path,
    ) -> tuple[str, str]:
        for encoding in self.supported_encodings:
            try:
                return (
                    path.read_text(encoding=encoding),
                    encoding,
                )
            except UnicodeDecodeError:
                continue

        raise KnowledgeBaseError(f"Could not decode {path.name} using supported encodings.")
