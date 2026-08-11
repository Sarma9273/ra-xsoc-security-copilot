# RA-XSOC Knowledge-Base Schema

## Source

RA-XSOC V2 initially imports thirty legacy CyberGPT TXT
knowledge records.

The source files remain unchanged and are treated as
immutable evidence.

## Required fields

- attack ID
- incident type
- description
- severity
- threat-framework mapping
- indicators
- containment
- investigation
- recovery
- prevention
- detection rules
- affected assets
- references

## Optional fields

- tools
- real-world examples
- keywords

Keywords are not invented during legacy import because the
V1 documents do not contain a dedicated keyword section.

## Framework mappings

Conventional attacks may contain MITRE ATT&CK technique or
sub-technique identifiers.

Emerging AI threats may contain descriptive framework
mappings without a conventional MITRE identifier.

The raw source value is always preserved.

## Provenance

Every normalized record stores:

- original filename
- original encoding
- SHA-256 checksum
- schema version

This allows the normalized representation to be traced back
to its exact source document.
