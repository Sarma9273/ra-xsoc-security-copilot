from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class APISettings:
    """Runtime configuration for the RA-XSOC API."""

    service_name: str = "ra-xsoc-api"
    environment: str = "development"
    api_version: str = "0.1.0"
    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"
    cors_enabled: bool = False
    cors_origins: tuple[str, ...] = ()
    auth_required: bool = True

    @classmethod
    def from_environment(cls) -> APISettings:
        """Build API settings from environment variables."""
        return cls(
            service_name=os.getenv("RA_XSOC_SERVICE_NAME", "ra-xsoc-api"),
            environment=os.getenv("RA_XSOC_ENVIRONMENT", "development"),
            api_version=os.getenv("RA_XSOC_API_VERSION", "0.1.0"),
            host=os.getenv("RA_XSOC_HOST", "127.0.0.1"),
            port=int(os.getenv("RA_XSOC_PORT", "8000")),
            log_level=os.getenv("RA_XSOC_LOG_LEVEL", "INFO"),
            cors_enabled=os.getenv("RA_XSOC_CORS_ENABLED", "false").lower()
            in {"1", "true", "yes"},
            cors_origins=tuple(
                origin.strip()
                for origin in os.getenv("RA_XSOC_CORS_ORIGINS", "").split(",")
                if origin.strip()
            ),
            auth_required=os.getenv("RA_XSOC_AUTH_REQUIRED", "true").lower()
            in {"1", "true", "yes"},
        )
