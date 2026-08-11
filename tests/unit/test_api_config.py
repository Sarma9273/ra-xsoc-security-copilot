from __future__ import annotations

from ra_xsoc_api.config import APISettings


def test_default_configuration() -> None:
    settings = APISettings.from_environment()

    assert settings.service_name == "ra-xsoc-api"
    assert settings.environment == "development"
    assert settings.api_version == "0.1.0"
    assert settings.host == "127.0.0.1"
    assert settings.port == 8000
    assert settings.log_level == "INFO"
    assert settings.cors_enabled is False


def test_configuration_reads_environment_variables(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "RA_XSOC_SERVICE_NAME",
        "ra-xsoc-test",
    )
    monkeypatch.setenv(
        "RA_XSOC_ENVIRONMENT",
        "test",
    )
    monkeypatch.setenv(
        "RA_XSOC_API_VERSION",
        "9.9.9",
    )
    monkeypatch.setenv(
        "RA_XSOC_HOST",
        "0.0.0.0",
    )
    monkeypatch.setenv(
        "RA_XSOC_PORT",
        "9000",
    )
    monkeypatch.setenv(
        "RA_XSOC_LOG_LEVEL",
        "DEBUG",
    )
    monkeypatch.setenv(
        "RA_XSOC_CORS_ENABLED",
        "true",
    )

    settings = APISettings.from_environment()

    assert settings.service_name == "ra-xsoc-test"
    assert settings.environment == "test"
    assert settings.api_version == "9.9.9"
    assert settings.host == "0.0.0.0"
    assert settings.port == 9000
    assert settings.log_level == "DEBUG"
    assert settings.cors_enabled is True


def test_cors_environment_accepts_common_true_values(
    monkeypatch,
) -> None:
    for value in ("1", "true", "TRUE", "yes", "Yes"):
        monkeypatch.setenv(
            "RA_XSOC_CORS_ENABLED",
            value,
        )

        settings = APISettings.from_environment()

        assert settings.cors_enabled is True


def test_cors_environment_defaults_to_false(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "RA_XSOC_CORS_ENABLED",
        "false",
    )

    settings = APISettings.from_environment()

    assert settings.cors_enabled is False