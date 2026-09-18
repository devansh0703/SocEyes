from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger("fda.config")


class Settings:
    """Environment-driven configuration.

    Nothing here carries a usable default credential: a missing secret is
    surfaced as a startup warning instead of silently falling back to a password
    that is published in this repository.
    """

    app_name = "FDA Detection API"

    elasticsearch_url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9201").rstrip("/")
    elastic_user = os.environ.get("ELASTIC_USER", "elastic")
    elastic_password = os.environ.get("ELASTIC_PASSWORD", "")
    es_timeout_seconds = int(os.environ.get("FDA_ES_TIMEOUT_SECONDS", "30"))

    playbook_root = Path(
        os.environ.get("SOAR_PLAYBOOK_ROOT", "vendor/MITRE-ATT_CK-Playbooks/Playbooks")
    )
    cors_origins = [
        origin.strip()
        for origin in os.environ.get("API_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
        if origin.strip()
    ]

    @property
    def allow_credentials(self) -> bool:
        """Browsers reject credentialed requests against a wildcard origin."""
        return "*" not in self.cors_origins

    def warn_about_missing_configuration(self) -> None:
        if not self.elastic_password:
            logger.warning(
                "ELASTIC_PASSWORD is not set: Elasticsearch requests will fail with 401. "
                "Copy .env.example to .env and set it."
            )
        if not os.environ.get("NVIDIA_API_KEY", "").strip():
            logger.info("NVIDIA_API_KEY is not set: LLM-backed summaries are disabled.")


settings = Settings()

