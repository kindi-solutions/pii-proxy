"""Presidio recognizers for secret keys and API tokens."""

from __future__ import annotations

from typing import ClassVar

from presidio_analyzer import Pattern, PatternRecognizer


class SecretKeyRecognizer(PatternRecognizer):
    """Recognizes common secret keys and API tokens (AWS, GitHub, Bitbucket, Sentry, generic)."""

    PATTERNS: ClassVar[list[Pattern]] = [
        # AWS access key ID
        Pattern("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", 0.95),
        # GitHub tokens
        Pattern("github_pat_classic", r"\bghp_[A-Za-z0-9]{36}\b", 0.95),
        Pattern("github_pat_fine", r"\bgithub_pat_[A-Za-z0-9_]{82}\b", 0.95),
        Pattern("github_oauth", r"\bgho_[A-Za-z0-9]{36}\b", 0.95),
        Pattern("github_app", r"\bghs_[A-Za-z0-9]{36}\b", 0.95),
        # Generic sk-/pk- style (OpenAI, Stripe, etc.)
        Pattern("generic_sk_pk", r"\b(?:sk|pk|rk)[-_](?:live|test|prod|proj)?[-_]?[A-Za-z0-9_-]{20,}\b", 0.85),
        # Bitbucket / Atlassian app passwords and API tokens
        Pattern("bitbucket_app_password", r"\bATBB[A-Za-z0-9]{32}\b", 0.95),
        Pattern("atlassian_api_token", r"\bATATT3x[A-Za-z0-9_-]{38}\b", 0.95),
        # Sentry auth tokens (new format) and DSN
        Pattern("sentry_token", r"\bsntrys_[A-Za-z0-9+/=]{40,}\b", 0.95),
        Pattern("sentry_dsn", r"https://[0-9a-f]{32}@(?:[a-z0-9]+\.)?(?:ingest\.)?sentry\.io/[0-9]+", 0.95),
        Pattern("sentry_dsn_country_code", r"https://[0-9a-f]{32}@[a-z0-9]+(?:\.[a-z0-9]+)*\.sentry\.io/[0-9]+", 0.95),
    ]
    def __init__(self) -> None:
        super().__init__(
            supported_entity="SECRET_KEY",
            patterns=self.PATTERNS,
            supported_language="en",
        )


def get_secret_key_recognizers() -> list[PatternRecognizer]:
    """Return all secret key recognizers."""
    return [SecretKeyRecognizer()]
