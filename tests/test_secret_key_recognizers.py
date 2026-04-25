"""Tests for secret key and API token recognizers."""

import pytest

from piiproxy.secret_key_recognizers import (
    SecretKeyRecognizer,
    get_secret_key_recognizers,
)


@pytest.fixture
def recognizer():
    return SecretKeyRecognizer()


def _detected(recognizer: SecretKeyRecognizer, text: str) -> bool:
    """Return True if any SECRET_KEY entity is found in the text."""
    results = recognizer.analyze(text=text, entities=["SECRET_KEY"])
    return any(r.entity_type == "SECRET_KEY" for r in results)


class TestAWSAccessKey:
    def test_valid_key_detected(self, recognizer):
        assert _detected(recognizer, "AKIAIOSFODNN7EXAMPLE")

    def test_valid_key_in_sentence(self, recognizer):
        assert _detected(recognizer, "Set AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE in your env")

    def test_too_short_not_detected(self, recognizer):
        assert not _detected(recognizer, "AKIAIOSFODNN7")  # only 13 chars after AKIA

    def test_lowercase_not_detected(self, recognizer):
        assert not _detected(recognizer, "akiaiosfodnn7example1234")


class TestGitHubTokens:
    def test_classic_pat_detected(self, recognizer):
        assert _detected(recognizer, "ghp_" + "A" * 36)

    def test_fine_grained_pat_detected(self, recognizer):
        assert _detected(recognizer, "github_pat_" + "A" * 82)

    def test_oauth_token_detected(self, recognizer):
        assert _detected(recognizer, "gho_" + "A" * 36)

    def test_app_token_detected(self, recognizer):
        assert _detected(recognizer, "ghs_" + "A" * 36)

    def test_classic_pat_too_short_not_detected(self, recognizer):
        assert not _detected(recognizer, "ghp_" + "A" * 10)

    def test_classic_pat_in_config_line(self, recognizer):
        token = "ghp_" + "Abc123xyz" * 4
        assert _detected(recognizer, f"GITHUB_TOKEN={token}")


class TestGenericSkPkKeys:
    def test_openai_sk_detected(self, recognizer):
        assert _detected(recognizer, "sk-" + "A" * 48)

    def test_stripe_live_sk_detected(self, recognizer):
        assert _detected(recognizer, "sk_live_" + "A" * 24)

    def test_stripe_test_pk_detected(self, recognizer):
        assert _detected(recognizer, "pk_test_" + "A" * 24)

    def test_rk_prefix_detected(self, recognizer):
        assert _detected(recognizer, "rk_" + "A" * 20)

    def test_too_short_not_detected(self, recognizer):
        assert not _detected(recognizer, "sk-" + "A" * 5)  # under 20 chars

    def test_sk_prod_detected(self, recognizer):
        assert _detected(recognizer, "sk_prod_" + "a1b2c3d4e5f6" * 2)


class TestBitbucketTokens:
    def test_app_password_detected(self, recognizer):
        assert _detected(recognizer, "ATBB" + "A" * 32)

    def test_atlassian_api_token_detected(self, recognizer):
        assert _detected(recognizer, "ATATT3x" + "A" * 38)

    def test_app_password_too_short_not_detected(self, recognizer):
        assert not _detected(recognizer, "ATBB" + "A" * 10)

    def test_atlassian_token_in_sentence(self, recognizer):
        token = "ATATT3x" + "A" * 38
        assert _detected(recognizer, f"Use token {token} for Bitbucket access")


class TestSentryTokens:
    def test_new_format_token_detected(self, recognizer):
        token = "sntrys_" + "A" * 40
        assert _detected(recognizer, token)

    def test_new_format_token_in_sentence(self, recognizer):
        token = "sntrys_" + "Abc1XyZ2" * 5
        assert _detected(recognizer, f"SENTRY_AUTH_TOKEN={token}")

    def test_token_too_short_not_detected(self, recognizer):
        assert not _detected(recognizer, "sntrys_" + "A" * 5)

    def test_dsn_detected(self, recognizer):
        dsn = "https://" + "a1b2c3d4" * 4 + "@sentry.io/12345"
        assert _detected(recognizer, dsn)

    def test_dsn_with_ingest_subdomain_detected(self, recognizer):
        dsn = "https://" + "a1b2c3d4" * 4 + "@o999.ingest.sentry.io/99999"
        assert _detected(recognizer, dsn)

    def test_dsn_with_short_hash_not_detected(self, recognizer):
        # Hash must be exactly 32 hex chars
        dsn = "https://" + "abc123" + "@sentry.io/12345"
        assert not _detected(recognizer, dsn)


class TestGetSecretKeyRecognizers:
    def test_returns_one_recognizer(self):
        recognizers = get_secret_key_recognizers()
        assert len(recognizers) == 1

    def test_recognizer_is_correct_type(self):
        recognizers = get_secret_key_recognizers()
        assert isinstance(recognizers[0], SecretKeyRecognizer)

    def test_recognizer_supports_secret_key_entity(self):
        recognizers = get_secret_key_recognizers()
        assert "SECRET_KEY" in recognizers[0].supported_entities
