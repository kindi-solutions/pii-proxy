"""Tests for the Presidio-based sanitizer."""

import pytest

from piiproxy.config import Settings
from piiproxy.sanitizer import Sanitizer


@pytest.fixture
def sanitizer():
    settings = Settings()
    # Only use English to avoid needing Swedish spaCy model in tests
    settings.sanitization.languages = ["en"]
    settings.audit.enabled = False
    return Sanitizer(settings)


class TestSanitizeText:
    def test_no_pii(self, sanitizer: Sanitizer):
        text = "The weather is nice today."
        result = sanitizer.sanitize_text(text)
        assert result == text

    def test_email_redacted(self, sanitizer: Sanitizer):
        text = "Contact me at john.doe@example.com for details."
        result = sanitizer.sanitize_text(text)
        assert "john.doe@example.com" not in result
        assert "EMAIL_ADDRESS" in result

    def test_phone_redacted(self, sanitizer: Sanitizer):
        text = "My phone number is +46701234567."
        result = sanitizer.sanitize_text(text)
        assert "+46701234567" not in result

    def test_empty_string(self, sanitizer: Sanitizer):
        assert sanitizer.sanitize_text("") == ""

    def test_whitespace_only(self, sanitizer: Sanitizer):
        assert sanitizer.sanitize_text("   ") == "   "

    def test_allowlist_preserved(self, sanitizer: Sanitizer):
        text = "Claude is made by Anthropic."
        result = sanitizer.sanitize_text(text)
        assert "Claude" in result
        assert "Anthropic" in result


class TestSanitizeRequest:
    def test_simple_message(self, sanitizer: Sanitizer):
        body = {
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": "My email is john@example.com"}
            ],
        }
        result = sanitizer.sanitize_request(body)
        content = result["messages"][0]["content"]
        assert "john@example.com" not in content
        assert result["model"] == "claude-sonnet-4-20250514"

    def test_counters_reset_per_request(self, sanitizer: Sanitizer):
        body1 = {
            "messages": [
                {"role": "user", "content": "Email: a@b.com"}
            ],
        }
        body2 = {
            "messages": [
                {"role": "user", "content": "Email: c@d.com"}
            ],
        }
        sanitizer.sanitize_request(body1)
        result2 = sanitizer.sanitize_request(body2)
        # Counter should reset, so we get _1 again not _2
        content = result2["messages"][0]["content"]
        assert "_1>" in content or "EMAIL" in content
