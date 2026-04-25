"""Tests for message_walker.py — walks Anthropic message structures."""

from piiproxy.message_walker import sanitize_request_body


def _upper(text: str) -> str:
    """Simple mutator for testing."""
    return text.upper()


def test_string_content():
    body = {
        "messages": [{"role": "user", "content": "hello world"}],
    }
    result = sanitize_request_body(body, _upper)
    assert result["messages"][0]["content"] == "HELLO WORLD"


def test_array_content_text_block():
    body = {
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": "hello world"}],
            }
        ],
    }
    result = sanitize_request_body(body, _upper)
    assert result["messages"][0]["content"][0]["text"] == "HELLO WORLD"


def test_tool_use_block():
    body = {
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "tool_1",
                        "name": "search",
                        "input": {"query": "find this", "nested": {"value": "deep text"}},
                    }
                ],
            }
        ],
    }
    result = sanitize_request_body(body, _upper)
    tool_input = result["messages"][0]["content"][0]["input"]
    assert tool_input["query"] == "FIND THIS"
    assert tool_input["nested"]["value"] == "DEEP TEXT"


def test_tool_result_string_content():
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "tool_1",
                        "content": "result text here",
                    }
                ],
            }
        ],
    }
    result = sanitize_request_body(body, _upper)
    assert result["messages"][0]["content"][0]["content"] == "RESULT TEXT HERE"


def test_tool_result_array_content():
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "tool_1",
                        "content": [{"type": "text", "text": "nested result"}],
                    }
                ],
            }
        ],
    }
    result = sanitize_request_body(body, _upper)
    assert result["messages"][0]["content"][0]["content"][0]["text"] == "NESTED RESULT"


def test_system_string():
    body = {
        "system": "you are a helper",
        "messages": [{"role": "user", "content": "hi"}],
    }
    result = sanitize_request_body(body, _upper)
    assert result["system"] == "YOU ARE A HELPER"


def test_system_array():
    body = {
        "system": [{"type": "text", "text": "you are a helper"}],
        "messages": [{"role": "user", "content": "hi"}],
    }
    result = sanitize_request_body(body, _upper)
    assert result["system"][0]["text"] == "YOU ARE A HELPER"


def test_image_block_unchanged():
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "image", "source": {"type": "base64", "data": "abc123"}},
                    {"type": "text", "text": "describe this"},
                ],
            }
        ],
    }
    result = sanitize_request_body(body, _upper)
    # Image block should be unchanged
    assert result["messages"][0]["content"][0]["source"]["data"] == "abc123"
    # Text block should be mutated
    assert result["messages"][0]["content"][1]["text"] == "DESCRIBE THIS"


def test_preserves_other_fields():
    body = {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": "hello"}],
    }
    result = sanitize_request_body(body, _upper)
    assert result["model"] == "claude-sonnet-4-20250514"
    assert result["max_tokens"] == 1024
