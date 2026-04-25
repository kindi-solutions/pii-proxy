"""Walk Anthropic message request bodies to extract all text fields for sanitization."""

from __future__ import annotations

from typing import Any, Callable


def _walk_string_values(obj: Any, mutator: Callable[[str], str]) -> Any:
    """Recursively walk a JSON-like object and apply mutator to all string values."""
    if isinstance(obj, str):
        return mutator(obj)
    if isinstance(obj, list):
        return [_walk_string_values(item, mutator) for item in obj]
    if isinstance(obj, dict):
        return {k: _walk_string_values(v, mutator) for k, v in obj.items()}
    return obj


def _sanitize_content(content: str | list[dict[str, Any]], mutator: Callable[[str], str]) -> str | list[dict[str, Any]]:
    """Sanitize a message content field (string or array of content blocks)."""
    if isinstance(content, str):
        return mutator(content)

    result = []
    for block in content:
        block_type = block.get("type")
        sanitized_block = dict(block)

        if block_type == "text":
            sanitized_block["text"] = mutator(block["text"])
        elif block_type == "tool_use":
            # Recursively walk all string values in tool input
            sanitized_block["input"] = _walk_string_values(block.get("input", {}), mutator)
        elif block_type == "tool_result":
            inner = block.get("content")
            if inner is not None:
                sanitized_block["content"] = _sanitize_content(inner, mutator)
        # image blocks and other types pass through unchanged

        result.append(sanitized_block)
    return result


def sanitize_request_body(body: dict[str, Any], mutator: Callable[[str], str]) -> dict[str, Any]:
    """Walk an Anthropic Messages API request body and apply mutator to all text fields.

    Args:
        body: The full request JSON body.
        mutator: A function that takes a string and returns a sanitized string.

    Returns:
        A new dict with all text fields sanitized.
    """
    result = dict(body)

    # Sanitize system prompt
    system = result.get("system")
    if system is not None:
        if isinstance(system, str):
            result["system"] = mutator(system)
        elif isinstance(system, list):
            sanitized_system = []
            for block in system:
                if block.get("type") == "text":
                    sanitized_system.append({**block, "text": mutator(block["text"])})
                else:
                    sanitized_system.append(block)
            result["system"] = sanitized_system

    # Sanitize messages
    messages = result.get("messages")
    if messages is not None:
        sanitized_messages = []
        for msg in messages:
            sanitized_msg = dict(msg)
            content = msg.get("content")
            if content is not None:
                sanitized_msg["content"] = _sanitize_content(content, mutator)
            sanitized_messages.append(sanitized_msg)
        result["messages"] = sanitized_messages

    return result
