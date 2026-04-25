"""Debug logging: logs incoming vs outgoing request body diffs."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

REQUEST_DEBUG_LOG = "request_debug.jsonl"


def log_request_pair(incoming_body: Any, outgoing_body: Any) -> None:
    """Write one JSONL entry comparing the body before and after sanitization."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "incoming_body": incoming_body,
        "outgoing_body": outgoing_body,
        "body_sanitized": incoming_body != outgoing_body,
    }
    try:
        with open(Path(REQUEST_DEBUG_LOG), "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        logger.exception("Failed to write request debug log")
