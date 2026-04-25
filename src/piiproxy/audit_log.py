"""Structured JSONL audit logging for PII detections."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from presidio_analyzer import RecognizerResult

    from .config import AuditConfig

logger = logging.getLogger(__name__)


def log_pii_detection(
    results: list[RecognizerResult],
    original_text: str | None,
    config: AuditConfig,
) -> None:
    """Write a PII detection event to the audit log.

    Args:
        results: Presidio analyzer results.
        original_text: The original text (only included if config allows).
        config: Audit configuration.
    """
    if not config.enabled or not results:
        return

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "entities_found": [
            {
                "entity_type": r.entity_type,
                "score": round(r.score, 3),
                "start": r.start,
                "end": r.end,
            }
            for r in results
        ],
        "total_count": len(results),
    }

    if config.log_original_values and original_text is not None:
        entry["original_text"] = original_text

    try:
        log_path = Path(config.log_file)
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        logger.exception("Failed to write audit log entry")
