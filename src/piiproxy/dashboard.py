"""Lightweight HTML dashboard for sanitization statistics."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _read_jsonl(path: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    p = Path(path)
    if not p.exists():
        return entries
    with open(p) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def _extract_last_user_message(body: Any) -> str:
    """Pull the last user message text out of an Anthropic request body."""
    messages = body.get("messages", []) if isinstance(body, dict) else []
    for msg in reversed(messages):
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        return block.get("text", "")
    return ""


def _bar(value: int, max_value: int, color: str = "#e05252") -> str:
    pct = int((value / max_value) * 100) if max_value else 0
    return (
        f'<div style="background:#eee;border-radius:4px;height:18px;width:100%">'
        f'<div style="background:{color};width:{pct}%;height:18px;border-radius:4px;'
        f'transition:width 0.3s"></div></div>'
    )


def render_dashboard(audit_log: str, request_log: str) -> str:
    audit_entries = _read_jsonl(audit_log)
    request_entries = _read_jsonl(request_log)

    # --- stats ---
    total_requests = len(request_entries)
    sanitized_requests = sum(
        1 for e in request_entries if e.get("body_sanitized")
    )
    clean_requests = total_requests - sanitized_requests
    total_entities = sum(e.get("total_count", 0) for e in audit_entries)

    pii_counts: Counter[str] = Counter()
    secret_counts: Counter[str] = Counter()
    for e in audit_entries:
        for entity in e.get("entities_found", []):
            if entity["entity_type"] == "SECRET_KEY":
                secret_counts[entity["entity_type"]] += 1
            else:
                pii_counts[entity["entity_type"]] += 1

    max_pii = max(pii_counts.values(), default=1)
    max_secret = max(secret_counts.values(), default=1)

    # --- recent sanitized messages (last 5) ---
    recent = [e for e in request_entries if e.get("body_sanitized")][-10:]

    # --- HTML ---
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    pii_rows = ""
    for entity, count in pii_counts.most_common():
        pii_rows += f"""
        <tr>
          <td style="padding:8px 12px;font-family:monospace;font-size:13px">{entity}</td>
          <td style="padding:8px 12px;width:60%">{_bar(count, max_pii, "#e05252")}</td>
          <td style="padding:8px 12px;text-align:right;font-weight:600">{count}</td>
        </tr>"""
    if not pii_rows:
        pii_rows = '<tr><td colspan="3" style="padding:16px;color:#999;text-align:center">No PII detected yet</td></tr>'

    secret_rows = ""
    for entity, count in secret_counts.most_common():
        secret_rows += f"""
        <tr>
          <td style="padding:8px 12px;font-family:monospace;font-size:13px">{entity}</td>
          <td style="padding:8px 12px;width:60%">{_bar(count, max_secret, "#8e44ad")}</td>
          <td style="padding:8px 12px;text-align:right;font-weight:600">{count}</td>
        </tr>"""
    if not secret_rows:
        secret_rows = '<tr><td colspan="3" style="padding:16px;color:#999;text-align:center">No secret keys detected yet</td></tr>'

    message_rows = ""
    for e in reversed(recent):
        ts = e.get("timestamp", "")[:19].replace("T", " ")
        before = _extract_last_user_message(e.get("incoming_body"))
        after = _extract_last_user_message(e.get("outgoing_body"))
        message_rows += f"""
        <tr>
          <td style="padding:10px 12px;color:#999;font-size:12px;white-space:nowrap">{ts}</td>
          <td style="padding:10px 12px;font-family:monospace;font-size:12px;color:#c0392b;word-break:break-word">{_escape(before)}</td>
          <td style="padding:10px 12px;font-family:monospace;font-size:12px;color:#27ae60;word-break:break-word">{_escape(after)}</td>
        </tr>"""

    if not message_rows:
        message_rows = '<tr><td colspan="3" style="padding:16px;color:#999;text-align:center">No sanitized messages yet</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>pii-proxy</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0 }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #f4f6f8; color: #2c3e50; }}
    header {{ background: #2c3e50; color: white; padding: 18px 32px;
              display: flex; justify-content: space-between; align-items: center }}
    header h1 {{ font-size: 18px; font-weight: 600 }}
    header span {{ font-size: 12px; opacity: 0.6 }}
    .cards {{ display: flex; gap: 16px; padding: 24px 32px }}
    .card {{ background: white; border-radius: 8px; padding: 20px 24px;
             flex: 1; box-shadow: 0 1px 3px rgba(0,0,0,.08) }}
    .card .label {{ font-size: 12px; color: #888; text-transform: uppercase;
                    letter-spacing: .05em; margin-bottom: 8px }}
    .card .value {{ font-size: 32px; font-weight: 700 }}
    .card.highlight .value {{ color: #e05252 }}
    section {{ margin: 0 32px 24px; background: white; border-radius: 8px;
               box-shadow: 0 1px 3px rgba(0,0,0,.08); overflow: hidden }}
    section h2 {{ font-size: 14px; font-weight: 600; padding: 16px 20px;
                  border-bottom: 1px solid #f0f0f0; background: #fafafa }}
    table {{ width: 100%; border-collapse: collapse }}
    tr:not(:last-child) td {{ border-bottom: 1px solid #f5f5f5 }}
  </style>
</head>
<body>
  <header>
    <h1>pii-proxy &mdash; PII Dashboard</h1>
    <span>Updated: {now}</span>
  </header>

  <div class="cards">
    <div class="card">
      <div class="label">Total Requests</div>
      <div class="value">{total_requests}</div>
    </div>
    <div class="card highlight">
      <div class="label">Requests with PII</div>
      <div class="value">{sanitized_requests}</div>
    </div>
    <div class="card">
      <div class="label">Clean Requests</div>
      <div class="value">{clean_requests}</div>
    </div>
    <div class="card highlight">
      <div class="label">PII Entities Removed</div>
      <div class="value">{total_entities}</div>
    </div>
  </div>

  <section>
    <h2>Swedish PII Entities</h2>
    <table>{pii_rows}</table>
  </section>

  <section>
    <h2>Secret Keys Detected</h2>
    <table>{secret_rows}</table>
  </section>

  <section>
    <h2>Recent Sanitized Messages (last 10)</h2>
    <table>
      <thead>
        <tr style="background:#fafafa">
          <th style="padding:8px 12px;text-align:left;font-size:12px;color:#888;font-weight:500">Time</th>
          <th style="padding:8px 12px;text-align:left;font-size:12px;color:#c0392b;font-weight:500">Before</th>
          <th style="padding:8px 12px;text-align:left;font-size:12px;color:#27ae60;font-weight:500">After</th>
        </tr>
      </thead>
      <tbody>{message_rows}</tbody>
    </table>
  </section>
</body>
</html>"""


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )
