"""Structured (JSON) logging with per-request correlation IDs.

Every log line is one JSON object, so log tools (Datadog, Loki, CloudWatch, a SIEM)
can filter and alert on fields such as `"event": "guardrail.blocked"` instead of
grepping free text.

Each request gets an id stored in a ContextVar. Every log line written while that
request is handled carries the same `request_id`, so an investigator can pull up the
full story of one request, from prompt check to LLM call to response check.
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any, TextIO

# ContextVar (not a global) because the server handles many requests concurrently;
# each one sees its own value.
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
            "request_id": request_id_var.get(),
        }
        # Structured fields: logger.info("guardrail.blocked", extra={"data": {...}})
        data = getattr(record, "data", None)
        if data:
            entry["data"] = data
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging(level: str = "INFO", stream: TextIO | None = None) -> None:
    """Send all logs to stdout as JSON. Containers should log to stdout and let the
    platform collect them, rather than writing files inside the container."""
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
