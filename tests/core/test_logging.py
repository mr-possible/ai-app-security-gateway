import io
import json
import logging

import pytest

from app.core.logging import configure_logging, request_id_var


@pytest.fixture
def log_stream():
    """Route logs into a buffer for the test, then restore the original setup."""
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    stream = io.StringIO()
    configure_logging("DEBUG", stream=stream)
    yield stream
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


def read_lines(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def test_each_line_is_valid_json_with_core_fields(log_stream):
    logging.getLogger("app.test").info("guardrail.passed")
    (entry,) = read_lines(log_stream)
    assert entry["event"] == "guardrail.passed"
    assert entry["level"] == "INFO"
    assert entry["logger"] == "app.test"
    assert entry["timestamp"].endswith("+00:00")


def test_structured_data_is_included(log_stream):
    logging.getLogger("app").warning(
        "guardrail.blocked", extra={"data": {"risk_score": 0.95, "rules": ["io.ignore"]}}
    )
    (entry,) = read_lines(log_stream)
    assert entry["data"] == {"risk_score": 0.95, "rules": ["io.ignore"]}


def test_request_id_is_attached_to_every_line(log_stream):
    token = request_id_var.set("req-abc")
    try:
        logging.getLogger("app").info("first")
        logging.getLogger("app").info("second")
    finally:
        request_id_var.reset(token)
    logging.getLogger("app").info("outside request")
    ids = [e["request_id"] for e in read_lines(log_stream)]
    assert ids == ["req-abc", "req-abc", None]


def test_exceptions_are_captured(log_stream):
    try:
        raise RuntimeError("upstream timeout")
    except RuntimeError:
        logging.getLogger("app").exception("llm.call_failed")
    (entry,) = read_lines(log_stream)
    assert "RuntimeError: upstream timeout" in entry["exception"]


def test_level_filtering():
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    stream = io.StringIO()
    try:
        configure_logging("WARNING", stream=stream)
        logging.getLogger("app").info("hidden")
        logging.getLogger("app").warning("shown")
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
    assert [e["event"] for e in read_lines(stream)] == ["shown"]


FAKE_KEY = "sk-" + "leak" * 8  # assembled at runtime so secret scanners stay quiet


def test_secrets_in_messages_are_scrubbed(log_stream):
    logging.getLogger("app").error("upstream said: invalid key %s", FAKE_KEY)
    raw = log_stream.getvalue()
    assert FAKE_KEY not in raw
    assert "[API_KEY_REDACTED]" in raw


def test_pii_inside_structured_data_is_scrubbed(log_stream):
    logging.getLogger("app").info(
        "user.lookup",
        extra={"data": {"user": {"email": "jane@acme.com"}, "phones": ["+91 98765 43210"]}},
    )
    (entry,) = read_lines(log_stream)
    assert entry["data"] == {
        "user": {"email": "[EMAIL_REDACTED]"},
        "phones": ["[PHONE_REDACTED]"],
    }


def test_secrets_inside_exception_tracebacks_are_scrubbed(log_stream):
    try:
        raise PermissionError(f"auth failed for {FAKE_KEY}")
    except PermissionError:
        logging.getLogger("app").exception("llm.auth_failed")
    assert FAKE_KEY not in log_stream.getvalue()


def test_non_string_values_are_left_intact(log_stream):
    logging.getLogger("app").info("score", extra={"data": {"risk": 0.95, "blocked": True}})
    (entry,) = read_lines(log_stream)
    assert entry["data"] == {"risk": 0.95, "blocked": True}
