"""Unit tests for structured JSON logging configuration (COMP-8)."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator

import pytest

from src.external.logging_config import configure_logging


@pytest.fixture(autouse=True)
def _restore_root_logger() -> Iterator[None]:
    """Snapshot and restore the root logger so tests don't leak handlers."""
    root = logging.getLogger()
    original_handlers = list(root.handlers)
    original_level = root.level
    try:
        yield
    finally:
        root.handlers = original_handlers
        root.setLevel(original_level)


def _reconfigure_with_capture() -> logging.StreamHandler:
    """Call configure_logging() then swap the stdout handler's stream for an in-memory buffer."""
    import io

    configure_logging()
    root = logging.getLogger()
    capture = io.StringIO()
    for handler in root.handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.stream = capture
    return capture  # type: ignore[return-value]


def test_log_record_renders_as_valid_json_with_expected_keys() -> None:
    capture = _reconfigure_with_capture()

    logger = logging.getLogger("src.application.audit_log")
    logger.info(
        "audit_event_logged",
        extra={
            "event_id": "11111111-1111-1111-1111-111111111111",
            "event_type": "evidence.upload_requested",
            "seq": 1,
        },
    )

    line = capture.getvalue().strip()  # type: ignore[attr-defined]
    parsed = json.loads(line)

    assert parsed["event"] == "audit_event_logged"
    assert parsed["event_type"] == "evidence.upload_requested"
    assert parsed["seq"] == 1
    assert parsed["level"] == "info"
    assert parsed["logger"] == "src.application.audit_log"
    assert "timestamp" in parsed


def test_extra_fields_from_existing_call_sites_are_preserved() -> None:
    """Existing `logger.info(msg, extra={...})` call sites need no code changes."""
    capture = _reconfigure_with_capture()

    logging.getLogger(__name__).warning(
        "audit_chain_tampered", extra={"detail": "Hash mismatch at seq=3"}
    )

    parsed = json.loads(capture.getvalue().strip())  # type: ignore[attr-defined]
    assert parsed["event"] == "audit_chain_tampered"
    assert parsed["detail"] == "Hash mismatch at seq=3"
    assert parsed["level"] == "warning"


def test_configure_logging_writes_to_file_when_path_given(tmp_path: object) -> None:
    import os

    log_path = os.path.join(str(tmp_path), "nested", "app.log")
    configure_logging(log_file_path=log_path)

    logging.getLogger("test.file").info("hello", extra={"foo": "bar"})
    for handler in logging.getLogger().handlers:
        handler.flush()

    with open(log_path, encoding="utf-8") as f:
        parsed = json.loads(f.readline())

    assert parsed["event"] == "hello"
    assert parsed["foo"] == "bar"


def test_configure_logging_reads_log_file_path_from_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    import os

    log_path = os.path.join(str(tmp_path), "env.log")
    monkeypatch.setenv("KRONOS_LOG_FILE", log_path)

    configure_logging()

    logging.getLogger("test.env").info("from_env")
    for handler in logging.getLogger().handlers:
        handler.flush()

    assert os.path.exists(log_path)
    with open(log_path, encoding="utf-8") as f:
        parsed = json.loads(f.readline())
    assert parsed["event"] == "from_env"


def test_configure_logging_respects_log_level_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KRONOS_LOG_LEVEL", "WARNING")
    configure_logging()
    assert logging.getLogger().level == logging.WARNING
