"""Structured JSON logging configuration (structlog + stdlib integration)."""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Mapping
from types import TracebackType

import structlog

_ArgsType = tuple[object, ...] | Mapping[str, object]
_SysExcInfoType = (
    tuple[type[BaseException], BaseException, TracebackType | None] | tuple[None, None, None]
)

# Shared by both structlog-native loggers and the stdlib `logging.getLogger`
# call sites used throughout the codebase (e.g. AuditLogService.log()'s
# `logger.info("audit_event_logged", extra={...})`). structlog.stdlib.
# ExtraAdder is what makes every existing `extra={...}` call site render as
# JSON fields without editing each call site (COMP-8).
_SHARED_PROCESSORS: list[structlog.types.Processor] = [
    structlog.contextvars.merge_contextvars,
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
    structlog.processors.TimeStamper(fmt="iso", utc=True),
    structlog.stdlib.ExtraAdder(),
    structlog.processors.StackInfoRenderer(),
    structlog.processors.format_exc_info,
]

# Attribute names every stdlib LogRecord already carries (filename, module,
# levelname, ...). `Logger.makeRecord` raises KeyError if an `extra={...}`
# dict tries to reuse one of these — e.g.
# `logger.info(..., extra={"filename": ...})` in
# src/application/evidence_intake.py. That collision is normally invisible
# because the default root logger level (WARNING) silently drops INFO calls
# before makeRecord ever runs; turning logging on for real (this module's
# entire point, COMP-8) exposes it as a hard crash at every such call site
# across the codebase. Renaming the colliding key (not dropping it) here is
# the one place this can be fixed without editing every pre-existing
# `extra={...}` call site.
_RESERVED_LOGRECORD_ATTRS = frozenset(
    vars(logging.LogRecord("", 0, "", 0, "", (), None)).keys()
) | {"message", "asctime"}
_original_make_record = logging.Logger.makeRecord


def _make_record_with_safe_extra(  # noqa: PLR0913
    self: logging.Logger,
    name: str,
    level: int,
    fn: str,
    lno: int,
    msg: object,
    args: _ArgsType,
    exc_info: _SysExcInfoType | None,
    func: str | None = None,
    extra: Mapping[str, object] | None = None,
    sinfo: str | None = None,
) -> logging.LogRecord:
    """Rename (never drop) `extra` keys that collide with built-in LogRecord attributes."""
    if extra:
        extra = {
            (f"extra_{key}" if key in _RESERVED_LOGRECORD_ATTRS else key): value
            for key, value in extra.items()
        }
    return _original_make_record(
        self, name, level, fn, lno, msg, args, exc_info, func, extra, sinfo
    )


def configure_logging(log_file_path: str | None = None, level: int | None = None) -> None:
    """Wire stdlib `logging` + structlog so every log record renders as one JSON line.

    Every existing ``logging.getLogger(__name__).info(msg, extra={...})`` call
    site across the codebase (audit log, evidence intake, parsing, etc.) is
    rendered as structured JSON without modification, so app logs finally
    reach the Fluent Bit -> Wazuh/OpenSearch pipeline (COMP-8) instead of
    being unstructured stdout text that ``structlog`` (a declared dependency
    that was never actually imported anywhere) did nothing about.

    *log_file_path* defaults to the ``KRONOS_LOG_FILE`` env var (unset means
    stdout-only — read directly via ``os.getenv`` rather than
    ``pydantic_settings.Settings``, matching the existing pattern already
    used for env-driven config in this module's caller,
    ``src/external/fastapi_app.py``). When set, logs are written to both
    stdout and that file path (e.g. a volume Fluent Bit tails).

    *level* defaults to the ``KRONOS_LOG_LEVEL``/``LOG_LEVEL`` env var
    (``INFO`` if unset).
    """
    resolved_path = log_file_path if log_file_path is not None else os.getenv("KRONOS_LOG_FILE")
    resolved_level = level if level is not None else _resolve_level()

    logging.Logger.makeRecord = _make_record_with_safe_extra  # type: ignore[method-assign]

    structlog.configure(
        processors=[
            *_SHARED_PROCESSORS,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
        foreign_pre_chain=_SHARED_PROCESSORS,
    )

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if resolved_path:
        os.makedirs(os.path.dirname(resolved_path) or ".", exist_ok=True)
        handlers.append(logging.FileHandler(resolved_path))

    for handler in handlers:
        handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = handlers
    root_logger.setLevel(resolved_level)


def _resolve_level() -> int:
    """Resolve the stdlib log level from KRONOS_LOG_LEVEL/LOG_LEVEL, defaulting to INFO."""
    name = os.getenv("KRONOS_LOG_LEVEL", os.getenv("LOG_LEVEL", "INFO")).upper()
    level = getattr(logging, name, None)
    return level if isinstance(level, int) else logging.INFO
