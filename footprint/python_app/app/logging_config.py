"""Structured logging configuration with correlation ID tracking and secret redaction."""

import json
import logging
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Optional

# Context variable for request correlation ID
request_id_ctx: ContextVar[Optional[str]] = ContextVar("request_id_ctx", default=None)

# Sensitive keys that must be redacted if present in logging dictionaries
REDACTED_KEYS = {
    "authorization",
    "password",
    "secret",
    "token",
    "cookie",
    "access_token",
    "api_key",
    "secret_key"
}


class StructuredJsonFormatter(logging.Formatter):
    """JSON log formatter adhering to cloud-native structured logging standards."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
            "process": record.process,
        }

        # Attach request_id if available in context
        req_id = request_id_ctx.get()
        if req_id:
            log_entry["request_id"] = req_id

        # Attach exception details if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


class StandardColoredFormatter(logging.Formatter):
    """Clean standard formatter with request correlation tags."""

    def format(self, record: logging.LogRecord) -> str:
        req_id = request_id_ctx.get() or "sys"
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        record.asctime = timestamp
        prefix = f"[{timestamp}] [{record.levelname:<7}] [{req_id}] [{record.name}]:"
        message = record.getMessage()

        if record.exc_info:
            exc_text = self.formatException(record.exc_info)
            return f"{prefix} {message}\n{exc_text}"
        return f"{prefix} {message}"


def setup_logging(log_level: str = "INFO", log_format: str = "structured") -> None:
    """Configures application-wide root logger with appropriate formatter and level."""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove existing handlers to avoid duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(numeric_level)

    if log_format.lower() == "structured":
        stream_handler.setFormatter(StructuredJsonFormatter())
    else:
        stream_handler.setFormatter(StandardColoredFormatter())

    root_logger.addHandler(stream_handler)

    # Reduce noise from 3rd party libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Returns a module-specific logger instance."""
    return logging.getLogger(name)


def sanitize_data(data: dict) -> dict:
    """Recursively redacts sensitive keys from dictionaries before logging."""
    sanitized = {}
    for k, v in data.items():
        if any(sensitive in k.lower() for sensitive in REDACTED_KEYS):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_data(v)
        elif isinstance(v, list):
            sanitized[k] = [sanitize_data(i) if isinstance(i, dict) else i for i in v]
        else:
            sanitized[k] = v
    return sanitized
