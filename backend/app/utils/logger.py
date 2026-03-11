"""
Structured logging configuration.
- Development: coloured human-readable output
- Production: JSON lines for log aggregation (Loki / CloudWatch / etc.)
"""
import logging
import sys
import json
from datetime import datetime, timezone
from app.utils.config import settings


class JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON for structured log ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra"):
            log_entry.update(record.extra)
        return json.dumps(log_entry)


class ColorFormatter(logging.Formatter):
    """ANSI-coloured formatter for development console output."""

    GREY = "\x1b[38;5;246m"
    CYAN = "\x1b[36m"
    YELLOW = "\x1b[33m"
    RED = "\x1b[31m"
    BOLD_RED = "\x1b[31;1m"
    RESET = "\x1b[0m"

    LEVEL_COLORS = {
        logging.DEBUG: GREY,
        logging.INFO: CYAN,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: BOLD_RED,
    }

    FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(message)s"
    DATE_FORMAT = "%H:%M:%S"

    def format(self, record: logging.LogRecord) -> str:
        color = self.LEVEL_COLORS.get(record.levelno, self.RESET)
        formatter = logging.Formatter(
            f"{color}{self.FORMAT}{self.RESET}",
            datefmt=self.DATE_FORMAT,
        )
        return formatter.format(record)


def get_logger(name: str) -> logging.Logger:
    """
    Return a configured logger instance.

    Usage:
        from app.utils.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Starting scan", extra={"repo_id": repo_id})
    """
    logger = logging.getLogger(name)

    if logger.handlers:  # Avoid adding duplicate handlers
        return logger

    logger.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)

    if settings.APP_ENV == "production":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(ColorFormatter())

    logger.addHandler(handler)
    logger.propagate = False
    return logger


# Root application logger
log = get_logger("ark")
