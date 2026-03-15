"""
logging_config.py
Centralised logging setup for IAM Defender.

Call setup_logging() once at the application entry point (app.py or main.py).
All modules that use logging.getLogger(__name__) will inherit this config.
"""

import logging
import os
import sys


def setup_logging(level: str = None) -> None:
    """
    Configure the root logger.

    Level is read from the IAM_LOG_LEVEL environment variable if not provided.
    Defaults to INFO.

    Format:
        2024-01-15 12:34:56,789 [INFO ] app: Analysing 42 principals
    """
    level_str  = (level or os.environ.get("IAM_LOG_LEVEL", "INFO")).upper()
    log_level  = getattr(logging, level_str, logging.INFO)

    fmt = "%(asctime)s [%(levelname)-5s] %(name)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))

    root = logging.getLogger()
    root.setLevel(log_level)
    # Avoid adding duplicate handlers if called more than once
    if not root.handlers:
        root.addHandler(handler)

    # Silence noisy third-party loggers (keep werkzeug at INFO so Flask prints the URL)
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
