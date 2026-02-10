import logging
import builtins
from logging.handlers import RotatingFileHandler

LOG_FORMAT = "%(asctime)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(log_file: str, max_bytes: int = 5 * 1024 * 1024, backup_count: int = 3):
    import os
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger("cti")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return

    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    file_handler = RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console handler removed — logs only go to file
    # To debug, add: logger.addHandler(logging.StreamHandler())

    _original_print = builtins.print

    def patched_print(*args, **kwargs):
        msg = " ".join(str(a) for a in args)
        if msg.strip():
            logger.info(msg)

    builtins.print = patched_print
