import builtins
import logging
import os
import sys

_DEFAULT_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"


def _level_for_message(message: str) -> int:
    msg = message.lstrip()
    if msg.startswith("[ERR]") or msg.startswith("[ERROR]"):
        return logging.ERROR
    if msg.startswith("[WARN]") or msg.startswith("[WARNING]"):
        return logging.WARNING
    if msg.startswith("[RATE LIMIT]"):
        return logging.WARNING
    return logging.INFO


def _patch_print(logger: logging.Logger) -> None:
    def _print(*args, **kwargs):
        sep = kwargs.get("sep", " ")
        msg = sep.join(str(a) for a in args)
        msg = msg.rstrip("\n")
        if not msg:
            return
        level = _level_for_message(msg)
        for line in msg.splitlines():
            logger.log(level, line)

    builtins.print = _print


def setup_logging(log_path: str, console: bool = False) -> logging.Logger:
    log_dir = os.path.dirname(log_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("cti")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter = logging.Formatter(_DEFAULT_FORMAT)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    if console:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    _patch_print(logger)
    return logger
