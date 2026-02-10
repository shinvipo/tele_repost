"""Repost filters — keyword matching and sender filtering.

No Telethon imports. Uses core/message.py for message text extraction.
"""

from typing import List

from ..core.message import extract_search_text, get_sender_id
from ..state import app


def sender_allowed(msg, allowed_senders: List[int]) -> bool:
    if not allowed_senders:
        return True
    sender_id = get_sender_id(msg)
    return sender_id is not None and sender_id in allowed_senders


def should_repost_message(msg) -> bool:
    keywords = app.options.keywords
    if not keywords:
        return True

    text = extract_search_text(msg)
    if not text:
        return False

    lower_text = text.lower()
    return any(k in lower_text for k in keywords)
