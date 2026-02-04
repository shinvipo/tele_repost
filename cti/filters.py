from typing import List, Optional

from telethon import utils

from .normalize import normalize_channel_id
from .state import app


def safe_text(msg) -> str:
    return (msg.message or "").strip()


def extract_search_text(msg) -> str:
    parts: List[str] = []
    text = safe_text(msg)
    if text:
        parts.append(text)

    file_obj = getattr(msg, "file", None)
    file_name = getattr(file_obj, "name", None) if file_obj else None
    if file_name:
        parts.append(str(file_name))

    return " ".join(parts).strip()


def get_sender_id(msg) -> Optional[int]:
    sid = getattr(msg, "sender_id", None)
    if sid:
        sid = int(sid)
        if str(sid).startswith("-100"):
            sid = normalize_channel_id(sid)
        return sid

    from_id = getattr(msg, "from_id", None)
    if from_id:
        try:
            sid = int(utils.get_peer_id(from_id))
            if str(sid).startswith("-100"):
                sid = normalize_channel_id(sid)
            return sid
        except Exception:
            pass

    sender = getattr(msg, "sender", None)
    if sender and getattr(sender, "id", None):
        sid = int(sender.id)
        if str(sid).startswith("-100"):
            sid = normalize_channel_id(sid)
        return sid

    return None


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
