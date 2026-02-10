"""Message utility functions — pure Python, no Telethon.

Extracted from filters.py to be shared across features (repost, admin).
"""

from typing import List, Optional

from .normalize import normalize_channel_id


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
    """Extract sender ID from a Telethon message without importing telethon.utils.

    Handles PeerUser, PeerChannel, PeerChat, and direct sender attributes.
    """
    sid = getattr(msg, "sender_id", None)
    if sid:
        sid = int(sid)
        if str(sid).startswith("-100"):
            sid = normalize_channel_id(sid)
        return sid

    from_id = getattr(msg, "from_id", None)
    if from_id:
        # Extract ID from Peer object without telethon.utils.get_peer_id
        uid = getattr(from_id, "user_id", None)
        if uid:
            return int(uid)
        cid = getattr(from_id, "channel_id", None)
        if cid:
            return int(cid)  # raw channel_id, no -100 prefix
        gid = getattr(from_id, "chat_id", None)
        if gid:
            return -int(gid)  # negative to match Telethon convention

    sender = getattr(msg, "sender", None)
    if sender and getattr(sender, "id", None):
        sid = int(sender.id)
        if str(sid).startswith("-100"):
            sid = normalize_channel_id(sid)
        return sid

    return None
