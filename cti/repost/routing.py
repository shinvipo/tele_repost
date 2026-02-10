"""Route lookup — find destinations for a source chat."""

from typing import List

from ..core.models import ResolvedDest
from ..core.normalize import normalize_channel_id
from ..state import app
from .filters import sender_allowed


def get_route_dests(chat_id: int) -> List[ResolvedDest]:
    chat_id_key = str(chat_id)
    dests = app.route_map.get(chat_id_key, [])
    if not dests and str(chat_id).startswith("-100"):
        alt_key = str(normalize_channel_id(chat_id))
        dests = app.route_map.get(alt_key, [])
    return dests


def filter_dests_for_message(msg, dests: List[ResolvedDest]) -> List[ResolvedDest]:
    filtered: List[ResolvedDest] = []
    for d in dests:
        allowed = d.allowed_senders if d.allowed_senders else app.options.allowed_senders
        if sender_allowed(msg, allowed):
            filtered.append(d)
    return filtered
