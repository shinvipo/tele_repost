from typing import Any, List

from telethon import utils

from .constants import BACKFILL_LIMIT
from .filters import should_repost_message
from .repost import repost_message
from .routing import filter_dests_for_message
from .state import app, get_client, update_last_id


async def collect_recent_messages(entity, limit: int) -> List[Any]:
    client = get_client()
    messages: List[Any] = []
    async for msg in client.iter_messages(entity, limit=limit, reverse=False):
        if msg is not None:
            messages.append(msg)
    return messages


async def backfill_missing_state():
    for src_key, src_ent in app.source_entities.items():
        if src_key in app.state:
            continue

        dests = app.route_map.get(src_key, [])
        if not dests:
            continue

        name = app.source_name_map.get(src_key, src_key)
        print(f"[BACKFILL] source={name} id={src_key} limit={BACKFILL_LIMIT}")

        sent = 0
        chat_id = utils.get_peer_id(src_ent)

        recent_msgs = await collect_recent_messages(src_ent, BACKFILL_LIMIT)
        seen = len(recent_msgs)
        max_id = max((m.id for m in recent_msgs if m and m.id), default=0)

        for msg in reversed(recent_msgs):
            filtered_dests = filter_dests_for_message(msg, dests)
            if not filtered_dests:
                continue

            matched = should_repost_message(msg)
            grouped_id = getattr(msg, "grouped_id", None)
            if not matched and not grouped_id:
                continue

            await repost_message(chat_id, msg, filtered_dests, matched)
            if matched:
                sent += 1

        current = int(app.state.get(src_key, 0))
        new_last = max(current, max_id)
        update_last_id(src_key, new_last)
        print(f"[BACKFILL] done source={name} seen={seen} sent={sent} last_id={new_last}")
