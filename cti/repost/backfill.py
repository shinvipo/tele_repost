"""Backfill and catch-up logic — fill gaps in message history."""

import asyncio
from typing import Any, List, Optional

from ..core.constants import BACKFILL_LIMIT
from ..infra.client import get_peer_id
from ..state import app, get_client, update_last_id
from .filters import should_repost_message
from .routing import filter_dests_for_message
from .service import repost_message


async def collect_recent_messages(entity, limit: int) -> List[Any]:
    client = get_client()
    messages: List[Any] = []
    async for msg in client.iter_messages(entity, limit=limit, reverse=False):
        if msg is not None:
            messages.append(msg)
    return messages


def _get_source_lock(src_key: str) -> asyncio.Lock:
    lock = app.source_locks.get(src_key)
    if lock is None:
        lock = asyncio.Lock()
        app.source_locks[src_key] = lock
    return lock


async def backfill_missing_state() -> None:
    for src_key, src_ent in app.source_entities.items():
        if src_key in app.state:
            continue

        dests = app.route_map.get(src_key, [])
        if not dests:
            continue

        name = app.source_name_map.get(src_key, src_key)
        print(f"[BACKFILL] source={name} id={src_key} limit={BACKFILL_LIMIT}")

        sent = 0
        chat_id = get_peer_id(src_ent)

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
        await update_last_id(src_key, new_last)
        print(f"[BACKFILL] done source={name} seen={seen} sent={sent} last_id={new_last}")

async def catch_up_source_from_state(
    src_key: str,
    src_ent: Optional[Any] = None,
    reason: str = "",
) -> Optional[bool]:
    client = get_client()
    source_ent = src_ent or app.source_entities.get(src_key)
    if source_ent is None:
        print(f"[CATCHUP] skip source id={src_key} reason=source_not_found")
        return None

    dests = app.route_map.get(src_key, [])
    if not dests:
        return None

    lock = _get_source_lock(src_key)
    if lock.locked():
        print(f"[CATCHUP] skip source id={src_key} reason={reason or 'busy'} (already_running)")
        return None

    async with lock:
        last_id = int(app.state.get(src_key, 0))
        if last_id <= 0:
            return None

        name = app.source_name_map.get(src_key, src_key)
        reason_suffix = f" reason={reason}" if reason else ""
        print(f"[CATCHUP] source={name} id={src_key} from_id={last_id}{reason_suffix}")
        try:
            chat_id = get_peer_id(source_ent)
            max_id = last_id
            seen = 0
            sent = 0

            async for msg in client.iter_messages(source_ent, min_id=last_id, reverse=True):
                if msg is None:
                    continue
                if msg.id and msg.id > max_id:
                    max_id = msg.id
                if msg.id <= last_id:
                    continue

                seen += 1

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

            if max_id > last_id:
                await update_last_id(src_key, max_id)
            print(f"[CATCHUP] done source={name} seen={seen} sent={sent} last_id={max_id}")
            return True
        except Exception as e:
            print(f"[CATCHUP] fail source={name} id={src_key} reason={e}")
            return False


async def catch_up_from_state():
    total_sources = 0
    succeeded_sources = 0
    failed_sources = 0
    skipped_sources = 0

    for src_key, src_ent in app.source_entities.items():
        last_id = int(app.state.get(src_key, 0))
        if last_id <= 0:
            continue

        dests = app.route_map.get(src_key, [])
        if not dests:
            continue

        total_sources += 1
        result = await catch_up_source_from_state(src_key, src_ent)
        if result is True:
            succeeded_sources += 1
        elif result is False:
            failed_sources += 1
        else:
            skipped_sources += 1

    print(
        f"[CATCHUP] summary eligible_sources={total_sources} "
        f"succeeded={succeeded_sources} failed={failed_sources} skipped={skipped_sources}"
    )
