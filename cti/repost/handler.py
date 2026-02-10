"""Repost message handler — thin event handler, delegates to service.

Handler only: receives event → extracts data → calls service → updates state.
"""

from ..core.normalize import normalize_channel_id
from ..state import app, update_last_id
from .backfill import catch_up_source_from_state
from .filters import should_repost_message
from .routing import filter_dests_for_message, get_route_dests
from .service import repost_message


def _source_key_for_chat(chat_id: int) -> str:
    key = str(chat_id)
    if key in app.source_entities:
        return key
    if key.startswith("-100"):
        alt_key = str(normalize_channel_id(chat_id))
        if alt_key in app.source_entities:
            return alt_key
    return key


async def on_new_message(event):
    source_key = _source_key_for_chat(event.chat_id)
    msg = event.message

    last_id = int(app.state.get(source_key, 0))
    gap_threshold = int(getattr(app.options, "gap_trigger_threshold", 1))
    if gap_threshold > 0 and last_id > 0 and msg.id > (last_id + gap_threshold):
        gap = msg.id - last_id
        print(
            f"[GAP] chat_id={event.chat_id} source_key={source_key} "
            f"last_id={last_id} incoming_id={msg.id} gap={gap} threshold={gap_threshold}"
        )
        await catch_up_source_from_state(source_key, reason=f"gap_detected gap={gap}")
        last_id = int(app.state.get(source_key, 0))

    if msg.id <= last_id:
        return

    dests = get_route_dests(event.chat_id)
    if not dests:
        await update_last_id(source_key, msg.id)
        if app.options.progress_log:
            print(f"[SKIP] chat_id={event.chat_id} msg_id={msg.id} (no route)")
        return

    filtered_dests = filter_dests_for_message(msg, dests)
    if not filtered_dests:
        await update_last_id(source_key, msg.id)
        if app.options.progress_log:
            print(f"[SKIP] chat_id={event.chat_id} msg_id={msg.id} (sender filter)")
        return

    matched = should_repost_message(msg)

    try:
        await repost_message(event.chat_id, msg, filtered_dests, matched)
        await update_last_id(source_key, msg.id)

        if app.options.progress_log:
            if matched:
                print(f"[OK] chat_id={event.chat_id} msg_id={msg.id}")
            else:
                grouped_id = getattr(msg, "grouped_id", None)
                if not grouped_id:
                    print(f"[SKIP] chat_id={event.chat_id} msg_id={msg.id} (keyword filter)")

    except Exception as e:
        print(f"[ERR] chat_id={event.chat_id} msg_id={msg.id} -> {e}")
