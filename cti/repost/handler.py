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
            f"[REPOST] [GAP] chat_id={event.chat_id} source_key={source_key} "
            f"last_id={last_id} incoming_id={msg.id} gap={gap} threshold={gap_threshold}"
        )
        await catch_up_source_from_state(source_key, reason=f"gap_detected gap={gap}")
        last_id = int(app.state.get(source_key, 0))

    if msg.id <= last_id:
        return

    # 1. Check if allowed source/route
    dests = get_route_dests(msg)
    if not dests:
        # print(f"[REPOST] [SKIP] chat_id={event.chat_id} msg_id={msg.id} (no route)") # noisy
        return

    # 2. Check if allowed sender (for that specific route) -> handled inside routing or here?
    # Actually routing returns dests, but we might filter by sender if specified in route.
    # The current routing logic includes basic sender filtering if `allowed_senders` defined.
    # But let's verify if `should_repost_message` filters globally too.
    if not should_repost_message(msg, app.options):
        print(f"[REPOST] [SKIP] chat_id={event.chat_id} msg_id={msg.id} (sender filter)")
        return

    # 3. Process
    try:
        # Repost
        sent_messages = await repost_message(msg, dests, event.client) # Assuming event.client is the client
        if sent_messages:
            if app.options.progress_log:
                print(f"[REPOST] [OK] chat_id={event.chat_id} msg_id={msg.id}")
            # Update state
            src_key = str(event.chat_id) # Using event.chat_id directly as source_key is already normalized
            await update_last_id(src_key, msg.id)
        else:
            # Filtered by keyword or album incomplete
            if app.options.progress_log:
               # If it was returned empty but not error, usually filtered
                print(f"[REPOST] [SKIP] chat_id={event.chat_id} msg_id={msg.id} (keyword filter)")

    except Exception as e:
        print(f"[REPOST] [ERR] chat_id={event.chat_id} msg_id={msg.id} -> {e}")
        import traceback
        traceback.print_exc()
