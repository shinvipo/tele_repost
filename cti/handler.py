import asyncio

from telethon.errors import FloodWaitError

from .filters import should_repost_message
from .repost import repost_message
from .routing import filter_dests_for_message, get_route_dests
from .state import app, update_last_id


async def on_new_message(event):
    chat_id_key = str(event.chat_id)
    msg = event.message

    last_id = int(app.state.get(chat_id_key, 0))
    if msg.id <= last_id:
        return

    dests = get_route_dests(event.chat_id)
    if not dests:
        await update_last_id(chat_id_key, msg.id)
        if app.options.progress_log:
            print(f"[SKIP] chat_id={event.chat_id} msg_id={msg.id} (no route)")
        return

    filtered_dests = filter_dests_for_message(msg, dests)
    if not filtered_dests:
        await update_last_id(chat_id_key, msg.id)
        if app.options.progress_log:
            print(f"[SKIP] chat_id={event.chat_id} msg_id={msg.id} (sender filter)")
        return

    matched = should_repost_message(msg)

    try:
        await repost_message(event.chat_id, msg, filtered_dests, matched)

        await update_last_id(chat_id_key, msg.id)

        if app.options.progress_log:
            if matched:
                print(f"[OK] chat_id={event.chat_id} msg_id={msg.id}")
            else:
                grouped_id = getattr(msg, "grouped_id", None)
                if not grouped_id:
                    print(f"[SKIP] chat_id={event.chat_id} msg_id={msg.id} (keyword filter)")

    except FloodWaitError as e:
        print(f"[RATE LIMIT] FloodWait {e.seconds}s")
        await asyncio.sleep(e.seconds + 1)
    except Exception as e:
        print(f"[ERR] chat_id={event.chat_id} msg_id={msg.id} -> {e}")


async def on_admin_message(event):
    from .admin import handle_admin_command

    await handle_admin_command(event)
