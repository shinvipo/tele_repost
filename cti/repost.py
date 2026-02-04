import asyncio
import tempfile
from typing import List

from .constants import POST_PREFIX
from .filters import safe_text
from .models import ResolvedDest
from .state import app, get_client
from .telegram import send_album_to_dests, send_file_to_dests, send_text_to_dests


async def flush_album_later(chat_id_key: str, grouped_id: int, prefix: str, dests: List[ResolvedDest]):
    options = app.options
    client = get_client()

    await asyncio.sleep(options.album_wait_seconds)

    msgs = app.album_buffer.get(chat_id_key, {}).pop(grouped_id, [])
    matched = app.album_match.get(chat_id_key, {}).pop(grouped_id, False)
    if not msgs:
        return

    if not matched:
        if options.progress_log:
            print(f"[SKIP] chat_id={chat_id_key} grouped_id={grouped_id} (keyword filter)")
        return

    msgs.sort(key=lambda m: m.id)

    if not options.download_media:
        await send_text_to_dests(
            dests,
            f"{prefix}\n\n[ALBUM] Album detected ({len(msgs)} items) but download_media=false.",
        )
        return

    first_caption = safe_text(msgs[0])
    caption = f"{prefix}\n\n{first_caption}" if first_caption else prefix

    with tempfile.TemporaryDirectory() as td:
        file_paths = []
        for m in msgs:
            try:
                p = await client.download_media(m, file=td)
                if p:
                    file_paths.append(p)
            except Exception:
                pass

        if not file_paths:
            await send_text_to_dests(dests, f"{prefix}\n\n[WARN] Could not download album media.")
            return

        await send_album_to_dests(dests, file_paths, caption)


async def repost_message(chat_id: int, msg, dests: List[ResolvedDest], matched: bool):
    client = get_client()
    options = app.options
    chat_id_key = str(chat_id)
    prefix = POST_PREFIX

    grouped_id = getattr(msg, "grouped_id", None)
    if grouped_id:
        app.album_buffer.setdefault(chat_id_key, {}).setdefault(grouped_id, []).append(msg)
        app.album_match.setdefault(chat_id_key, {})
        if matched:
            app.album_match[chat_id_key][grouped_id] = True
        else:
            app.album_match[chat_id_key].setdefault(grouped_id, False)

        app.album_tasks.setdefault(chat_id_key, {})
        old = app.album_tasks[chat_id_key].get(grouped_id)
        if old and not old.done():
            old.cancel()

        app.album_tasks[chat_id_key][grouped_id] = asyncio.create_task(
            flush_album_later(chat_id_key, grouped_id, prefix, dests)
        )
        return

    if msg.media and options.download_media:
        if not matched:
            return
        with tempfile.TemporaryDirectory() as td:
            try:
                p = await client.download_media(msg, file=td)
            except Exception as e:
                await send_text_to_dests(dests, f"{prefix}\n\n[WARN] Could not download media.\nReason: {e}")
                return

            if not p:
                await send_text_to_dests(dests, f"{prefix}\n\n[WARN] Media empty/unsupported.")
                return

            caption_text = safe_text(msg)
            caption = f"{prefix}\n\n{caption_text}" if caption_text else prefix
            await send_file_to_dests(dests, p, caption)
        return

    if not matched:
        return
    text = safe_text(msg) or "(no text / media-only)"
    await send_text_to_dests(dests, f"{prefix}\n\n{text}")
