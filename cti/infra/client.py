"""Telethon infrastructure layer — entity resolution, send helpers, retry logic.

This is the ONLY place outside of main.py that should import Telethon directly.
"""

import asyncio
from typing import Any, List, Optional

from telethon import utils
from telethon.errors import FloodWaitError, RPCError
from telethon.errors.rpcerrorlist import SlowModeWaitError
from telethon.tl.types import PeerUser

from ..core.models import ResolvedDest, TargetType
from ..core.normalize import normalize_channel_id
from ..state import app, get_client


def get_peer_id(entity) -> int:
    """Extract peer ID from a Telethon entity."""
    return utils.get_peer_id(entity)


async def resolve_target(target: TargetType):
    """
    Resolve target into InputPeer.
    Supports:
      - "@username"
      - "https://t.me/xxx"
      - group/channel -100...
      - user_id (requires access_hash -> must exist in dialogs/contacts/cache)
    """
    client = get_client()

    key = str(target)
    if key in app.entity_cache:
        return app.entity_cache[key]

    if isinstance(target, str):
        t = target.strip()
        if t.startswith("@") or "t.me/" in t:
            ent = await client.get_input_entity(t)
            app.entity_cache[key] = ent
            return ent

        if t.lstrip("-").isdigit():
            target = int(t)
        else:
            ent = await client.get_input_entity(t)
            app.entity_cache[key] = ent
            return ent

    if isinstance(target, int):
        if str(target).startswith("-100"):
            try:
                ent = await client.get_input_entity(target)
                app.entity_cache[key] = ent
                return ent
            except Exception:
                ent = await resolve_from_dialogs(client, target)
                if ent is not None:
                    app.entity_cache[key] = ent
                    return ent
                raise

        try:
            ent = await client.get_input_entity(PeerUser(target))
            app.entity_cache[key] = ent
            return ent
        except Exception:
            async for d in client.iter_dialogs():
                if getattr(d.entity, "id", None) == target:
                    app.entity_cache[key] = d.input_entity
                    return d.input_entity
            raise RuntimeError(
                f"Cannot resolve user_id={target}. Use @username OR chat that user once OR add to contacts."
            )

    ent = await client.get_input_entity(target)
    app.entity_cache[key] = ent
    return ent


async def resolve_from_dialogs(client, group_peer_id: int):
    target_id = normalize_channel_id(group_peer_id)
    async for dialog in client.iter_dialogs():
        ent = dialog.entity
        if getattr(ent, "id", None) == target_id:
            return ent
    return None


async def resolve_entity_with_fallback(target: TargetType):
    client = get_client()
    try:
        return await client.get_entity(target)
    except Exception:
        if isinstance(target, int):
            target_int = target
        elif isinstance(target, str) and target.lstrip("-").isdigit():
            target_int = int(target)
        else:
            raise

        ent = await resolve_from_dialogs(client, target_int)
        if ent is None:
            raise
        return ent


def build_reply_to(topic_id: Optional[int]):
    if not topic_id:
        return None
    return int(topic_id)


async def send_text_to_dests(dests: List[ResolvedDest], text: str):
    client = get_client()
    for d in dests:
        reply_to = build_reply_to(d.topic_id)
        await send_with_retry(
            d.raw_dest,
            lambda r=reply_to, ent=d.dest_ent: client.send_message(ent, text, reply_to=r),
        )


async def send_file_to_dests(dests: List[ResolvedDest], file_path: str, caption: str):
    client = get_client()
    for d in dests:
        reply_to = build_reply_to(d.topic_id)
        await send_with_retry(
            d.raw_dest,
            lambda r=reply_to, ent=d.dest_ent: client.send_file(ent, file_path, caption=caption, reply_to=r),
        )


async def send_album_to_dests(dests: List[ResolvedDest], file_paths: List[str], caption: str):
    client = get_client()
    for d in dests:
        reply_to = build_reply_to(d.topic_id)
        await send_with_retry(
            d.raw_dest,
            lambda r=reply_to, ent=d.dest_ent: client.send_file(ent, file_paths, caption=caption, reply_to=r),
        )


async def send_with_retry(raw_dest, send_coro_factory):
    options = app.options
    for attempt in range(options.max_send_retries + 1):
        try:
            await send_coro_factory()
            return
        except FloodWaitError as e:
            wait_s = int(e.seconds) + 1
            print(f"[RATE LIMIT] FloodWait {wait_s}s for DEST={raw_dest}")
            await asyncio.sleep(wait_s)
        except SlowModeWaitError as e:
            wait_s = int(getattr(e, "seconds", 0)) + 1
            print(f"[RATE LIMIT] SlowMode {wait_s}s for DEST={raw_dest}")
            await asyncio.sleep(max(1, wait_s))
        except RPCError as e:
            msg = str(e).lower()
            if "too many requests" in msg:
                wait_s = options.retry_base_seconds * (2 ** attempt)
                print(f"[RATE LIMIT] Too many requests; backoff {wait_s:.1f}s for DEST={raw_dest}")
                await asyncio.sleep(wait_s)
                continue
            if options.progress_log:
                print(f"[WARN] send failed to DEST={raw_dest}: {e}")
            return
        except Exception as e:
            if options.progress_log:
                print(f"[WARN] send failed to DEST={raw_dest}: {e}")
            return
