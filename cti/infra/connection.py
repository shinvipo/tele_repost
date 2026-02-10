"""Connection watcher — detect disconnect/reconnect and trigger catchup."""

import asyncio
import time
from typing import Optional

from ..state import app, get_client


POLL_INTERVAL_SECONDS = 2


def _should_catchup(min_offline_minutes: Optional[int], offline_seconds: float) -> bool:
    if min_offline_minutes is None:
        return True
    if min_offline_minutes <= 0:
        return True
    return offline_seconds >= (min_offline_minutes * 60)


async def _run_catchup(reason: str) -> bool:
    from ..repost.backfill import catch_up_from_state

    if app.catchup_lock.locked():
        print(f"[INFO] Catch-up skipped ({reason}, already running)")
        return False

    try:
        print(f"[INFO] Catch-up triggered ({reason})")
        async with app.catchup_lock:
            await catch_up_from_state()
        print(f"[INFO] Catch-up finished ({reason})")
        return True
    except Exception as e:
        print(f"[WARN] Catch-up failed ({reason}): {e}")
        return False


async def watch_connection():
    client = get_client()
    was_connected = client.is_connected()
    last_disconnect = None

    while True:
        try:
            connected = client.is_connected()
        except Exception:
            connected = False
        now = time.time()

        if connected and not was_connected:
            if last_disconnect is not None:
                offline_seconds = now - last_disconnect
                min_offline = app.options.catchup_min_offline_minutes
                print(
                    f"[INFO] Reconnected after {offline_seconds:.1f}s (min_offline_minutes={min_offline})"
                )
                if _should_catchup(min_offline, offline_seconds):
                    await _run_catchup("reconnect")
                else:
                    print("[INFO] Catch-up skipped (offline too short)")
            last_disconnect = None
        elif not connected and was_connected:
            last_disconnect = now
            print("[WARN] Disconnected from Telegram")

        was_connected = connected
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
