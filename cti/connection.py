import asyncio
import time
from typing import Optional

from .backfill import catch_up_from_state
from .state import app, get_client


def _should_catchup(min_offline_minutes: Optional[int], offline_seconds: float) -> bool:
    if min_offline_minutes is None:
        return True
    if min_offline_minutes <= 0:
        return True
    return offline_seconds >= (min_offline_minutes * 60)


async def watch_connection():
    client = get_client()
    was_connected = client.is_connected()
    last_disconnect = None

    while True:
        try:
            connected = client.is_connected()
        except Exception:
            connected = False

        if connected and not was_connected:
            if last_disconnect is not None:
                offline_seconds = time.time() - last_disconnect
                min_offline = app.options.catchup_min_offline_minutes
                print(
                    f"[INFO] Reconnected after {offline_seconds:.1f}s (min_offline_minutes={min_offline})"
                )
                if _should_catchup(min_offline, offline_seconds):
                    print("[INFO] Catch-up triggered")
                    async with app.catchup_lock:
                        await catch_up_from_state()
                    print("[INFO] Catch-up finished")
                else:
                    print("[INFO] Catch-up skipped (offline too short)")
            last_disconnect = None
        elif not connected and was_connected:
            last_disconnect = time.time()
            print("[WARN] Disconnected from Telegram")

        was_connected = connected
        await asyncio.sleep(2)
