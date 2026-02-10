import asyncio
import json
import os
from typing import Any, Dict

from .models import RuntimeState

app = RuntimeState()


def get_client():
    if app.client is None:
        raise RuntimeError("Telegram client not initialized")
    return app.client


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_state(path: str) -> Dict[str, int]:
    """Load repost state from unified state file.

    Handles both legacy flat format and new unified format.
    """
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # New unified format: { "repost": {...}, "cve_monitor": {...} }
        if "repost" in data:
            return {str(k): int(v) for k, v in data["repost"].items()}
        # Legacy flat format: { "chat_key": msg_id, ... }
        if data and all(isinstance(v, (int, float)) for v in data.values()):
            return {str(k): int(v) for k, v in data.items()}
        return {}
    except Exception:
        return {}


def load_cve_state(path: str) -> Dict[str, Any]:
    """Load CVE monitor state from unified state file."""
    if not os.path.exists(path):
        return {"last_fetch_time": None, "processed_cves": []}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("cve_monitor", {"last_fetch_time": None, "processed_cves": []})
    except Exception:
        return {"last_fetch_time": None, "processed_cves": []}


async def _write_unified_state(path: str) -> None:
    """Write unified state file containing both repost and CVE monitor state."""
    unified = {
        "repost": app.state,
        "cve_monitor": app.cve_state,
    }
    tmp = path + ".tmp"
    for attempt in range(5):
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(unified, f, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
            return
        except PermissionError:
            # Windows file lock or antivirus scan; retry a few times
            await asyncio.sleep(0.2 * (attempt + 1))
        finally:
            if os.path.exists(tmp) and attempt == 4:
                try:
                    os.remove(tmp)
                except Exception:
                    pass


async def save_state(path: str, st: Dict[str, int]) -> None:
    """Save unified state (backward-compatible signature)."""
    await _write_unified_state(path)


async def update_last_id(chat_id_key: str, msg_id: int) -> None:
    async with app.state_lock:
        app.state[chat_id_key] = int(msg_id)
        await _write_unified_state(app.options.state_file)


async def update_cve_state() -> None:
    """Save state after CVE monitor state has been modified."""
    async with app.state_lock:
        await _write_unified_state(app.options.state_file)
