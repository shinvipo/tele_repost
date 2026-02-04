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
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return {str(k): int(v) for k, v in data.items()}
    except Exception:
        return {}


def save_state(path: str, st: Dict[str, int]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def update_last_id(chat_id_key: str, msg_id: int) -> None:
    app.state[chat_id_key] = int(msg_id)
    save_state(app.options.state_file, app.state)
