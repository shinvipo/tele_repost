import json
from typing import List, Optional, Tuple

from .constants import CONFIG_PATH
from .filters import get_sender_id, safe_text
from .normalize import normalize_channel_id, normalize_keywords
from .state import app, get_client, load_json


def _normalize_chat_id(chat_id: Optional[int]) -> Optional[int]:
    if chat_id is None:
        return None
    try:
        chat_id = int(chat_id)
    except Exception:
        return None
    if str(chat_id).startswith("-100"):
        return normalize_channel_id(chat_id)
    return chat_id


def _normalize_chat_ids(chat_ids: List[int]) -> List[int]:
    out: List[int] = []
    for cid in chat_ids:
        norm = _normalize_chat_id(cid)
        if norm is None:
            continue
        out.append(norm)
    seen = set()
    uniq: List[int] = []
    for v in out:
        if v in seen:
            continue
        seen.add(v)
        uniq.append(v)
    return uniq


def _is_admin_message(event) -> bool:
    opts = app.options
    admin_chats = _normalize_chat_ids(opts.admin_chat_ids)
    sender_id = get_sender_id(event.message)

    has_chat = bool(admin_chats)
    has_senders = bool(opts.admin_senders)

    if not has_chat and not has_senders:
        return False

    if has_chat and has_senders:
        chat_id = _normalize_chat_id(event.chat_id)
        return chat_id in admin_chats and sender_id is not None and sender_id in opts.admin_senders

    if has_chat:
        chat_id = _normalize_chat_id(event.chat_id)
        return chat_id in admin_chats

    return sender_id is not None and sender_id in opts.admin_senders


def _parse_keywords_command(text: str) -> Optional[Tuple[str, str]]:
    t = text.strip()
    if not t:
        return None

    lower = t.lower()
    if lower.startswith("/keywords"):
        cmd = t[len("/keywords") :].strip()
    elif lower.startswith("keywords"):
        cmd = t[len("keywords") :].strip()
    else:
        return None

    if not cmd:
        return ("help", "")

    parts = cmd.split(maxsplit=1)
    action = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""
    return (action, args)


def _parse_keywords_list(args: str) -> List[str]:
    if not args:
        return []
    if "," in args:
        raw = [x.strip() for x in args.split(",")]
    else:
        raw = [x.strip() for x in args.split()]
    raw = [x for x in raw if x]
    return normalize_keywords(raw)


def _write_keywords_to_config(new_keywords: List[str]) -> None:
    cfg = load_json(CONFIG_PATH)
    opts = cfg.get("options", {})
    opts["keywords"] = new_keywords
    cfg["options"] = opts
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def _format_keywords(keys: List[str]) -> str:
    if not keys:
        return "(empty)"
    return ", ".join(keys)


def _usage() -> str:
    return (
        "Usage:\n"
        "  /keywords show\n"
        "  /keywords set k1,k2\n"
        "  /keywords add k3 k4\n"
        "  /keywords remove k2\n"
        "  /keywords clear"
    )


async def handle_admin_command(event) -> bool:
    if not _is_admin_message(event):
        return False

    text = safe_text(event.message)
    parsed = _parse_keywords_command(text)
    if not parsed:
        return False

    action, args = parsed
    client = get_client()

    current = list(app.options.keywords)
    if action in {"set", "add", "remove"} and not args.strip():
        await client.send_message(event.chat_id, _usage())
        return True

    if action in {"show", "list"}:
        await client.send_message(event.chat_id, f"[KEYWORDS] {_format_keywords(current)}")
        return True
    if action in {"help", "usage", "?"}:
        await client.send_message(event.chat_id, _usage())
        return True

    if action == "set":
        new_keys = _parse_keywords_list(args)
    elif action == "add":
        to_add = _parse_keywords_list(args)
        new_keys = current[:]
        for k in to_add:
            if k not in new_keys:
                new_keys.append(k)
    elif action == "remove":
        to_remove = set(_parse_keywords_list(args))
        new_keys = [k for k in current if k not in to_remove]
    elif action == "clear":
        new_keys = []
    else:
        await client.send_message(event.chat_id, _usage())
        return True

    _write_keywords_to_config(new_keys)

    from .apply import apply_config
    from .config import parse_config

    cfg = parse_config(load_json(CONFIG_PATH))
    await apply_config(cfg)

    await client.send_message(event.chat_id, f"[KEYWORDS] {_format_keywords(new_keys)}")
    return True
