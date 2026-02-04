from typing import Any, List, Optional

from .models import TargetType


def normalize_channel_id(peer_id: int) -> int:
    s = str(peer_id)
    if s.startswith("-100"):
        return int(s[4:])
    return int(peer_id)


def parse_target(raw: Any) -> TargetType:
    if raw is None:
        raise ValueError("Empty target")

    s = str(raw).strip()
    if not s:
        raise ValueError("Empty target")

    if s.startswith("@") or "t.me/" in s:
        return s

    if s.lstrip("-").isdigit():
        return int(s)

    return s


def parse_topic_id(raw: Any) -> Optional[int]:
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw if raw > 0 else None
    s = str(raw).strip()
    if not s:
        return None
    if s.isdigit():
        v = int(s)
        return v if v > 0 else None
    raise ValueError("topic_id must be a positive integer")


def parse_chat_ids(raw: Any) -> List[int]:
    if raw is None:
        return []
    if isinstance(raw, (int, str)):
        raw_list = [raw]
    elif isinstance(raw, list):
        raw_list = raw
    else:
        return []

    out: List[int] = []
    for item in raw_list:
        s = str(item).strip()
        if not s:
            continue
        if s.lstrip("-").isdigit():
            v = int(s)
            if str(v).startswith("-100"):
                v = normalize_channel_id(v)
            out.append(v)
        else:
            raise ValueError("admin_chat_ids must be numeric ids")

    seen = set()
    uniq: List[int] = []
    for v in out:
        if v in seen:
            continue
        seen.add(v)
        uniq.append(v)
    return uniq


def normalize_keywords(raw: Any) -> List[str]:
    if not raw:
        return []
    if isinstance(raw, str):
        raw_list = [raw]
    elif isinstance(raw, list):
        raw_list = raw
    else:
        return []

    out: List[str] = []
    for item in raw_list:
        s = str(item).strip()
        if s:
            out.append(s.lower())
    return out


def normalize_sender_ids(raw: Any) -> List[int]:
    if not raw:
        return []
    if isinstance(raw, (int, str)):
        raw_list = [raw]
    elif isinstance(raw, list):
        raw_list = raw
    else:
        return []

    out: List[int] = []
    for item in raw_list:
        s = str(item).strip()
        if not s:
            continue
        if s.lstrip("-").isdigit():
            v = int(s)
            if str(v).startswith("-100"):
                v = normalize_channel_id(v)
            out.append(v)

    seen = set()
    uniq: List[int] = []
    for v in out:
        if v in seen:
            continue
        seen.add(v)
        uniq.append(v)
    return uniq
