"""Input normalization utilities — pure Python, no Telethon."""

from typing import Any, List, Optional, Union

TargetType = Union[str, int]


def normalize_channel_id(raw_id: int) -> int:
    s = str(raw_id)
    if s.startswith("-100"):
        return int(s[4:])
    if s.startswith("100"):
        return int(s[3:])
    return raw_id


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
    try:
        val = int(raw)
        return val if val > 0 else None
    except (ValueError, TypeError):
        return None


def parse_chat_ids(raw: Any) -> List[int]:
    if raw is None:
        return []
    if isinstance(raw, int):
        return [raw]
    if isinstance(raw, str):
        raw = raw.strip()
        if raw.lstrip("-").isdigit():
            return [int(raw)]
        return []
    if isinstance(raw, list):
        result: List[int] = []
        for item in raw:
            try:
                result.append(int(item))
            except (ValueError, TypeError):
                pass
        return result
    return []


def normalize_keywords(raw: Any) -> List[str]:
    if not raw:
        return []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    result: List[str] = []
    for item in raw:
        s = str(item).strip().lower()
        if s and s not in result:
            result.append(s)
    return result


def normalize_sender_ids(raw: Any) -> List[int]:
    if not raw:
        return []
    if isinstance(raw, (int, float)):
        return [int(raw)]
    if isinstance(raw, str):
        raw = raw.strip()
        if raw.lstrip("-").isdigit():
            return [int(raw)]
        return []
    if isinstance(raw, list):
        result: List[int] = []
        for item in raw:
            try:
                val = int(item)
                if val not in result:
                    result.append(val)
            except (ValueError, TypeError):
                pass
        return result
    return []


def normalize_non_negative_int(raw: Any, default: int = 0, field_name: str = "") -> int:
    if raw is None:
        return default
    try:
        val = int(raw)
        return max(0, val)
    except (ValueError, TypeError):
        if field_name:
            print(f"[WARN] Invalid {field_name}={raw}, using default={default}")
        return default


def normalize_optional_int(raw: Any) -> Optional[int]:
    if raw is None:
        return None
    try:
        return int(raw)
    except (ValueError, TypeError):
        return None
