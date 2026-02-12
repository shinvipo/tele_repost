from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

if TYPE_CHECKING:
    from telethon import TelegramClient

TargetType = Union[str, int]


@dataclass
class TelegramConfig:
    api_id: int
    api_hash: str
    session: str


@dataclass
class RouteConfig:
    source: TargetType
    dest: TargetType
    topic_id: Optional[int] = None
    allowed_senders: List[int] = field(default_factory=list)


@dataclass
class MonitorConfig:
    sources: List[TargetType]
    dests: List[TargetType]
    routes: List[RouteConfig] = field(default_factory=list)


@dataclass
class OptionsConfig:
    download_media: bool = True
    album_wait_seconds: float = 1.2
    progress_log: bool = True
    reload_interval_seconds: float = 2.0
    state_file: str = "data/state_last_ids.json"
    keywords: List[str] = field(default_factory=list)
    allowed_senders: List[int] = field(default_factory=list)
    admin_chat_ids: List[int] = field(default_factory=list)
    admin_senders: List[int] = field(default_factory=list)
    gap_trigger_threshold: int = 1
    catchup_min_offline_minutes: Optional[int] = None
    max_send_retries: int = 3
    retry_base_seconds: float = 1.5


@dataclass
class CveMonitorConfig:
    enabled: bool = False
    interval_seconds: int = 300
    dest: Union[str, int] = 0
    topic_id: Optional[int] = None
    keywords: List[str] = field(default_factory=list)
    include_updates: bool = True
    kev_enabled: bool = True
    kev_cache_file: str = "data/cve_kev_cache.json"
    kev_cache_ttl_hours: int = 24
    min_cvss: float = 0.0


@dataclass
class AppConfig:
    telegram: TelegramConfig
    monitor: MonitorConfig
    options: OptionsConfig
    cve_monitor: Optional[CveMonitorConfig] = None


@dataclass
class ResolvedDest:
    raw_dest: TargetType
    dest_ent: Any
    topic_id: Optional[int] = None
    allowed_senders: List[int] = field(default_factory=list)


@dataclass
class RuntimeState:
    client: Optional[TelegramClient] = None
    entity_cache: Dict[str, Any] = field(default_factory=dict)
    route_map: Dict[str, List[ResolvedDest]] = field(default_factory=dict)
    source_entities: Dict[str, Any] = field(default_factory=dict)
    source_name_map: Dict[str, str] = field(default_factory=dict)
    state: Dict[str, int] = field(default_factory=dict)
    cve_state: Dict[str, Any] = field(default_factory=lambda: {"last_fetch_time": None, "processed_cves": []})
    options: OptionsConfig = field(default_factory=OptionsConfig)
    album_buffer: Dict[str, Dict[int, List[Any]]] = field(default_factory=dict)
    album_match: Dict[str, Dict[int, bool]] = field(default_factory=dict)
    album_tasks: Dict[str, Dict[int, asyncio.Task]] = field(default_factory=dict)
    active_handler_fn: Optional[Any] = None
    active_handler_event: Optional[Any] = None
    active_admin_handler_fn: Optional[Any] = None
    active_admin_handler_event: Optional[Any] = None
    source_locks: Dict[str, asyncio.Lock] = field(default_factory=dict)
    catchup_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    state_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
