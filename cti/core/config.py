from typing import Any, Dict, List

from .models import AppConfig, CveMonitorConfig, MonitorConfig, OptionsConfig, RouteConfig, TelegramConfig
from .normalize import (
    normalize_keywords,
    normalize_non_negative_int,
    normalize_optional_int,
    normalize_sender_ids,
    parse_chat_ids,
    parse_target,
    parse_topic_id,
)


def validate_config(cfg: Dict[str, Any]) -> None:
    if "telegram" not in cfg:
        raise ValueError("Missing 'telegram' section")
    if "monitor" not in cfg:
        raise ValueError("Missing 'monitor' section")
    if "api_id" not in cfg["telegram"] or "api_hash" not in cfg["telegram"]:
        raise ValueError("Missing telegram.api_id or telegram.api_hash")

    monitor = cfg.get("monitor", {})
    routes = monitor.get("routes", None)
    if routes is not None:
        if not isinstance(routes, list) or not routes:
            raise ValueError("monitor.routes must be a non-empty array")
        for i, r in enumerate(routes):
            if not isinstance(r, dict):
                raise ValueError(f"monitor.routes[{i}] must be an object")
            if "source" not in r or "dest" not in r:
                raise ValueError(f"monitor.routes[{i}] must have 'source' and 'dest'")
        return

    sources = monitor.get("sources", [])
    dests = monitor.get("dests", [])
    if not isinstance(sources, list) or not sources:
        raise ValueError("monitor.sources must be a non-empty array")
    if not isinstance(dests, list) or not dests:
        raise ValueError("monitor.dests must be a non-empty array")


def parse_config(cfg: Dict[str, Any]) -> AppConfig:
    validate_config(cfg)

    tg = cfg["telegram"]
    telegram = TelegramConfig(
        api_id=int(tg["api_id"]),
        api_hash=str(tg["api_hash"]),
        session=str(tg.get("session", "monitor_session")),
    )

    monitor_raw = cfg["monitor"]
    routes_raw = monitor_raw.get("routes", None)

    routes: List[RouteConfig] = []
    if routes_raw is not None:
        for r in routes_raw:
            source = parse_target(r.get("source"))
            dest = parse_target(r.get("dest"))
            topic_id = parse_topic_id(r.get("topic_id"))
            allowed = normalize_sender_ids(r.get("allowed_senders", []))
            routes.append(
                RouteConfig(
                    source=source,
                    dest=dest,
                    topic_id=topic_id,
                    allowed_senders=allowed,
                )
            )
        sources = [r.source for r in routes]
        dests = [r.dest for r in routes]
    else:
        sources_raw = monitor_raw["sources"]
        dests_raw = monitor_raw["dests"]
        sources = [parse_target(x) for x in sources_raw]
        dests = [parse_target(x) for x in dests_raw]
        routes = [RouteConfig(source=s, dest=d, topic_id=None) for s in sources for d in dests]

    monitor = MonitorConfig(
        sources=sources,
        dests=dests,
        routes=routes,
    )

    opts = cfg.get("options", {})
    options = OptionsConfig(
        download_media=bool(opts.get("download_media", True)),
        album_wait_seconds=float(opts.get("album_wait_seconds", 1.2)),
        progress_log=bool(opts.get("progress_log", True)),
        reload_interval_seconds=float(opts.get("reload_interval_seconds", 2)),
        state_file=str(opts.get("state_file", "data/state_last_ids.json")),
        keywords=normalize_keywords(opts.get("keywords", [])),
        allowed_senders=normalize_sender_ids(opts.get("allowed_senders", [])),
        admin_chat_ids=parse_chat_ids(
            opts.get("admin_chat_ids", opts.get("admin_chat_id"))
        ),
        admin_senders=normalize_sender_ids(opts.get("admin_senders", [])),
        gap_trigger_threshold=normalize_non_negative_int(
            opts.get("gap_trigger_threshold"), default=1, field_name="gap_trigger_threshold"
        ),
        catchup_min_offline_minutes=normalize_optional_int(
            opts.get("catchup_min_offline_minutes")
        ),
        max_send_retries=int(opts.get("max_send_retries", 3)),
        retry_base_seconds=float(opts.get("retry_base_seconds", 1.5)),
    )

    cve_monitor = None
    cve_raw = cfg.get("cve_monitor", {})
    if cve_raw and cve_raw.get("enabled", False):
        cve_monitor = CveMonitorConfig(
            enabled=True,
            interval_seconds=int(cve_raw.get("interval_seconds", 300)),
            dest=parse_target(cve_raw["dest"]),
            topic_id=parse_topic_id(cve_raw.get("topic_id")),
            keywords=normalize_keywords(cve_raw.get("keywords", [])),
            include_updates=bool(cve_raw.get("include_updates", True)),
            kev_enabled=bool(cve_raw.get("kev_enabled", True)),
            kev_cache_file=str(cve_raw.get("kev_cache_file", "data/cve_kev_cache.json")),
            kev_cache_ttl_hours=int(cve_raw.get("kev_cache_ttl_hours", 24)),
            min_cvss=float(cve_raw.get("min_cvss", 0.0)),
        )

    return AppConfig(telegram=telegram, monitor=monitor, options=options, cve_monitor=cve_monitor)
