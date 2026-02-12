"""Apply config — resolve entities, build route map, register handlers."""

import asyncio
import os
from typing import Any, Dict, List

from .admin.handler import on_admin_message
from .core.models import AppConfig, ResolvedDest
from .infra.client import get_peer_id, resolve_entity_with_fallback, resolve_target
from .infra.registry import register_admin_handler, register_message_handler, unregister_handlers
from .repost.backfill import backfill_missing_state, catch_up_from_state
from .repost.handler import on_new_message
from .state import app, get_client, load_cve_state, load_json, load_state


def _format_route(d: ResolvedDest) -> str:
    if d.allowed_senders and d.topic_id:
        return f"{d.raw_dest}#topic={d.topic_id}#senders={d.allowed_senders}"
    if d.topic_id:
        return f"{d.raw_dest}#topic={d.topic_id}"
    if d.allowed_senders:
        return f"{d.raw_dest}#senders={d.allowed_senders}"
    return f"{d.raw_dest}"


async def apply_config(cfg: AppConfig) -> None:
    """
    Apply config safely:
      - if config is invalid -> do nothing
      - if resolve fails -> keep previous config
      - remove old handler + add new handler with updated sources
    """
    client = get_client()

    options = cfg.options
    app.options = options

    loaded = load_state(options.state_file)
    for k, v in loaded.items():
        app.state.setdefault(k, v)

    app.cve_state = load_cve_state(options.state_file)

    routes = cfg.monitor.routes

    route_map: Dict[str, List[ResolvedDest]] = {}
    resolved_sources_map: Dict[str, Any] = {}
    new_source_name_map: Dict[str, str] = {}

    for r in routes:
        try:
            src_ent = await resolve_entity_with_fallback(r.source)
        except Exception as e:
            raise ValueError(f"Cannot resolve SOURCE={r.source}: {e}")

        src_key = str(get_peer_id(src_ent))

        try:
            dest_ent = await resolve_target(r.dest)
        except Exception as e:
            print(f"[CORE] [WARN] Skip ROUTE dest={r.dest} (cannot resolve): {e}")
            continue

        if src_key not in resolved_sources_map:
            resolved_sources_map[src_key] = src_ent
            name = getattr(src_ent, "title", None) or getattr(src_ent, "username", None) or str(
                getattr(src_ent, "id", r.source)
            )
            new_source_name_map[src_key] = name

        route_map.setdefault(src_key, []).append(
            ResolvedDest(
                raw_dest=r.dest,
                dest_ent=dest_ent,
                topic_id=r.topic_id,
                allowed_senders=r.allowed_senders,
            )
        )

    if not route_map:
        raise ValueError("No valid ROUTES resolved. Fix monitor.routes or monitor.dests.")

    resolved_sources = list(resolved_sources_map.values())
    if not resolved_sources:
        raise ValueError("No valid SOURCES resolved. Fix monitor.routes or monitor.sources.")

    app.entity_cache = {}

    app.route_map = route_map
    app.source_entities = resolved_sources_map
    app.source_name_map = new_source_name_map

    # Unregister old handlers and register new ones
    unregister_handlers(client)
    register_message_handler(client, resolved_sources, on_new_message)

    if options.admin_chat_ids:
        admin_entities = []
        for chat_id in options.admin_chat_ids:
            try:
                admin_ent = await resolve_entity_with_fallback(chat_id)
                admin_entities.append(admin_ent)
            except Exception as e:
                print(f"[CORE] [WARN] Cannot resolve admin_chat_id={chat_id}: {e}")

        register_admin_handler(client, admin_entities, on_admin_message)

        if not admin_entities:
            print("[CORE] [WARN] admin_chat_ids configured but none resolved")
    else:
        register_admin_handler(client, [], on_admin_message)
        if options.admin_senders:
            print("[CORE] [WARN] admin_senders is set but admin_chat_ids is empty; admin commands are disabled.")

    print("====================================")
    print("[CORE] [OK] Config applied")
    print(f"SOURCES(resolved) : {list(app.source_name_map.items())}")
    print("ROUTES(resolved)  :")
    for src_key, dests in app.route_map.items():
        name = app.source_name_map.get(src_key, src_key)
        dests_str = ", ".join([_format_route(d) for d in dests])
        print(f"  {name} ({src_key}) -> {dests_str}")
    print(f"download_media    : {options.download_media}")
    print(f"album_wait_sec    : {options.album_wait_seconds}")
    print(f"progress_log      : {options.progress_log}")
    print(f"state_file        : {options.state_file}")
    print(f"reload_interval_s : {options.reload_interval_seconds}")
    print(f"keywords          : {options.keywords}")
    print(f"allowed_senders   : {options.allowed_senders}")
    print(f"admin_chat_ids    : {options.admin_chat_ids}")
    print(f"admin_senders     : {options.admin_senders}")
    print(f"gap_trigger_threshold : {options.gap_trigger_threshold}")
    print(f"catchup_min_offline_minutes : {options.catchup_min_offline_minutes}")
    print(f"max_send_retries  : {options.max_send_retries}")
    print(f"retry_base_sec    : {options.retry_base_seconds}")
    print("====================================")

    await backfill_missing_state()
    await catch_up_from_state()


async def watch_config(config_path: str, parse_config_fn, apply_config_fn) -> None:
    last_mtime = None

    while True:
        try:
            if os.path.exists(config_path):
                mtime = os.path.getmtime(config_path)
                if last_mtime is None:
                    last_mtime = mtime

                if mtime != last_mtime:
                    last_mtime = mtime
                    print("[CORE] [INFO] config/config.json changed -> reloading ...")
                    try:
                        cfg = parse_config_fn(load_json(config_path))
                        await apply_config_fn(cfg)
                    except Exception as e:
                        print(f"[CORE] [WARN] Reload failed, keep previous config. Reason: {e}")
        except Exception as e:
            print(f"[CORE] [WARN] watch_config error: {e}")

        await asyncio.sleep(max(1.0, app.options.reload_interval_seconds))
