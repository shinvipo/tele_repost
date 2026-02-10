"""
CVE Monitor Runner — Async loop that integrates CVE monitoring with the Telethon client.

Polls cvelistV5 delta.json at configurable intervals, parses new/updated CVEs,
optionally filters by keywords, and sends formatted alerts to a dedicated topic/channel.
"""

import asyncio

from ..models import CveMonitorConfig
from ..state import app, update_cve_state
from ..telegram import resolve_target, send_with_retry, build_reply_to
from .formatter import TelegramFormatter
from .kev import KEVLookup
from .monitor import DeltaMonitor
from .parser import CVEParser


def _matches_keywords(cve_data: dict, keywords: list[str]) -> bool:
    """Check if a CVE matches any of the configured keywords (case-insensitive).

    Searches in: title, description, affected vendor names, product names, package names.
    """
    if not keywords:
        return True  # No keywords = accept all

    text_parts = [
        cve_data.get("title", ""),
        cve_data.get("description", ""),
    ]
    for prod in cve_data.get("affected_products", []):
        text_parts.append(prod.get("vendor", ""))
        text_parts.append(prod.get("product", ""))
        text_parts.append(prod.get("package_name", ""))

    combined = " ".join(text_parts).lower()
    return any(kw in combined for kw in keywords)


async def _send_cve_message(client, dest_entity, topic_id: int | None, message: str,
                            raw_dest):
    """Send a single CVE alert message via Telethon with retry."""
    reply_to = build_reply_to(topic_id)
    await send_with_retry(
        raw_dest,
        lambda r=reply_to, ent=dest_entity: client.send_message(
            ent, message, parse_mode="html", reply_to=r,
            link_preview=False,
        ),
    )


async def _process_delta(
    delta: dict,
    parser: CVEParser,
    formatter: TelegramFormatter,
    kev: KEVLookup,
    monitor: DeltaMonitor,
    client,
    dest_entity,
    config: CveMonitorConfig,
) -> int:
    """Process a single delta snapshot: parse CVEs and send alerts."""
    new_entries, updated_entries = monitor.get_new_entries(delta)

    if not config.include_updates:
        updated_entries = []

    if not new_entries and not updated_entries:
        return 0

    total = len(new_entries) + len(updated_entries)
    print(f"[CVE Monitor] Processing {total} CVEs ({len(new_entries)} new, {len(updated_entries)} updated)")

    processed_ids = []

    for entry in new_entries:
        await _process_one(
            entry, True, parser, formatter, kev, monitor,
            client, dest_entity, config,
        )
        processed_ids.append(entry.get("cveId", ""))

    for entry in updated_entries:
        await _process_one(
            entry, False, parser, formatter, kev, monitor,
            client, dest_entity, config,
        )
        processed_ids.append(entry.get("cveId", ""))

    monitor.mark_processed(delta.get("fetchTime", ""), processed_ids)
    await update_cve_state()
    return total


async def _process_one(
    entry: dict,
    is_new: bool,
    parser: CVEParser,
    formatter: TelegramFormatter,
    kev: KEVLookup,
    monitor: DeltaMonitor,
    client,
    dest_entity,
    config: CveMonitorConfig,
):
    """Process a single CVE entry from delta."""
    cve_id = entry.get("cveId", "")
    github_link = entry.get("githubLink", "")

    if not github_link:
        print(f"[WARN] No githubLink for {cve_id}, skipping")
        return

    # Download full CVE JSON (run in executor to not block event loop)
    loop = asyncio.get_event_loop()
    raw = await loop.run_in_executor(None, monitor.fetch_cve_json, github_link)
    if not raw:
        return

    # Parse
    cve_data = parser.parse(raw)

    # Keyword filtering
    if not _matches_keywords(cve_data, config.keywords):
        return

    # KEV lookup
    kev_entry = kev.lookup(cve_id)

    # Format message
    message = formatter.format(cve_data, is_new=is_new, kev_entry=kev_entry)

    # Send via Telethon
    await _send_cve_message(client, dest_entity, config.topic_id, message, config.dest)
    await asyncio.sleep(1)  # Rate limiting between messages


async def start_cve_monitor(config: CveMonitorConfig, client) -> None:
    """Main entry point: start the CVE monitor as an async background task.

    Args:
        config: CveMonitorConfig with all settings.
        client: Telethon TelegramClient (already connected).
    """
    print("[CVE Monitor] Initializing...")

    # Resolve destination entity
    try:
        dest_entity = await resolve_target(config.dest)
    except Exception as e:
        print(f"[ERR] CVE Monitor: cannot resolve dest={config.dest}: {e}")
        return

    # Initialize components (KEV downloads synchronously on init, run in executor)
    loop = asyncio.get_event_loop()
    parser = CVEParser()
    formatter = TelegramFormatter()
    kev = await loop.run_in_executor(
        None, KEVLookup, config.kev_enabled, config.kev_cache_file, config.kev_cache_ttl_hours
    )
    # DeltaMonitor uses the shared in-memory cve_state from app
    monitor = DeltaMonitor(app.cve_state)

    # Catchup: process missed deltas
    missed = monitor.catchup()
    for delta_snapshot in missed:
        await _process_delta(
            delta_snapshot, parser, formatter, kev, monitor,
            client, dest_entity, config,
        )

    keywords_info = f", keywords={config.keywords}" if config.keywords else ", keywords=ALL"
    print(
        f"[CVE Monitor] Started. Polling every {config.interval_seconds}s, "
        f"dest={config.dest}, topic_id={config.topic_id}"
        f"{keywords_info}"
    )

    # Main polling loop
    while True:
        try:
            delta = await loop.run_in_executor(None, monitor.fetch_delta)
            if delta:
                count = await _process_delta(
                    delta, parser, formatter, kev, monitor,
                    client, dest_entity, config,
                )
                if count:
                    print(f"[CVE Monitor] Processed {count} CVEs in this cycle")
        except Exception as e:
            print(f"[ERR] CVE Monitor cycle error: {e}")

        await asyncio.sleep(config.interval_seconds)
