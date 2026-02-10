import asyncio

from telethon import TelegramClient

from .apply import apply_config, watch_config
from .connection import watch_connection
from .config import parse_config
from .constants import CONFIG_PATH, LOG_PATH
from .cve.runner import start_cve_monitor
from .logger import setup_logging
from .state import app, load_json


async def main():
    setup_logging(LOG_PATH)
    cfg = parse_config(load_json(CONFIG_PATH))

    client = TelegramClient(cfg.telegram.session, cfg.telegram.api_id, cfg.telegram.api_hash)
    app.client = client

    async with client:
        await apply_config(cfg)
        asyncio.create_task(watch_config(CONFIG_PATH, parse_config, apply_config))
        asyncio.create_task(watch_connection())

        if cfg.cve_monitor and cfg.cve_monitor.enabled:
            asyncio.create_task(start_cve_monitor(cfg.cve_monitor, client))
        else:
            print("[INFO] CVE Monitor is disabled")

        print("[OK] Monitoring... (Ctrl+C to stop)")
        await client.run_until_disconnected()


def run():
    asyncio.run(main())
