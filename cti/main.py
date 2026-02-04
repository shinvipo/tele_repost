import asyncio

from telethon import TelegramClient

from .apply import apply_config, watch_config
from .config import parse_config
from .constants import CONFIG_PATH
from .state import app, load_json


async def main():
    cfg = parse_config(load_json(CONFIG_PATH))

    client = TelegramClient(cfg.telegram.session, cfg.telegram.api_id, cfg.telegram.api_hash)
    app.client = client

    async with client:
        await apply_config(cfg)
        asyncio.create_task(watch_config(CONFIG_PATH, parse_config, apply_config))
        print("[OK] Monitoring... (Ctrl+C to stop)")
        await client.run_until_disconnected()


def run():
    asyncio.run(main())
