"""Admin command handler — thin event handler for admin commands.

Handler only: receives event → extracts text → calls service → sends response.
"""

from ..core.message import safe_text
from ..state import app, get_client, load_json
from . import service


async def on_admin_message(event):
    if not service.is_admin_message(event):
        return

    text = safe_text(event.message)
    parsed = service.parse_keywords_command(text)
    if not parsed:
        return

    action, args = parsed
    current = list(app.options.keywords)

    new_keywords, response = service.process_keywords_action(action, args, current)

    if new_keywords is not None:
        service.write_keywords_to_config(new_keywords)

        # Lazy import to avoid circular dependency (apply -> admin -> apply)
        from ..apply import apply_config
        from ..core.config import parse_config
        from ..core.constants import CONFIG_PATH

        cfg = parse_config(load_json(CONFIG_PATH))
        await apply_config(cfg)

    client = get_client()
    await client.send_message(event.chat_id, response)
