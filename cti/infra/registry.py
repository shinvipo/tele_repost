"""Event handler registration/unregistration — Telethon events layer.

Extracted from apply.py to isolate handler lifecycle management.
"""

from telethon import events, utils

from ..state import app


def unregister_handlers(client):
    """Remove previously registered event handlers."""
    if app.active_handler_fn and app.active_handler_event:
        try:
            client.remove_event_handler(app.active_handler_fn, app.active_handler_event)
        except Exception:
            pass
    if app.active_admin_handler_fn and app.active_admin_handler_event:
        try:
            client.remove_event_handler(app.active_admin_handler_fn, app.active_admin_handler_event)
        except Exception:
            pass


def register_message_handler(client, watch_sources, handler_fn):
    """Register the new-message handler on the given source entities."""
    watch_chats = list(watch_sources)
    if watch_chats:
        unique_map = {}
        for ent in watch_chats:
            try:
                key = utils.get_peer_id(ent)
            except Exception:
                key = None
            if key is None:
                continue
            unique_map[key] = ent
        watch_chats = list(unique_map.values())

    app.active_handler_fn = handler_fn
    app.active_handler_event = events.NewMessage(chats=watch_chats)
    client.add_event_handler(app.active_handler_fn, app.active_handler_event)


def register_admin_handler(client, admin_entities, handler_fn):
    """Register the admin-command handler on the given admin chats."""
    if admin_entities:
        app.active_admin_handler_fn = handler_fn
        app.active_admin_handler_event = events.NewMessage(chats=admin_entities)
        client.add_event_handler(app.active_admin_handler_fn, app.active_admin_handler_event)
    else:
        app.active_admin_handler_fn = None
        app.active_admin_handler_event = None
