"""Message preparation and signing helpers."""

from __future__ import annotations

from typing import Any


def create_message_component(data: bytes, filename: str, timestamp: int) -> dict[str, Any]:
    """Package raw data and metadata into a message component."""
    raise NotImplementedError("create_message_component is not implemented yet")


def sign_message(message_component: dict[str, Any], sender_private_key: object, sender_key_id: str) -> dict[str, Any]:
    """Create a detached signature package for the given message component."""
    raise NotImplementedError("sign_message is not implemented yet")