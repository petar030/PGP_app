"""Encryption helpers for the PGP pipeline."""

from __future__ import annotations

from typing import Any


def encrypt_message(
    compressed_bytes: bytes,
    receiver_public_key: object,
    receiver_key_id: str,
    symmetric_algo: str,
) -> dict[str, Any]:
    """Encrypt the compressed payload and wrap the session key metadata."""
    raise NotImplementedError("encrypt_message is not implemented yet")