"""Radix-64 encoding helpers for the PGP pipeline."""

from __future__ import annotations

from typing import Any


def encode_radix64(final_packet_dict: dict[str, Any], is_encrypted: bool) -> str:
    """Serialize the final packet into ASCII armored PGP text."""
    raise NotImplementedError("encode_radix64 is not implemented yet")