"""Compression helpers for the PGP pipeline."""

from __future__ import annotations


def compress_data(serialized_data: bytes, perform_compression: bool) -> bytes:
    """Prefix the compression flag and optionally compress payload bytes."""
    raise NotImplementedError("compress_data is not implemented yet")