"""Compression helpers for the PGP pipeline."""

from __future__ import annotations

import pickle
import zlib


def compress_data(packet: dict, is_signed: bool, perform_compression: bool) -> bytes:
    serialized_packet = pickle.dumps(packet)
    header = bytearray()

    if perform_compression:
        header.append(0x01)
    else:
        header.append(0x00)

    if is_signed:
        header.append(0x01)
    else:
        header.append(0x00)

    if perform_compression:
        payload = zlib.compress(serialized_packet)
    else:
        payload = serialized_packet

    final_stream = bytes(header + payload)

    return final_stream

def decompress_data(compressed_bytes: bytes) -> dict:
    if len(compressed_bytes) < 2:
        raise ValueError("Podaci su prekratki da bi sadržali PGP flegove.")

    compression_flag = compressed_bytes[0]
    is_signed_flag = compressed_bytes[1]

    payload = compressed_bytes[2:]

    if compression_flag == 0x01:
        serialized_packet = zlib.decompress(payload)
    elif compression_flag == 0x00:
        serialized_packet = payload
    else:
        raise ValueError(
            f"Kritična greška: Nepoznat fleg za kompresiju ({hex(compression_flag)})"
        )

    packet = pickle.loads(serialized_packet)

    if is_signed_flag == 0x01:
        required_keys = [
            "sender_key_id",
            "sig_timestamp",
            "encrypted_hash",
            "message_comp",
        ]

        if not all(k in packet for k in required_keys):
            raise TypeError(
                "Greška u strukturi: Očekivan je potpisani paket, ali nedostaju ključevi."
            )

    elif is_signed_flag == 0x00:
        required_keys = ["filename", "timestamp", "data"]
        if not all(k in packet for k in required_keys):
            raise TypeError(
                "Greška u strukturi: Očekivana je obična poruka, ali nedostaju ključevi."
            )

    else:
        raise ValueError(
            f"Kritična greška: Nepoznat fleg za potpis ({hex(is_signed_flag)})"
        )

    return packet