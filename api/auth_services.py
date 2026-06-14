"""Message preparation and signing helpers."""

from __future__ import annotations

from typing import Any

from rsa_keyring.keyring_utils import key_id_to_bytes

from datetime import datetime

import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def create_message_component(data: str, filename: str) -> dict:
    return {
        'filename': filename,
        'timestamp': datetime.now().timestamp(),
        'data': data.encode('utf-8')
    }

def extract_message_component(packed_message: dict) -> dict:
    return {
        'filename': packed_message['filename'],
        'timestamp': packed_message['timestamp'],
        'data': packed_message['data'].decode('utf-8')
    }

def sign_message(message_component: dict, sender_private_key: object, sender_key_id: str) -> dict:
    hasher = hashlib.sha1()
    hasher.update(message_component['data'])
    hasher.update(str(int(datetime.now().timestamp())).encode('utf-8'))
    message_digest = hasher.digest()

    leading_octets = message_digest[:2]
    encrypted_hash = sender_private_key.sign(
        message_digest,
        padding.PKCS1v15(),
        hashes.SHA1()
    )

    return {
        'sender_key_id': sender_key_id,
        'sig_timestamp': datetime.now().timestamp(),
        'leading_octets': leading_octets,
        'encrypted_hash': encrypted_hash,
        'message_comp': message_component
    }

def verify_signature(signed_packet: dict, sender_public_key: object) -> dict:
    msg_comp = signed_packet['message_comp']
    data = msg_comp['data']
    received_hash = signed_packet['encrypted_hash']
    received_octets = signed_packet['leading_octets']
    sig_timestamp = signed_packet['sig_timestamp']

    hasher = hashlib.sha1()
    hasher.update(data)
    
    hasher.update(str(int(sig_timestamp)).encode('utf-8'))
    
    calculated_digest = hasher.digest()

    if calculated_digest[:2] != received_octets:
        raise ValueError("Integritet poruke narušen: Vodeći okteti se ne poklapaju.")

    try:
        sender_public_key.verify(
            received_hash,
            calculated_digest,
            padding.PKCS1v15(),
            hashes.SHA1()
        )
        is_valid = True
    except Exception:
        raise ValueError("Verifikacija potpisa nije uspela! Ključ ne odgovara.")

    return {
        'is_valid': is_valid,
        'sender_key_id': signed_packet['sender_key_id'],
        'message_comp': msg_comp
    }