"""Encryption helpers for the PGP pipeline."""

from __future__ import annotations

import os
from typing import Any

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.modes import CFB
from cryptography.hazmat.primitives import serialization

from rsa_keyring.keyring_utils import key_id_to_bytes

SUPPORTED_CIPHERS = {
    "AES128": algorithms.AES,
    "Cast5": algorithms.CAST5,
}


def generate_random_number(length: int) -> bytes:
    """Generate a random number of specified length."""

    return os.urandom(length)

def encrypt_message(
    compressed_bytes: bytes,
    receiver_public_key: object,
    receiver_key_id: str,
    symmetric_algo: str,
) -> dict[str, Any]:
    """Encrypt the compressed payload and wrap the session key metadata."""

    if symmetric_algo not in SUPPORTED_CIPHERS:
        raise ValueError(f"Unsupported symmetric algorithm: {symmetric_algo}")

    receiver_key_id = key_id_to_bytes(receiver_key_id)

    # Generating session key and IV
    raw_session_key = generate_random_number(16)
    iv = generate_random_number(SUPPORTED_CIPHERS[symmetric_algo].block_size // 8)

    # Encryption using the specified symmetric algorithm in CFB mode
    algo_class = SUPPORTED_CIPHERS[symmetric_algo]
    cipher = Cipher(algo_class(raw_session_key), CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(compressed_bytes) + encryptor.finalize()

    # Encrypt the session key with the receiver's public key using RSA encryption
    encrypted_session_key = receiver_public_key.encrypt(
        raw_session_key,
        padding.PKCS1v15(),
    )

    # Adding IV to the beginning of the ciphertext for later decryption
    final_encrypted_data = iv + ciphertext

    return {
        "receiver_key_id": receiver_key_id,
        "session_key": encrypted_session_key,
        "symmetric_algo": symmetric_algo,
        "encrypted_data": final_encrypted_data,
    }

def decrypt_message(encrypted_message: dict[str, Any], receiver_private_key: object) -> dict[str, Any]:
    """Decrypt the encrypted message using the receiver's private key."""

    encrypted_session_key = encrypted_message["session_key"]
    raw_session_key = receiver_private_key.decrypt(
        encrypted_session_key,
        padding.PKCS1v15(),
    )

    final_encrypted_data = encrypted_message["encrypted_data"]
    algo_class = SUPPORTED_CIPHERS[encrypted_message["symmetric_algo"]]
    block_size_bytes = algo_class.block_size // 8
    iv = final_encrypted_data[:block_size_bytes]
    ciphertext = final_encrypted_data[block_size_bytes:]

    cipher = Cipher(algo_class(raw_session_key), CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    return {
        "decrypted_data": decrypted_data,
        "symmetric_algo": encrypted_message["symmetric_algo"],
    }
