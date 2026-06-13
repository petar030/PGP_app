from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

from .keyring_models import SUPPORTED_RSA_KEY_SIZES


def generate_rsa_key_pair(key_size: int):
    if key_size not in SUPPORTED_RSA_KEY_SIZES:
        raise ValueError(f"Unsupported RSA key size: {key_size}")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    public_key = private_key.public_key()

    return private_key, public_key


def calculate_key_id(public_key) -> bytes:
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_key_der[-8:]


def calculate_key_id_hex(public_key) -> str:
    return calculate_key_id(public_key).hex().upper()


def serialize_public_key_to_pem(public_key) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


def serialize_private_key_to_pem(private_key, password: str, encrypted: bool = True) -> str:
    if not isinstance(password, str) or not password:
        raise ValueError("Password is required")

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        ) if encrypted else serialization.NoEncryption()
    ).decode("utf-8")


def load_public_key_from_pem(public_key_pem: str):
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode("utf-8")
    )

    if not isinstance(public_key, RSAPublicKey):
        raise ValueError("PEM does not contain an RSA public key")

    return public_key


def load_private_key_from_pem(private_key_pem: str, password: str | None = None):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=password.encode("utf-8") if password is not None else None
    )

    if not isinstance(private_key, RSAPrivateKey):
        raise ValueError("PEM does not contain an RSA private key")

    return private_key


def key_id_to_hex(key_id: str | bytes) -> str:
    if isinstance(key_id, bytes):
        if len(key_id) != 8:
            raise ValueError("Key ID bytes must be exactly 8 bytes")

        return key_id.hex().upper()

    if isinstance(key_id, str):
        normalized = key_id.replace(" ", "").replace(":", "").upper()

        if len(normalized) != 16:
            raise ValueError("Key ID hex string must contain exactly 16 hex characters")

        try:
            bytes.fromhex(normalized)
        except ValueError as e:
            raise ValueError("Invalid key ID hex string") from e

        return normalized

    raise TypeError("Key ID must be str or bytes")

def key_id_to_bytes(key_id: str | bytes) -> bytes:
    if isinstance(key_id, bytes):
        if len(key_id) != 8:
            raise ValueError("Key ID bytes must be exactly 8 bytes")

        return key_id

    if isinstance(key_id, str):
        normalized = key_id.replace(" ", "").replace(":", "").upper()

        if len(normalized) != 16:
            raise ValueError("Key ID hex string must contain exactly 16 hex characters")

        try:
            return bytes.fromhex(normalized)
        except ValueError as e:
            raise ValueError("Invalid key ID hex string") from e

    raise TypeError("Key ID must be str or bytes")