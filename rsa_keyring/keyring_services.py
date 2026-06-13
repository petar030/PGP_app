import time
from copy import deepcopy
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .keyring_storage import (
    ensure_keyring_storage,
    load_public_keyring,
    load_private_keyring,
    save_public_keyring,
    save_private_keyring,
)

from .keyring_utils import (
    generate_rsa_key_pair,
    calculate_key_id_hex,
    serialize_public_key_to_pem,
    serialize_private_key_to_pem,
    load_public_key_from_pem,
    load_private_key_from_pem,
    key_id_to_hex,
)


_public_keyring: dict[str, dict] = {}
_private_keyring: dict[str, dict] = {}
_initialized = False


# Keyring initialization
def initialize_keyrings() -> None:
    global _public_keyring, _private_keyring, _initialized

    ensure_keyring_storage()
    _public_keyring = _normalize_keyring(load_public_keyring())
    _private_keyring = _normalize_keyring(load_private_keyring())
    _initialized = True
def save_keyrings() -> None:
    _ensure_initialized()
    save_public_keyring(_public_keyring)
    save_private_keyring(_private_keyring)


# Retrieving list of keys
def get_public_keys() -> list[dict]:
    _ensure_initialized()
    return deepcopy(list(_public_keyring.values()))
def get_private_keys() -> list[dict]:
    _ensure_initialized()
    return deepcopy(list(_private_keyring.values()))


# Key generation
def generate_key_pair(user_name: str, email: str, key_size: int, password: str) -> tuple[dict, dict]:
    _ensure_initialized()

    private_key, public_key = generate_rsa_key_pair(key_size)
    timestamp = int(time.time())
    key_id = calculate_key_id_hex(public_key)
    public_key_pem = serialize_public_key_to_pem(public_key)

    if key_id in _private_keyring:
        raise ValueError("Key pair already exists")

    public_entry = {
        "key_id": key_id,
        "user_name": user_name.strip(),
        "email": email.strip(),
        "timestamp": timestamp,
        "key_size": public_key.key_size,
        "public_key_pem": public_key_pem,
    }

    private_entry = {
        "key_id": key_id,
        "user_name": user_name.strip(),
        "email": email.strip(),
        "timestamp": timestamp,
        "key_size": public_key.key_size,
        "public_key_pem": public_key_pem,
        "encrypted_private_key_pem": serialize_private_key_to_pem(private_key, password, encrypted=True),
    }

    _public_keyring[key_id] = public_entry
    _private_keyring[key_id] = private_entry

    save_keyrings()

    return deepcopy(public_entry), deepcopy(private_entry)


# Import/Export
def import_key(
    file_path: str,
    user_name: str = "",
    email: str = "",
    private_key_pem_password: str | None = None,
    keyring_password: str | None = None,
) -> dict | tuple[dict, dict]:
    _ensure_initialized()

    pem_content = Path(file_path).read_text(encoding="utf-8")

    try:
        _extract_key_pem_block(pem_content, is_private=True)
        has_private_key = True
    except ValueError:
        has_private_key = False

    if has_private_key:
        return import_key_pair(
            file_path=file_path,
            user_name=user_name,
            email=email,
            private_key_pem_password=private_key_pem_password,
            keyring_password=keyring_password,
        )

    return import_public_key(
        file_path=file_path,
        user_name=user_name,
        email=email,
    )
def import_public_key(file_path: str, user_name: str = "", email: str = "") -> dict:
    _ensure_initialized()

    pem_content = Path(file_path).read_text(encoding="utf-8")
    public_key_pem = _extract_key_pem_block(pem_content)
    public_key = load_public_key_from_pem(public_key_pem)

    key_id = calculate_key_id_hex(public_key)

    if key_id in _public_keyring:
        raise ValueError("Public key already exists")

    entry = {
        "key_id": key_id,
        "user_name": user_name.strip(),
        "email": email.strip(),
        "timestamp": int(time.time()),
        "key_size": public_key.key_size,
        "public_key_pem": serialize_public_key_to_pem(public_key),
    }

    _public_keyring[key_id] = entry
    save_public_keyring(_public_keyring)

    return deepcopy(entry)
def import_key_pair(
    file_path: str,
    user_name: str = "",
    email: str = "",
    private_key_pem_password: str | None = None,
    keyring_password: str | None = None,
) -> tuple[dict, dict]:
    _ensure_initialized()

    pem_content = Path(file_path).read_text(encoding="utf-8")

    public_key_pem = _extract_key_pem_block(pem_content)
    private_key_pem = _extract_key_pem_block(pem_content, is_private=True)

    public_key = load_public_key_from_pem(public_key_pem)

    timestamp = int(time.time())
    key_id = calculate_key_id_hex(public_key)
    normalized_public_key_pem = serialize_public_key_to_pem(public_key)

    if key_id in _private_keyring:
        raise ValueError("Key pair already exists")

    if keyring_password:
        private_key = load_private_key_from_pem(private_key_pem, private_key_pem_password)
        private_public_key = private_key.public_key()
        private_key_id = calculate_key_id_hex(private_public_key)

        if private_key_id != key_id:
            raise ValueError("Public key and private key do not match")

        encrypted_private_key_pem = serialize_private_key_to_pem(
            private_key,
            keyring_password,
            encrypted=True,
        )
    else:
        if "-----BEGIN ENCRYPTED PRIVATE KEY-----" not in private_key_pem:
            raise ValueError("Keyring password is required for importing an unencrypted private key")

        encrypted_private_key_pem = private_key_pem

    public_entry = {
        "key_id": key_id,
        "user_name": user_name.strip(),
        "email": email.strip(),
        "timestamp": timestamp,
        "key_size": public_key.key_size,
        "public_key_pem": normalized_public_key_pem,
    }

    private_entry = {
        "key_id": key_id,
        "user_name": user_name.strip(),
        "email": email.strip(),
        "timestamp": timestamp,
        "key_size": public_key.key_size,
        "public_key_pem": normalized_public_key_pem,
        "encrypted_private_key_pem": encrypted_private_key_pem,
    }

    _public_keyring[key_id] = public_entry
    _private_keyring[key_id] = private_entry

    save_keyrings()

    return deepcopy(public_entry), deepcopy(private_entry)
def export_public_key(key_id: str | bytes, file_path: str) -> None:
    entry = find_public_key(key_id)

    if entry is None:
        raise ValueError("Public key not found")

    Path(file_path).write_text(entry["public_key_pem"], encoding="utf-8")
def export_key_pair(key_id: str | bytes, unlock_password: str | None, file_path: str) -> None:
    private_entry = find_private_key(key_id)

    if private_entry is None:
        raise ValueError("Key pair not found")


    if unlock_password is None:
        content = private_entry["public_key_pem"].strip() + "\n" + private_entry["encrypted_private_key_pem"].strip() + "\n"
        Path(file_path).write_text(content, encoding="utf-8")

    else:
        private_key = load_private_key_from_pem(private_entry["encrypted_private_key_pem"], unlock_password)
        private_key_pem = serialize_private_key_to_pem(private_key, unlock_password, encrypted=False)
        content = private_entry["public_key_pem"].strip() + "\n" + private_key_pem.strip() + "\n"
        Path(file_path).write_text(content, encoding="utf-8")

    

# Keyring index searching
def find_public_key(key_id: str | bytes) -> dict | None:
    _ensure_initialized()
    entry = _public_keyring.get(key_id_to_hex(key_id))
    return deepcopy(entry) if entry is not None else None
def find_private_key(key_id: str | bytes) -> dict | None:
    _ensure_initialized()
    entry = _private_keyring.get(key_id_to_hex(key_id))
    return deepcopy(entry) if entry is not None else None
def get_public_key_object(key_id: str | bytes):
    entry = find_public_key(key_id)

    if entry is None:
        raise ValueError("Public key not found")

    return load_public_key_from_pem(entry["public_key_pem"])


# Deleting keys
def delete_public_key(key_id: str | bytes) -> bool:
    _ensure_initialized()
    key_id_hex = key_id_to_hex(key_id)

    if key_id_hex in _private_keyring:
        raise ValueError("Cannot delete public key because matching private key exists")

    if key_id_hex not in _public_keyring:
        return False

    del _public_keyring[key_id_hex]
    save_public_keyring(_public_keyring)

    return True
def delete_private_key(key_id: str | bytes, delete_public_key_entry: bool = False) -> bool:
    _ensure_initialized()
    key_id_hex = key_id_to_hex(key_id)

    if key_id_hex not in _private_keyring:
        return False

    del _private_keyring[key_id_hex]

    if delete_public_key_entry and key_id_hex in _public_keyring:
        del _public_keyring[key_id_hex]

    save_keyrings()

    return True


# Helper functions
def _ensure_initialized() -> None:
    if not _initialized:
        initialize_keyrings()
def _normalize_keyring(keyring: dict[str, dict]) -> dict[str, dict]:
    normalized = {}

    for key_id, entry in keyring.items():
        normalized_key_id = key_id_to_hex(entry.get("key_id", key_id))

        normalized[normalized_key_id] = {
            "key_id": normalized_key_id,
            "user_name": entry.get("user_name", "").strip(),
            "email": entry.get("email", "").strip(),
            "timestamp": entry.get("timestamp", int(time.time())),
            "key_size": entry.get("key_size"),
            "public_key_pem": entry.get("public_key_pem", ""),
        }

        if "encrypted_private_key_pem" in entry:
            normalized[normalized_key_id]["encrypted_private_key_pem"] = entry["encrypted_private_key_pem"]

    return normalized
def _extract_key_pem_block(content: str, is_private: bool = False) -> str:
    """Izdvaja PEM blok za javni ili privatni ključ iz sadržaja."""
    # Definišemo koje tagove tražimo u zavisnosti od tipa ključa
    possible_blocks = (
        ["ENCRYPTED PRIVATE KEY", "PRIVATE KEY", "RSA PRIVATE KEY"]
        if is_private
        else ["PUBLIC KEY", "RSA PUBLIC KEY"]
    )

    # Prolazimo kroz opcije i vraćamo prvu na koju naiđemo
    for block_name in possible_blocks:
        begin = f"-----BEGIN {block_name}-----"
        end = f"-----END {block_name}-----"

        if begin in content and end in content:
            start = content.find(begin)
            finish = content.find(end) + len(end)
            return content[start:finish] + "\n"

    # Ako petlja završi, a ništa nismo našli, bacamo grešku
    key_type = "private" if is_private else "public"
    raise ValueError(f"Missing {key_type} key PEM block")


