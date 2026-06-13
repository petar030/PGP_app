import json
from pathlib import Path

from .keyring_models import PUBLIC_KEYRING_PATH, PRIVATE_KEYRING_PATH


def ensure_keyring_storage() -> None:
    for path in (PUBLIC_KEYRING_PATH, PRIVATE_KEYRING_PATH):
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        if not file_path.exists():
            file_path.write_text("{}", encoding="utf-8")


def load_public_keyring(path: str = PUBLIC_KEYRING_PATH) -> dict[str, dict]:
    return _load_keyring(path)


def save_public_keyring(public_keyring: dict[str, dict], path: str = PUBLIC_KEYRING_PATH) -> None:
    _save_keyring(public_keyring, path)


def load_private_keyring(path: str = PRIVATE_KEYRING_PATH) -> dict[str, dict]:
    return _load_keyring(path)


def save_private_keyring(private_keyring: dict[str, dict], path: str = PRIVATE_KEYRING_PATH) -> None:
    _save_keyring(private_keyring, path)


def _load_keyring(path: str) -> dict[str, dict]:
    file_path = Path(path)

    if not file_path.exists():
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text("{}", encoding="utf-8")
        return {}

    if file_path.stat().st_size == 0:
        file_path.write_text("{}", encoding="utf-8")
        return {}

    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        return data

    if isinstance(data, list):
        converted = {}

        for entry in data:
            if isinstance(entry, dict) and "key_id" in entry:
                converted[str(entry["key_id"])] = entry

        return converted

    raise ValueError(f"Invalid keyring format in {path}")


def _save_keyring(keyring: dict[str, dict], path: str) -> None:
    if not isinstance(keyring, dict):
        raise ValueError("Keyring must be a dict")

    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with file_path.open("w", encoding="utf-8") as f:
        json.dump(keyring, f, indent=4, ensure_ascii=False)