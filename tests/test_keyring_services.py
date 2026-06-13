import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import rsa_keyring.keyring_services as services
import rsa_keyring.keyring_storage as storage
from rsa_keyring.keyring_utils import key_id_to_hex


class TestKeyringServices(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.public_keyring_path = self.temp_path / "public_keyring.json"
        self.private_keyring_path = self.temp_path / "private_keyring.json"

        self.public_keyring_path.write_text("{}", encoding="utf-8")
        self.private_keyring_path.write_text("{}", encoding="utf-8")

        self.patchers = [
            patch.object(services, "ensure_keyring_storage", self.ensure_storage),
            patch.object(services, "load_public_keyring", self.load_public),
            patch.object(services, "load_private_keyring", self.load_private),
            patch.object(services, "save_public_keyring", self.save_public),
            patch.object(services, "save_private_keyring", self.save_private),
        ]

        for patcher in self.patchers:
            patcher.start()

        services._public_keyring = {}
        services._private_keyring = {}
        services._initialized = False

        services.initialize_keyrings()

    def tearDown(self):
        for patcher in reversed(self.patchers):
            patcher.stop()

        services._public_keyring = {}
        services._private_keyring = {}
        services._initialized = False

        self.temp_dir.cleanup()

    def ensure_storage(self):
        self.public_keyring_path.parent.mkdir(parents=True, exist_ok=True)
        self.private_keyring_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.public_keyring_path.exists():
            self.public_keyring_path.write_text("{}", encoding="utf-8")

        if not self.private_keyring_path.exists():
            self.private_keyring_path.write_text("{}", encoding="utf-8")

    def load_public(self):
        return storage.load_public_keyring(str(self.public_keyring_path))

    def load_private(self):
        return storage.load_private_keyring(str(self.private_keyring_path))

    def save_public(self, public_keyring):
        storage.save_public_keyring(public_keyring, str(self.public_keyring_path))

    def save_private(self, private_keyring):
        storage.save_private_keyring(private_keyring, str(self.private_keyring_path))

    def test_initialize_keyrings_loads_empty_dicts(self):
        self.assertEqual(services.get_public_keys(), [])
        self.assertEqual(services.get_private_keys(), [])

    def test_generate_key_pair_creates_public_and_private_entries(self):
        public_entry, private_entry = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        self.assertEqual(public_entry["key_id"], private_entry["key_id"])
        self.assertEqual(public_entry["user_name"], "Petar Rancic")
        self.assertEqual(public_entry["email"], "petar@example.com")
        self.assertEqual(public_entry["key_size"], 1024)

        self.assertIn("public_key_pem", public_entry)
        self.assertIn("public_key_pem", private_entry)
        self.assertIn("encrypted_private_key_pem", private_entry)

        self.assertNotIn("source", public_entry)
        self.assertNotIn("is_active", public_entry)
        self.assertNotIn("source", private_entry)
        self.assertNotIn("is_active", private_entry)

        self.assertEqual(len(services.get_public_keys()), 1)
        self.assertEqual(len(services.get_private_keys()), 1)

    def test_generate_key_pair_persists_to_json_as_dict(self):
        public_entry, private_entry = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        public_data = storage.load_public_keyring(str(self.public_keyring_path))
        private_data = storage.load_private_keyring(str(self.private_keyring_path))

        self.assertIsInstance(public_data, dict)
        self.assertIsInstance(private_data, dict)

        self.assertIn(public_entry["key_id"], public_data)
        self.assertIn(private_entry["key_id"], private_data)

    def test_find_public_key_by_hex_key_id(self):
        public_entry, _ = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        found = services.find_public_key(public_entry["key_id"])

        self.assertIsNotNone(found)
        self.assertEqual(found["key_id"], public_entry["key_id"])

    def test_find_private_key_by_hex_key_id(self):
        _, private_entry = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        found = services.find_private_key(private_entry["key_id"])

        self.assertIsNotNone(found)
        self.assertEqual(found["key_id"], private_entry["key_id"])

    def test_find_key_by_bytes_key_id(self):
        public_entry, private_entry = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        key_id_bytes = bytes.fromhex(public_entry["key_id"])

        found_public = services.find_public_key(key_id_bytes)
        found_private = services.find_private_key(key_id_bytes)

        self.assertIsNotNone(found_public)
        self.assertIsNotNone(found_private)
        self.assertEqual(found_public["key_id"], public_entry["key_id"])
        self.assertEqual(found_private["key_id"], private_entry["key_id"])

    def test_find_missing_key_returns_none(self):
        self.assertIsNone(services.find_public_key("0011223344556677"))
        self.assertIsNone(services.find_private_key("0011223344556677"))

    def test_get_public_key_object_returns_rsa_public_key(self):
        public_entry, _ = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        public_key = services.get_public_key_object(public_entry["key_id"])

        self.assertIsInstance(public_key, RSAPublicKey)

    def test_unlock_private_key_returns_rsa_private_key(self):
        _, private_entry = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        private_key = services.unlock_private_key(private_entry["key_id"], "test-password")

        self.assertIsInstance(private_key, RSAPrivateKey)

    def test_unlock_private_key_with_wrong_password_raises_value_error(self):
        _, private_entry = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        with self.assertRaises(ValueError):
            services.unlock_private_key(private_entry["key_id"], "wrong-password")

    def test_export_public_key_creates_pem_file(self):
        public_entry, _ = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        output_path = self.temp_path / "exported_public.pem"

        services.export_public_key(public_entry["key_id"], str(output_path))

        content = output_path.read_text(encoding="utf-8")

        self.assertIn("-----BEGIN PUBLIC KEY-----", content)
        self.assertIn("-----END PUBLIC KEY-----", content)

    def test_import_public_key_from_exported_pem(self):
        public_entry, _ = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        output_path = self.temp_path / "exported_public.pem"
        services.export_public_key(public_entry["key_id"], str(output_path))

        services.delete_public_key(public_entry["key_id"])

        imported_entry = services.import_public_key(
            file_path=str(output_path),
            user_name="Imported User",
            email="imported@example.com",
        )

        self.assertEqual(imported_entry["key_id"], public_entry["key_id"])
        self.assertEqual(imported_entry["user_name"], "Imported User")
        self.assertEqual(imported_entry["email"], "imported@example.com")
        self.assertIn(imported_entry["key_id"], storage.load_public_keyring(str(self.public_keyring_path)))

    def test_import_public_key_duplicate_raises_value_error(self):
        public_entry, _ = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        output_path = self.temp_path / "exported_public.pem"
        services.export_public_key(public_entry["key_id"], str(output_path))

        with self.assertRaises(ValueError):
            services.import_public_key(
                file_path=str(output_path),
                user_name="Duplicate User",
                email="duplicate@example.com",
            )

    def test_export_key_pair_creates_single_unencrypted_pem_file(self):
        public_entry, private_entry = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        output_path = self.temp_path / "exported_pair.pem"

        services.export_key_pair(
            key_id=private_entry["key_id"],
            unlock_password="test-password",
            file_path=str(output_path),
        )

        content = output_path.read_text(encoding="utf-8")

        self.assertIn("-----BEGIN PUBLIC KEY-----", content)
        self.assertIn("-----END PUBLIC KEY-----", content)
        self.assertIn("-----BEGIN PRIVATE KEY-----", content)
        self.assertIn("-----END PRIVATE KEY-----", content)
        self.assertNotIn("-----BEGIN ENCRYPTED PRIVATE KEY-----", content)

    def test_import_key_pair_from_exported_pair_pem(self):
        public_entry, private_entry = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="old-password",
        )

        output_path = self.temp_path / "exported_pair.pem"

        services.export_key_pair(
            key_id=private_entry["key_id"],
            unlock_password="old-password",
            file_path=str(output_path),
        )

        services.delete_key_pair(private_entry["key_id"])

        imported_public, imported_private = services.import_key_pair(
            file_path=str(output_path),
            user_name="Imported Pair",
            email="pair@example.com",
            private_key_pem_password=None,
            keyring_password="new-password",
        )

        self.assertEqual(imported_public["key_id"], public_entry["key_id"])
        self.assertEqual(imported_private["key_id"], private_entry["key_id"])
        self.assertEqual(imported_public["user_name"], "Imported Pair")
        self.assertEqual(imported_private["user_name"], "Imported Pair")

        unlocked_private_key = services.unlock_private_key(imported_private["key_id"], "new-password")

        self.assertIsInstance(unlocked_private_key, RSAPrivateKey)

    def test_import_key_pair_duplicate_raises_value_error(self):
        _, private_entry = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        output_path = self.temp_path / "exported_pair.pem"

        services.export_key_pair(
            key_id=private_entry["key_id"],
            unlock_password="test-password",
            file_path=str(output_path),
        )

        with self.assertRaises(ValueError):
            services.import_key_pair(
                file_path=str(output_path),
                user_name="Duplicate Pair",
                email="duplicate@example.com",
                private_key_pem_password=None,
                keyring_password="another-password",
            )

    def test_import_key_pair_requires_keyring_password(self):
        _, private_entry = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        output_path = self.temp_path / "exported_pair.pem"

        services.export_key_pair(
            key_id=private_entry["key_id"],
            unlock_password="test-password",
            file_path=str(output_path),
        )

        services.delete_key_pair(private_entry["key_id"])

        with self.assertRaises(ValueError):
            services.import_key_pair(
                file_path=str(output_path),
                user_name="Imported Pair",
                email="pair@example.com",
                private_key_pem_password=None,
                keyring_password="",
            )

    def test_import_key_pair_missing_private_block_raises_value_error(self):
        public_entry, _ = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        public_path = self.temp_path / "public_only.pem"
        services.export_public_key(public_entry["key_id"], str(public_path))

        services.delete_key_pair(public_entry["key_id"])

        with self.assertRaises(ValueError):
            services.import_key_pair(
                file_path=str(public_path),
                user_name="Missing Private",
                email="missing@example.com",
                private_key_pem_password=None,
                keyring_password="new-password",
            )

    def test_import_public_key_missing_public_block_raises_value_error(self):
        invalid_path = self.temp_path / "invalid.pem"
        invalid_path.write_text(
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            services.import_public_key(
                file_path=str(invalid_path),
                user_name="Invalid",
                email="invalid@example.com",
            )

    def test_delete_public_key_removes_only_public_entry(self):
        public_entry, private_entry = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        result = services.delete_public_key(public_entry["key_id"])

        self.assertTrue(result)
        self.assertIsNone(services.find_public_key(public_entry["key_id"]))
        self.assertIsNotNone(services.find_private_key(private_entry["key_id"]))

    def test_delete_key_pair_removes_public_and_private_entries(self):
        public_entry, private_entry = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        result = services.delete_key_pair(private_entry["key_id"])

        self.assertTrue(result)
        self.assertIsNone(services.find_public_key(public_entry["key_id"]))
        self.assertIsNone(services.find_private_key(private_entry["key_id"]))

    def test_delete_missing_keys_returns_false(self):
        self.assertFalse(services.delete_public_key("0011223344556677"))
        self.assertFalse(services.delete_key_pair("0011223344556677"))

    def test_returned_entries_are_deep_copies(self):
        public_entry, _ = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        found = services.find_public_key(public_entry["key_id"])
        found["user_name"] = "Changed"

        found_again = services.find_public_key(public_entry["key_id"])

        self.assertEqual(found_again["user_name"], "Petar Rancic")

    def test_keyring_reload_restores_persisted_entries(self):
        public_entry, private_entry = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        services._public_keyring = {}
        services._private_keyring = {}
        services._initialized = False

        services.initialize_keyrings()

        self.assertIsNotNone(services.find_public_key(public_entry["key_id"]))
        self.assertIsNotNone(services.find_private_key(private_entry["key_id"]))

    def test_key_id_to_hex_accepts_formatted_string(self):
        public_entry, _ = services.generate_key_pair(
            user_name="Petar Rancic",
            email="petar@example.com",
            key_size=1024,
            password="test-password",
        )

        key_id = public_entry["key_id"]
        formatted = f"{key_id[0:4]}:{key_id[4:8]}:{key_id[8:12]}:{key_id[12:16]}"

        found = services.find_public_key(formatted)

        self.assertIsNotNone(found)
        self.assertEqual(found["key_id"], key_id_to_hex(formatted))


if __name__ == "__main__":
    unittest.main()