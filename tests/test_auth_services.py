import unittest
from pathlib import Path
import sys
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from rsa_keyring.keyring_utils import calculate_key_id_hex

# Support direct execution from tests/ and discovery from project root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.auth_services import (
    create_message_component,
    extract_message_component,
    sign_message,
    verify_signature,
)


class TestAuthServices(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Generate one RSA keypair for all tests."""
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()
        cls.sender_key_id = calculate_key_id_hex(cls.public_key)

    def test_create_message_component(self):
        """Test creating a message component."""
        test_data = "Hello, World!"
        test_filename = "test.txt"

        msg_comp = create_message_component(data=test_data, filename=test_filename)

        self.assertEqual(msg_comp["filename"], test_filename)
        self.assertEqual(msg_comp["data"], test_data.encode("utf-8"))
        self.assertIsInstance(msg_comp["timestamp"], float)
        self.assertGreater(msg_comp["timestamp"], 0)

    def test_create_message_component_with_unicode(self):
        """Test creating a message component with unicode characters."""
        test_data = "Привет, мир! 你好，世界！"
        test_filename = "unicode_test.txt"

        msg_comp = create_message_component(data=test_data, filename=test_filename)

        self.assertEqual(msg_comp["filename"], test_filename)
        self.assertEqual(msg_comp["data"], test_data.encode("utf-8"))

    def test_extract_message_component(self):
        """Test extracting a message component."""
        test_data = "Tajna poruka"
        test_filename = "secret.txt"

        msg_comp = create_message_component(data=test_data, filename=test_filename)
        extracted = extract_message_component(packed_message=msg_comp)

        self.assertEqual(extracted["filename"], test_filename)
        self.assertEqual(extracted["data"], test_data)
        self.assertEqual(extracted["timestamp"], msg_comp["timestamp"])

    def test_message_component_roundtrip(self):
        """Test create -> extract roundtrip."""
        original_data = "Ovo je test poruka za PGP"
        original_filename = "poruka.txt"

        msg_comp = create_message_component(data=original_data, filename=original_filename)
        extracted = extract_message_component(packed_message=msg_comp)

        self.assertEqual(extracted["data"], original_data)
        self.assertEqual(extracted["filename"], original_filename)

    def test_sign_message(self):
        """Test signing a message."""
        msg_comp = create_message_component(data="Poruka za potpisivanje", filename="signed.txt")

        signed_packet = sign_message(
            message_component=msg_comp,
            sender_private_key=self.private_key,
            sender_key_id=self.sender_key_id,
        )

        self.assertEqual(signed_packet["sender_key_id"], self.sender_key_id)
        self.assertIsInstance(signed_packet["sig_timestamp"], float)
        self.assertIsInstance(signed_packet["leading_octets"], bytes)
        self.assertEqual(len(signed_packet["leading_octets"]), 2)
        self.assertIsInstance(signed_packet["encrypted_hash"], bytes)
        self.assertEqual(signed_packet["message_comp"], msg_comp)

    def test_verify_signature_valid(self):
        """Test verifying a valid signature."""
        msg_comp = create_message_component(
            data="Poruka sa validnim potpisom", filename="valid.txt"
        )

        signed_packet = sign_message(
            message_component=msg_comp,
            sender_private_key=self.private_key,
            sender_key_id=self.sender_key_id,
        )

        verified = verify_signature(
            signed_packet=signed_packet, sender_public_key=self.public_key
        )

        self.assertTrue(verified["is_valid"])
        self.assertEqual(verified["sender_key_id"], self.sender_key_id)
        self.assertEqual(verified["message_comp"]["filename"], "valid.txt")
        self.assertEqual(verified["message_comp"]["data"], b"Poruka sa validnim potpisom")

    def test_sign_and_verify_roundtrip(self):
        """Test complete sign -> verify roundtrip."""
        original_data = "Potpisan i verifikovan tekst"
        original_filename = "roundtrip.txt"

        msg_comp = create_message_component(data=original_data, filename=original_filename)

        signed_packet = sign_message(
            message_component=msg_comp,
            sender_private_key=self.private_key,
            sender_key_id=self.sender_key_id,
        )

        verified = verify_signature(
            signed_packet=signed_packet, sender_public_key=self.public_key
        )

        self.assertTrue(verified["is_valid"])
        self.assertEqual(verified["message_comp"]["data"], original_data.encode("utf-8"))
        self.assertEqual(verified["message_comp"]["filename"], original_filename)

    def test_verify_signature_with_wrong_key_fails(self):
        """Test that verification fails with wrong key."""
        msg_comp = create_message_component(data="Greska test", filename="error.txt")

        signed_packet = sign_message(
            message_component=msg_comp,
            sender_private_key=self.private_key,
            sender_key_id=self.sender_key_id,
        )

        # Generate a different keypair
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

        with self.assertRaises(ValueError) as context:
            verify_signature(signed_packet=signed_packet, sender_public_key=wrong_key)

        self.assertIn("Verifikacija potpisa nije uspela", str(context.exception))

    def test_verify_signature_with_tampered_data_fails(self):
        """Test that verification fails if data is tampered."""
        msg_comp = create_message_component(data="Originalna poruka", filename="tamper.txt")

        signed_packet = sign_message(
            message_component=msg_comp,
            sender_private_key=self.private_key,
            sender_key_id=self.sender_key_id,
        )

        # Tamper with the data
        signed_packet["message_comp"]["data"] = b"Promenjena poruka"

        with self.assertRaises(ValueError) as context:
            verify_signature(signed_packet=signed_packet, sender_public_key=self.public_key)

        self.assertIn("Integritet poruke narušen", str(context.exception))

    def test_signature_contains_required_fields(self):
        """Test that signed packet contains all required fields."""
        msg_comp = create_message_component(data="Test", filename="test.txt")

        signed_packet = sign_message(
            message_component=msg_comp,
            sender_private_key=self.private_key,
            sender_key_id=self.sender_key_id,
        )

        required_keys = [
            "sender_key_id",
            "sig_timestamp",
            "leading_octets",
            "encrypted_hash",
            "message_comp",
        ]

        for key in required_keys:
            self.assertIn(key, signed_packet)

    def test_create_message_component_with_empty_string(self):
        """Test creating a message component with empty string."""
        msg_comp = create_message_component(data="", filename="empty.txt")

        self.assertEqual(msg_comp["data"], b"")
        self.assertEqual(msg_comp["filename"], "empty.txt")

    def test_create_message_component_with_special_characters(self):
        """Test creating a message component with special characters."""
        special_data = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        msg_comp = create_message_component(data=special_data, filename="special.txt")

        extracted = extract_message_component(packed_message=msg_comp)
        self.assertEqual(extracted["data"], special_data)


if __name__ == "__main__":
    unittest.main()