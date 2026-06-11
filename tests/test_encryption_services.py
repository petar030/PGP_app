import unittest
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric import rsa

# Support direct execution from tests/ and discovery from project root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.encryption_services import decrypt_message, encrypt_message


class TestEncryptionServices(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Generate one RSA keypair and reusable payload for all tests."""
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()
        cls.key_id = "ETF_ETF_2026_ID"
        cls.mock_compressed_bytes = b"\x01Pozdrav sa ETF-a! Ovo je tajna PGP poruka."

    def test_encrypt_decrypt_roundtrip_aes128(self):
        encrypted_res = encrypt_message(
            compressed_bytes=self.mock_compressed_bytes,
            receiver_public_key=self.public_key,
            receiver_key_id=self.key_id,
            symmetric_algo="AES128",
        )

        self.assertEqual(encrypted_res["receiver_key_id"], self.key_id)
        self.assertEqual(encrypted_res["symmetric_algo"], "AES128")
        self.assertIsInstance(encrypted_res["session_key"], bytes)
        self.assertIsInstance(encrypted_res["encrypted_data"], bytes)

        decrypted_res = decrypt_message(
            encrypted_message=encrypted_res,
            receiver_private_key=self.private_key,
        )

        self.assertEqual(decrypted_res["decrypted_data"], self.mock_compressed_bytes)
        self.assertEqual(decrypted_res["receiver_key_id"], self.key_id)
        self.assertEqual(decrypted_res["symmetric_algo"], "AES128")

    def test_encrypt_decrypt_roundtrip_cast5(self):
        encrypted_res = encrypt_message(
            compressed_bytes=self.mock_compressed_bytes,
            receiver_public_key=self.public_key,
            receiver_key_id=self.key_id,
            symmetric_algo="Cast5",
        )

        self.assertEqual(encrypted_res["symmetric_algo"], "Cast5")

        decrypted_res = decrypt_message(
            encrypted_message=encrypted_res,
            receiver_private_key=self.private_key,
        )

        self.assertEqual(decrypted_res["decrypted_data"], self.mock_compressed_bytes)

    def test_rejects_unsupported_algorithm(self):
        with self.assertRaises(ValueError):
            encrypt_message(
                compressed_bytes=self.mock_compressed_bytes,
                receiver_public_key=self.public_key,
                receiver_key_id=self.key_id,
                symmetric_algo="3DES",
            )

    def test_encrypted_payload_contains_iv_prefix(self):
        encrypted_res = encrypt_message(
            compressed_bytes=self.mock_compressed_bytes,
            receiver_public_key=self.public_key,
            receiver_key_id=self.key_id,
            symmetric_algo="AES128",
        )

        # AES block size is 16 bytes, so ciphertext should be larger than IV.
        self.assertGreater(len(encrypted_res["encrypted_data"]), 16)


if __name__ == "__main__":
    unittest.main()