import unittest
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PROJECT_ROOT = Path(__file__).resolve().parents[1]
API_DIR = PROJECT_ROOT / "api"

for path in (API_DIR, PROJECT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from encryption_services import encrypt_message
from output_utils import (
    crc24,
    decode_radix64,
    deserialize_final_packet,
    encode_radix64,
    serialize_final_packet,
)


class TestOutputUtils(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()
        cls.expected_key_id = cls.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )[-8:]
        cls.plain_packet = {"data": b"compressed-payload"}

    def test_serialize_deserialize_plain_packet(self):
        serialized = serialize_final_packet(self.plain_packet, False)
        unpacked = deserialize_final_packet(serialized)

        self.assertEqual(serialized[0], 0x00)
        self.assertEqual(unpacked, {"data": b"compressed-payload"})

    def test_serialize_deserialize_encrypted_packet_with_aes128(self):
        encrypted_packet = encrypt_message(
            compressed_bytes=b"\x00hello-world",
            receiver_public_key=self.public_key,
            symmetric_algo="AES128",
        )

        serialized = serialize_final_packet(encrypted_packet, True)
        unpacked = deserialize_final_packet(serialized)

        self.assertEqual(serialized[0], 0x01)
        self.assertEqual(unpacked["receiver_key_id"], self.expected_key_id)
        self.assertEqual(unpacked["symmetric_algo"], "AES128")
        self.assertEqual(unpacked["session_key"], encrypted_packet["session_key"])
        self.assertEqual(unpacked["encrypted_data"], encrypted_packet["encrypted_data"])

    def test_serialize_deserialize_encrypted_packet_with_cast5(self):
        encrypted_packet = encrypt_message(
            compressed_bytes=b"test-cast5-payload",
            receiver_public_key=self.public_key,
            symmetric_algo="Cast5",
        )

        serialized = serialize_final_packet(encrypted_packet, True)
        unpacked = deserialize_final_packet(serialized)

        self.assertEqual(unpacked["receiver_key_id"], self.expected_key_id)
        self.assertEqual(unpacked["symmetric_algo"], "Cast5")
        self.assertEqual(unpacked["session_key"], encrypted_packet["session_key"])
        self.assertEqual(unpacked["encrypted_data"], encrypted_packet["encrypted_data"])

    def test_serialize_final_packet_rejects_unsupported_algorithm(self):
        packet = {
            "receiver_key_id": self.expected_key_id,
            "session_key": b"0123456789abcdef",
            "symmetric_algo": "3DES",
            "encrypted_data": b"payload-bytes",
        }

        with self.assertRaises(ValueError):
            serialize_final_packet(packet, True)

    def test_crc24_returns_24_bit_value(self):
        value = crc24(b"test-data")

        self.assertIsInstance(value, int)
        self.assertGreaterEqual(value, 0x000000)
        self.assertLessEqual(value, 0xFFFFFF)

    def test_encode_radix64_contains_pgp_headers_and_checksum(self):
        serialized = serialize_final_packet(self.plain_packet, False)
        armored = encode_radix64(serialized)

        self.assertTrue(armored.startswith("-----BEGIN PGP MESSAGE-----"))
        self.assertTrue(armored.endswith("-----END PGP MESSAGE-----\n"))
        self.assertIn("\n=", armored)

    def test_encode_decode_radix64_plain_packet_roundtrip(self):
        serialized = serialize_final_packet(self.plain_packet, False)
        armored = encode_radix64(serialized)
        decoded = decode_radix64(armored)
        unpacked = deserialize_final_packet(decoded)

        self.assertEqual(decoded, serialized)
        self.assertEqual(unpacked, self.plain_packet)

    def test_encode_decode_radix64_encrypted_packet_roundtrip(self):
        encrypted_packet = encrypt_message(
            compressed_bytes=b"\x00hello-world",
            receiver_public_key=self.public_key,
            symmetric_algo="AES128",
        )

        serialized = serialize_final_packet(encrypted_packet, True)
        armored = encode_radix64(serialized)
        decoded = decode_radix64(armored)
        unpacked = deserialize_final_packet(decoded)

        self.assertEqual(decoded, serialized)
        self.assertEqual(unpacked["receiver_key_id"], encrypted_packet["receiver_key_id"])
        self.assertEqual(unpacked["symmetric_algo"], encrypted_packet["symmetric_algo"])
        self.assertEqual(unpacked["session_key"], encrypted_packet["session_key"])
        self.assertEqual(unpacked["encrypted_data"], encrypted_packet["encrypted_data"])

    def test_decode_radix64_rejects_missing_begin_header(self):
        serialized = serialize_final_packet(self.plain_packet, False)
        armored = encode_radix64(serialized)
        malformed = armored.replace("-----BEGIN PGP MESSAGE-----", "")

        with self.assertRaises(ValueError):
            decode_radix64(malformed)

    def test_decode_radix64_rejects_missing_end_footer(self):
        serialized = serialize_final_packet(self.plain_packet, False)
        armored = encode_radix64(serialized)
        malformed = armored.replace("-----END PGP MESSAGE-----", "")

        with self.assertRaises(ValueError):
            decode_radix64(malformed)

    def test_decode_radix64_rejects_missing_checksum(self):
        serialized = serialize_final_packet(self.plain_packet, False)
        armored = encode_radix64(serialized)
        lines = armored.splitlines()
        malformed = "\n".join(line for line in lines if not line.startswith("="))

        with self.assertRaises(ValueError):
            decode_radix64(malformed)

    def test_decode_radix64_rejects_bad_base64_content(self):
        malformed = (
            "-----BEGIN PGP MESSAGE-----\n\n"
            "not-valid-base64!!!\n"
            "=AAAA\n"
            "-----END PGP MESSAGE-----\n"
        )

        with self.assertRaises(ValueError):
            decode_radix64(malformed)

    def test_decode_radix64_rejects_checksum_mismatch(self):
        serialized = serialize_final_packet(self.plain_packet, False)
        armored = encode_radix64(serialized)
        lines = armored.splitlines()
        malformed_lines = []

        for line in lines:
            if line.startswith("="):
                malformed_lines.append("=AAAA")
            else:
                malformed_lines.append(line)

        malformed = "\n".join(malformed_lines)

        with self.assertRaises(ValueError):
            decode_radix64(malformed)


if __name__ == "__main__":
    unittest.main()