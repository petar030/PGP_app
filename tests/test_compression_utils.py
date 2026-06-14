import unittest
from pathlib import Path
import sys
import pickle
import zlib

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from rsa_keyring.keyring_utils import calculate_key_id_hex

# Support direct execution from tests/ and discovery from project root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.compression_utils import compress_data, decompress_data
from api.auth_services import (
    create_message_component,
    sign_message,
    verify_signature,
)


class TestCompressionUtils(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Generate one RSA keypair for all tests."""
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()
        cls.sender_key_id = calculate_key_id_hex(cls.public_key)

    def test_compress_unsigned_uncompressed_data(self):
        """Test compressing unsigned, uncompressed data."""
        msg_comp = create_message_component(data="Test poruka", filename="test.txt")

        compressed = compress_data(
            packet=msg_comp, is_signed=False, perform_compression=False
        )

        self.assertIsInstance(compressed, bytes)
        self.assertGreater(len(compressed), 0)
        # Check header flags
        self.assertEqual(compressed[0], 0x00)  # No compression
        self.assertEqual(compressed[1], 0x00)  # Not signed

    def test_compress_unsigned_compressed_data(self):
        """Test compressing unsigned, compressed data."""
        msg_comp = create_message_component(data="Test poruka", filename="test.txt")

        compressed = compress_data(
            packet=msg_comp, is_signed=False, perform_compression=True
        )

        self.assertIsInstance(compressed, bytes)
        self.assertGreater(len(compressed), 0)
        # Check header flags
        self.assertEqual(compressed[0], 0x01)  # Compressed
        self.assertEqual(compressed[1], 0x00)  # Not signed

    def test_compress_signed_uncompressed_data(self):
        """Test compressing signed, uncompressed data."""
        msg_comp = create_message_component(data="Potpisana poruka", filename="signed.txt")

        signed_packet = sign_message(
            message_component=msg_comp,
            sender_private_key=self.private_key,
            sender_key_id=self.sender_key_id,
        )

        compressed = compress_data(
            packet=signed_packet, is_signed=True, perform_compression=False
        )

        self.assertIsInstance(compressed, bytes)
        # Check header flags
        self.assertEqual(compressed[0], 0x00)  # No compression
        self.assertEqual(compressed[1], 0x01)  # Signed

    def test_compress_signed_compressed_data(self):
        """Test compressing signed, compressed data."""
        msg_comp = create_message_component(data="Potpisana i komprimovana", filename="both.txt")

        signed_packet = sign_message(
            message_component=msg_comp,
            sender_private_key=self.private_key,
            sender_key_id=self.sender_key_id,
        )

        compressed = compress_data(
            packet=signed_packet, is_signed=True, perform_compression=True
        )

        self.assertIsInstance(compressed, bytes)
        # Check header flags
        self.assertEqual(compressed[0], 0x01)  # Compressed
        self.assertEqual(compressed[1], 0x01)  # Signed

    def test_decompress_unsigned_uncompressed_data(self):
        """Test decompressing unsigned, uncompressed data."""
        msg_comp = create_message_component(data="Originalna poruka", filename="original.txt")

        compressed = compress_data(
            packet=msg_comp, is_signed=False, perform_compression=False
        )

        decompressed = decompress_data(compressed_bytes=compressed)

        self.assertEqual(decompressed["filename"], "original.txt")
        self.assertEqual(decompressed["data"], b"Originalna poruka")

    def test_decompress_unsigned_compressed_data(self):
        """Test decompressing unsigned, compressed data."""
        msg_comp = create_message_component(data="Komprimovana poruka", filename="compressed.txt")

        compressed = compress_data(
            packet=msg_comp, is_signed=False, perform_compression=True
        )

        decompressed = decompress_data(compressed_bytes=compressed)

        self.assertEqual(decompressed["filename"], "compressed.txt")
        self.assertEqual(decompressed["data"], b"Komprimovana poruka")

    def test_compress_decompress_unsigned_roundtrip(self):
        """Test compress -> decompress roundtrip for unsigned data."""
        original_data = "Test podatka za roundtrip"
        original_filename = "roundtrip.txt"

        msg_comp = create_message_component(data=original_data, filename=original_filename)

        compressed = compress_data(
            packet=msg_comp, is_signed=False, perform_compression=True
        )

        decompressed = decompress_data(compressed_bytes=compressed)

        self.assertEqual(decompressed["filename"], original_filename)
        self.assertEqual(decompressed["data"], original_data.encode("utf-8"))
        self.assertEqual(decompressed["timestamp"], msg_comp["timestamp"])

    def test_compress_decompress_signed_roundtrip(self):
        """Test compress -> decompress roundtrip for signed data."""
        original_data = "Potpisana poruka za kompresiju"
        original_filename = "signed_compressed.txt"

        msg_comp = create_message_component(data=original_data, filename=original_filename)

        signed_packet = sign_message(
            message_component=msg_comp,
            sender_private_key=self.private_key,
            sender_key_id=self.sender_key_id,
        )

        compressed = compress_data(
            packet=signed_packet, is_signed=True, perform_compression=True
        )

        decompressed = decompress_data(compressed_bytes=compressed)

        # Verify it's still signed and intact
        verified = verify_signature(
            signed_packet=decompressed, sender_public_key=self.public_key
        )

        self.assertTrue(verified["is_valid"])
        self.assertEqual(verified["message_comp"]["filename"], original_filename)
        self.assertEqual(verified["message_comp"]["data"], original_data.encode("utf-8"))

    def test_decompress_with_invalid_compression_flag(self):
        """Test decompression with invalid compression flag."""
        # Create manually constructed invalid data
        header = bytearray()
        header.append(0xFF)  # Invalid compression flag
        header.append(0x00)  # Not signed

        payload = b"some payload"
        invalid_data = bytes(header + payload)

        with self.assertRaises(ValueError) as context:
            decompress_data(compressed_bytes=invalid_data)

        self.assertIn("Nepoznat fleg za kompresiju", str(context.exception))

    def test_decompress_with_invalid_signed_flag(self):
        """Test decompression with invalid signed flag."""
        # Create manually constructed invalid data
        header = bytearray()
        header.append(0x00)  # Not compressed
        header.append(0xFF)  # Invalid signed flag

        payload = pickle.dumps({"filename": "test.txt", "timestamp": 123, "data": b"test"})
        invalid_data = bytes(header + payload)

        with self.assertRaises(ValueError) as context:
            decompress_data(compressed_bytes=invalid_data)

        self.assertIn("Nepoznat fleg za potpis", str(context.exception))

    def test_decompress_too_short_data(self):
        """Test decompression with data that is too short."""
        short_data = b"\x00"  # Only one byte, needs at least 2

        with self.assertRaises(ValueError) as context:
            decompress_data(compressed_bytes=short_data)

        self.assertIn("Podaci su prekratki", str(context.exception))

    def test_decompress_missing_keys_unsigned_packet(self):
        """Test decompression fails if unsigned packet missing required keys."""
        # Create invalid unsigned packet manually
        invalid_packet = {"filename": "test.txt"}  # Missing timestamp and data

        serialized = pickle.dumps(invalid_packet)
        header = bytearray([0x00, 0x00])  # Not compressed, not signed
        invalid_data = bytes(header + serialized)

        with self.assertRaises(TypeError) as context:
            decompress_data(compressed_bytes=invalid_data)

        self.assertIn("Očekivana je obična poruka", str(context.exception))

    def test_decompress_missing_keys_signed_packet(self):
        """Test decompression fails if signed packet missing required keys."""
        # Create invalid signed packet manually
        invalid_packet = {
            "sender_key_id": "test_key",
            # Missing sig_timestamp, encrypted_hash, message_comp
        }

        serialized = pickle.dumps(invalid_packet)
        header = bytearray([0x00, 0x01])  # Not compressed, is signed
        invalid_data = bytes(header + serialized)

        with self.assertRaises(TypeError) as context:
            decompress_data(compressed_bytes=invalid_data)

        self.assertIn("Očekivan je potpisani paket", str(context.exception))

    def test_compress_with_large_data(self):
        """Test compression with large data to verify compression efficiency."""
        # Create a large message
        large_data = "A" * 10000

        msg_comp = create_message_component(data=large_data, filename="large.txt")

        compressed_no_zip = compress_data(
            packet=msg_comp, is_signed=False, perform_compression=False
        )
        compressed_with_zip = compress_data(
            packet=msg_comp, is_signed=False, perform_compression=True
        )

        # Compressed data should be significantly smaller
        self.assertLess(len(compressed_with_zip), len(compressed_no_zip))

        # Verify roundtrip
        decompressed = decompress_data(compressed_bytes=compressed_with_zip)
        self.assertEqual(decompressed["data"], large_data.encode("utf-8"))

    def test_compress_decompress_multiple_roundtrips(self):
        """Test multiple compress/decompress cycles with auth_services integration."""
        for i in range(5):
            original_data = f"Poruka broj {i}: Testiranje vise puta"
            msg_comp = create_message_component(data=original_data, filename=f"msg_{i}.txt")

            signed_packet = sign_message(
                message_component=msg_comp,
                sender_private_key=self.private_key,
                sender_key_id=self.sender_key_id,
            )

            compressed = compress_data(
                packet=signed_packet, is_signed=True, perform_compression=True
            )

            decompressed = decompress_data(compressed_bytes=compressed)

            verified = verify_signature(
                signed_packet=decompressed, sender_public_key=self.public_key
            )

            self.assertTrue(verified["is_valid"])
            self.assertEqual(verified["message_comp"]["data"], original_data.encode("utf-8"))

    def test_compression_header_structure(self):
        """Test the structure of compression header."""
        msg_comp = create_message_component(data="Header test", filename="header.txt")

        # Test all combinations: (perform_compression, is_signed, expected_comp, expected_sign)
        test_cases = [
            (False, False, 0x00, 0x00),
            (True, False, 0x01, 0x00),
            (False, True, 0x00, 0x01),
            (True, True, 0x01, 0x01),
        ]

        for perform_compression, is_signed, expected_comp, expected_sign in test_cases:
            signed_packet = (
                sign_message(
                    message_component=msg_comp,
                    sender_private_key=self.private_key,
                    sender_key_id=self.sender_key_id,
                )
                if is_signed
                else msg_comp
            )

            compressed = compress_data(
                packet=signed_packet,
                is_signed=is_signed,
                perform_compression=perform_compression,
            )

            self.assertEqual(
                compressed[0],
                expected_comp,
                f"Compression flag mismatch for {perform_compression}, {is_signed}",
            )
            self.assertEqual(
                compressed[1],
                expected_sign,
                f"Signed flag mismatch for {perform_compression}, {is_signed}",
            )


if __name__ == "__main__":
    unittest.main()