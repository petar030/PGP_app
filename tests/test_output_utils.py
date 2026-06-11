import unittest

from cryptography.hazmat.primitives.asymmetric import rsa

from api.encryption_services import encrypt_message
from api.output_utils import (
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
        cls.encrypted_packet = {
            "receiver_key_id": "ABCDEFGH",
            "session_key": b"0123456789abcdef",
            "symmetric_algo": "AES128",
            "encrypted_data": b"payload-bytes",
        }
        cls.compressed_packet = {"compressed_data": b"compressed-payload"}

    def test_serialize_deserialize_encrypted_packet(self):
        serialized = serialize_final_packet(self.encrypted_packet, True)
        unpacked = deserialize_final_packet(serialized)

        self.assertTrue(unpacked["is_encrypted"])
        self.assertEqual(unpacked["version"], 1)
        self.assertEqual(unpacked["receiver_key_id"], self.encrypted_packet["receiver_key_id"])
        self.assertEqual(unpacked["session_key"], self.encrypted_packet["session_key"])
        self.assertEqual(unpacked["symmetric_algo"], self.encrypted_packet["symmetric_algo"])
        self.assertEqual(unpacked["encrypted_data"], self.encrypted_packet["encrypted_data"])

    def test_serialize_deserialize_plain_packet(self):
        serialized = serialize_final_packet(self.compressed_packet, False)
        unpacked = deserialize_final_packet(serialized)

        self.assertFalse(unpacked["is_encrypted"])
        self.assertEqual(unpacked["version"], 1)
        self.assertEqual(unpacked["payload"], self.compressed_packet["compressed_data"])
        self.assertEqual(unpacked["compressed_data"], self.compressed_packet["compressed_data"])

    def test_radix64_roundtrip(self):
        armored = encode_radix64(self.encrypted_packet, True)
        decoded = decode_radix64(armored)
        serialized = serialize_final_packet(self.encrypted_packet, True)

        self.assertEqual(decoded, serialized)

    def test_roundtrip_with_real_encrypt_message_output(self):
        encrypted_packet = encrypt_message(
            compressed_bytes=b"\x00hello-world",
            receiver_public_key=self.public_key,
            receiver_key_id="ABCDEFGH",
            symmetric_algo="AES128",
        )

        serialized = serialize_final_packet(encrypted_packet, True)
        unpacked = deserialize_final_packet(serialized)

        self.assertEqual(unpacked["receiver_key_id"], "ABCDEFGH")
        self.assertEqual(unpacked["symmetric_algo"], "AES128")
        self.assertEqual(unpacked["encrypted_data"], encrypted_packet["encrypted_data"])


if __name__ == "__main__":
    unittest.main()