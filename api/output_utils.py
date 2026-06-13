import os

from .encryption_services import SUPPORTED_CIPHERS
from .encryption_services import encrypt_message

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import base64
import textwrap


PGP_BEGIN = "-----BEGIN PGP MESSAGE-----"
PGP_END = "-----END PGP MESSAGE-----"

def serialize_final_packet(data_dict: dict, is_encrypted: bool) -> bytes:
    """Serialize data into bytes for output."""
    
    if not is_encrypted:
        return b'\x00' + data_dict['data']    

    serialized_data = bytearray()
    # Append the encryption flag
    serialized_data.append(0x01)  # Flag for encrypted data
    # Append the receiver key ID (8B)
    serialized_data.extend(data_dict['receiver_key_id'])
    # Append symmetric algorithm (1B)
    if data_dict['symmetric_algo'] == 'AES128':
        serialized_data.append(0x00)
    elif data_dict['symmetric_algo'] == 'Cast5':
        serialized_data.append(0x01)
    else:
        raise ValueError(f"Unsupported symmetric algorithm: {data_dict['symmetric_algo']}")  
    # Append the encrypted session key length
    serialized_data.extend(len(data_dict['session_key']).to_bytes(2, 'big'))
    # Append the encrypted session key
    serialized_data.extend(data_dict['session_key'])
    # Append the encrypted data
    serialized_data.extend(data_dict['encrypted_data'])

    return bytes(serialized_data)


def deserialize_final_packet(serialized_packet: bytes) -> dict:
    """Parses the binary stream and reconstructs the data dictionary."""
    
    is_encrypted = serialized_packet[0] == 0x01
    
    if not is_encrypted:
        return {'data': serialized_packet[1:]}

    offset = 1
    
    receiver_key_id = serialized_packet[offset : offset + 8]
    offset += 8
    
    algo_id = serialized_packet[offset]
    offset += 1
    
    symmetric_algo = 'AES128' if algo_id == 0x00 else 'Cast5'
    
    session_key_len = int.from_bytes(serialized_packet[offset : offset + 2], 'big')
    offset += 2
    
    session_key = serialized_packet[offset : offset + session_key_len]
    offset += session_key_len
    
    encrypted_data = serialized_packet[offset:]
    
    return {
        "receiver_key_id": receiver_key_id,
        "symmetric_algo": symmetric_algo,
        "session_key": session_key,
        "encrypted_data": encrypted_data
    }


def crc24(data: bytes) -> int:
    crc = 0xB704CE

    for byte in data:
        crc ^= byte << 16

        for _ in range(8):
            crc <<= 1

            if crc & 0x1000000:
                crc ^= 0x1864CFB

    return crc & 0xFFFFFF


def encode_radix64(serialized_data: bytes) -> str:
    encoded = base64.b64encode(serialized_data).decode("ascii")
    wrapped = "\n".join(textwrap.wrap(encoded, 64))
    checksum = base64.b64encode(crc24(serialized_data).to_bytes(3, "big")).decode("ascii")

    return f"{PGP_BEGIN}\n\n{wrapped}\n={checksum}\n{PGP_END}\n"


def decode_radix64(armored_message: str) -> bytes:
    text = armored_message.strip()

    if not text.startswith(PGP_BEGIN):
        raise ValueError("Invalid radix-64 message: missing BEGIN header")

    if not text.endswith(PGP_END):
        raise ValueError("Invalid radix-64 message: missing END footer")

    body = text[len(PGP_BEGIN):text.rfind(PGP_END)]
    lines = body.strip().splitlines()

    base64_lines = []
    checksum_line = None

    for line in lines:
        line = line.strip()

        if not line:
            continue

        if line.startswith("="):
            checksum_line = line[1:]
        else:
            base64_lines.append(line)

    if checksum_line is None:
        raise ValueError("Invalid radix-64 message: missing checksum")

    encoded = "".join(base64_lines)

    try:
        decoded = base64.b64decode(encoded, validate=True)
    except Exception as e:
        raise ValueError("Invalid radix-64 message: bad Base64 content") from e

    expected_checksum = base64.b64encode(crc24(decoded).to_bytes(3, "big")).decode("ascii")

    if checksum_line != expected_checksum:
        raise ValueError("Invalid radix-64 message: checksum mismatch")

    return decoded

if __name__ == "__main__":
    
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    data_dict = encrypt_message(
        compressed_bytes=b"\x00hello-world",receiver_public_key=public_key, symmetric_algo="AES128")
    
    serialized = serialize_final_packet(data_dict, True)
    deserialized = deserialize_final_packet(serialized)
    
    # Provera polje po polje jer se tipovi (bytes/str) moraju poklapati
    if (deserialized["receiver_key_id"] == data_dict["receiver_key_id"] and
        deserialized["symmetric_algo"] == data_dict["symmetric_algo"] and
        deserialized["session_key"] == data_dict["session_key"] and
        deserialized["encrypted_data"] == data_dict["encrypted_data"]):
        print("Serialization and deserialization successful!")
    else:
        print("Mismatch in serialization/deserialization.")