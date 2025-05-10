import base64
from hashlib import shake_256
import hmac, hashlib, secrets

def int_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def bytes_to_Base64(n: bytes) -> str:
    return base64.b64encode(n).decode()

def Base64_to_bytes(n: str) -> bytes:
    return base64.b64decode(n)

def str_to_bytes(s: str) -> bytes:
    return s.encode('utf-8')

def bytes_to_str(b: bytes) -> str:
    return b.decode('utf-8')

def print_large_int_sci(x, digits=5):
    s = str(x)
    exponent = len(s) - 1
    mantissa = s[:digits]
    return f"{mantissa[0]}.{mantissa[1:]}e+{exponent}"

def generate_keystream(secret_bytes: bytes, length: int, nonce: bytes = b"") -> bytes:
    return shake_256(nonce + secret_bytes).digest(length)

def xor_bytes(b64_bytes: bytes, keystream: bytes) -> bytes:
    return bytes(m ^ k for m, k in zip(b64_bytes, keystream))

def create_mac(key_bytes: bytes, blob: bytes):
    return hmac.new(key_bytes, blob, hashlib.sha256).hexdigest()

def verify_mac(secret_bytes: bytes, data: bytes, mac: str) -> bool:
    return hmac.compare_digest(create_mac(secret_bytes, data), mac)