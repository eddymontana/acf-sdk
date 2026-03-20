import struct
import os

MAGIC_BYTE = 0xAC
VERSION = 0x01

def create_frame(payload: bytes, hmac_key: bytes) -> bytes:
    # 1. Generate Nonce
    nonce = os.urandom(16)
    
    # 2. Length of payload
    length = len(payload)
    
    # 3. Dummy HMAC (We will implement the real HMAC-SHA256 next)
    hmac_placeholder = b'\x00' * 32 
    
    # 4. Pack into Binary: Magic(B), Version(B), Length(I), Nonce(16s), HMAC(32s)
    header = struct.pack(">BB I 16s 32s", MAGIC_BYTE, VERSION, length, nonce, hmac_placeholder)
    
    return header + payload