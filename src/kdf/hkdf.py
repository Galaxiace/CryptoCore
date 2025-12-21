"""
Simplified HMAC-based key derivation for key hierarchies.
"""

from src.hash.sha256 import SHA256
import struct


def hmac_sha256_simple(key: bytes, message: bytes) -> bytes:
    """
    Simple HMAC-SHA256 implementation returning bytes.
    """
    block_size = 64  # SHA-256 block size

    # Process key
    if len(key) > block_size:
        # Hash key if it's too long
        hasher = SHA256()
        hasher.update(key)
        key = hasher.digest()

    # Pad key if needed
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))

    # Create inner and outer pads
    ipad = bytes(x ^ 0x36 for x in key)
    opad = bytes(x ^ 0x5C for x in key)

    # Inner hash
    inner_hasher = SHA256()
    inner_hasher.update(ipad)
    inner_hasher.update(message)
    inner_hash = inner_hasher.digest()

    # Outer hash
    outer_hasher = SHA256()
    outer_hasher.update(opad)
    outer_hasher.update(inner_hash)

    return outer_hasher.digest()


def derive_key(master_key: bytes, context: str, length: int = 32) -> bytes:
    """
    Derive a key from a master key using a deterministic HMAC-based method.

    Args:
        master_key: Master key as bytes
        context: Context string (e.g., "encryption", "authentication")
        length: Desired key length in bytes

    Returns:
        Derived key as bytes
    """
    if isinstance(context, str):
        context = context.encode('utf-8')

    derived = b''
    counter = 1

    while len(derived) < length:
        # T_i = HMAC(master_key, context || counter)
        block_input = context + struct.pack('>I', counter)
        block = hmac_sha256_simple(master_key, block_input)
        derived += block
        counter += 1

    # Return exactly the requested length
    return derived[:length]


def derive_key_hex(master_key: bytes, context: str, length: int = 32) -> str:
    """
    Convenience function returning hex string.
    """
    result = derive_key(master_key, context, length)
    return result.hex()