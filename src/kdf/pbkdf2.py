"""
PBKDF2-HMAC-SHA256 - Implementation following RFC 2898
Uses HMAC from Sprint 5 as required.
"""

import struct
from src.mac.hmac import HMAC


def pbkdf2_hmac_sha256(password, salt, iterations, dklen):
    """
    PBKDF2-HMAC-SHA256 implementation following RFC 2898.

    Uses HMAC-SHA256 implementation from Sprint 5 as required.

    Args:
        password: Password (bytes or string)
        salt: Salt (bytes or string, hex string is converted to bytes)
        iterations: Number of iterations
        dklen: Desired key length in bytes

    Returns:
        Derived key as bytes
    """
    # === CONVERT INPUTS TO BYTES ===
    # Convert password to bytes if needed
    if isinstance(password, str):
        password_bytes = password.encode('utf-8')
    else:
        password_bytes = password

    # Convert salt to bytes if needed
    if isinstance(salt, str):
        # Check if it's hex string
        try:
            salt_bytes = bytes.fromhex(salt)
        except ValueError:
            # Treat as raw string
            salt_bytes = salt.encode('utf-8')
    else:
        salt_bytes = salt

    # === CREATE HMAC ONCE ===
    hmac = HMAC(password_bytes)

    # === PRE-CALCULATIONS ===
    hlen = 32  # SHA-256 output length = 32 bytes
    blocks_needed = (dklen + hlen - 1) // hlen

    result = bytearray()
    pack_int = struct.pack

    # === MAIN LOOP ===
    for i in range(1, blocks_needed + 1):
        # U_1 = HMAC(password, salt || INT_32_BE(i))
        block_salt = salt_bytes + pack_int('>I', i)
        u_prev = hmac.compute_bytes(block_salt)

        # Create block for this iteration
        block = bytearray(u_prev)
        block_len = len(block)

        # Compute U_2 through U_c
        for _ in range(2, iterations + 1):
            u_curr = hmac.compute_bytes(u_prev)

            # XOR u_curr into block
            for j in range(block_len):
                block[j] ^= u_curr[j]

            u_prev = u_curr

        # Add block to result
        result.extend(block)

    # Return exactly dklen bytes
    return bytes(result[:dklen])


def pbkdf2_hex(password, salt, iterations=100000, dklen=32):
    """
    Convenience function returning hex string.
    """
    result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
    return result.hex()


def _hmac_sha256_direct(key, message):
    """
    Direct HMAC-SHA256 implementation without HMAC objects.
    FOR TESTING ONLY - NOT using HMAC class from Sprint 5.
    """
    from src.hash.sha256 import SHA256

    block_size = 64

    # Process key
    if len(key) > block_size:
        hasher = SHA256()
        hasher.update(key)
        key = hasher.digest()

    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))

    # Create pads
    ipad = bytes(x ^ 0x36 for x in key)
    opad = bytes(x ^ 0x5C for x in key)

    # Inner hash
    inner = SHA256()
    inner.update(ipad)
    inner.update(message)
    inner_hash = inner.digest()

    # Outer hash
    outer = SHA256()
    outer.update(opad)
    outer.update(inner_hash)

    return outer.digest()


def pbkdf2_hmac_sha256_direct(password, salt, iterations, dklen):
    """
    FASTEST version of PBKDF2.
    Uses direct HMAC computation without HMAC objects.
    FOR TESTING ONLY - NOT using HMAC class from Sprint 5!
    """
    # Convert inputs
    if isinstance(password, str):
        password = password.encode('utf-8')

    if isinstance(salt, str):
        try:
            salt = bytes.fromhex(salt)
        except ValueError:
            salt = salt.encode('utf-8')

    hlen = 32
    blocks_needed = (dklen + hlen - 1) // hlen

    result = bytearray()
    pack_int = struct.pack

    for i in range(1, blocks_needed + 1):
        block_salt = salt + pack_int('>I', i)
        u_prev = _hmac_sha256_direct(password, block_salt)

        block = bytearray(u_prev)
        block_len = len(block)

        for _ in range(2, iterations + 1):
            u_curr = _hmac_sha256_direct(password, u_prev)

            for j in range(block_len):
                block[j] ^= u_curr[j]

            u_prev = u_curr

        result.extend(block)

    return bytes(result[:dklen])


# ============================================================================
# PERFORMANCE COMPARISON
# ============================================================================

def benchmark_pbkdf2():
    """Benchmark different implementations"""
    import time
    import hashlib

    print("\n=== PBKDF2 IMPLEMENTATION BENCHMARK ===")

    test_cases = [
        ('test', 'salt', 1000, 32),
        ('password', 'salt', 1000, 32),
    ]

    # Наша основная реализация (использует HMAC из Sprint 5)
    our_result = pbkdf2_hmac_sha256('test', 'salt', 1, 32)
    print(f"Our implementation test: {our_result[:8].hex()}...")

    implementations = [
        ('Our (with HMAC from Sprint 5)', pbkdf2_hmac_sha256),
        ('Direct (for comparison)', pbkdf2_hmac_sha256_direct),
    ]

    for impl_name, impl_func in implementations:
        print(f"\n{impl_name}:")
        for pwd, salt, iters, dklen in test_cases:
            start = time.perf_counter()
            result = impl_func(pwd, salt, iters, dklen)
            elapsed = time.perf_counter() - start

            print(f"  {iters} iterations: {elapsed:.3f}s "
                  f"({elapsed/iters*1000:.2f}ms/iter)")
            print(f"  Result: {result[:8].hex()}...")

    # Сравнение с Python reference
    print("\nPython hashlib.pbkdf2_hmac (reference):")
    for pwd, salt, iters, dklen in test_cases:
        pwd_bytes = pwd.encode('utf-8') if isinstance(pwd, str) else pwd
        salt_bytes = salt.encode('utf-8') if isinstance(salt, str) else salt

        start = time.perf_counter()
        result = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt_bytes, iters, dklen)
        elapsed = time.perf_counter() - start

        print(f"  {iters} iterations: {elapsed:.3f}s "
              f"({elapsed/iters*1000:.2f}ms/iter)")


if __name__ == '__main__':
    benchmark_pbkdf2()