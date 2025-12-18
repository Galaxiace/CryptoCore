from .base_mode import BaseMode
from .ctr import CTR_MODE
from src.utils.csprng import generate_random_bytes
import struct
import os


class AuthenticationError(Exception):
    """Exception raised when authentication fails in GCM"""
    pass


class GCM_MODE(BaseMode):
    """
    Galois/Counter Mode (GCM) implementation following NIST SP 800-38D
    """

    # Irreducible polynomial for GF(2^128): x^128 + x^7 + x^2 + x + 1
    R = 0xE1000000000000000000000000000000

    def __init__(self, key):
        super().__init__(key)

        # Import AES_ECB_MODE here to avoid circular imports
        from ..aes_ecb import AES_ECB_MODE

        # Create AES instance for encryption
        self.aes = AES_ECB_MODE(key)

        # Precompute H (encryption of zero block)
        self.H = self._compute_H()

    def _compute_H(self):
        """Compute H = AES(K, 0^128)"""
        zero_block = b'\x00' * 16
        H_bytes = self.aes.encrypt(zero_block)

        if len(H_bytes) > 16:
            H_bytes = H_bytes[:16]

        return int.from_bytes(H_bytes, byteorder='big')

    def _mult_gf(self, x, y):
        """
        GF(2^128) multiplication using the irreducible polynomial

        Args:
            x, y: 128-bit integers representing field elements

        Returns:
            Product in GF(2^128)
        """
        # Простая, но корректная реализация
        z = 0
        v = y

        for i in range(127, -1, -1):
            if (x >> i) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ self.R
            else:
                v >>= 1

        return z

    def _ghash(self, aad, ciphertext):
        """
        Compute GHASH in GF(2^128)

        Args:
            aad: Associated Authenticated Data (bytes)
            ciphertext: Ciphertext (bytes)

        Returns:
            16-byte authentication tag as integer
        """
        # Convert lengths to 64-bit big-endian
        len_aad = len(aad) * 8  # bits
        len_ciphertext = len(ciphertext) * 8  # bits

        len_block = struct.pack('>QQ', len_aad, len_ciphertext)

        # Initialize state
        y = 0

        # Process AAD in 16-byte blocks
        for i in range(0, len(aad), 16):
            block = aad[i:i + 16]
            if len(block) < 16:
                block = block + b'\x00' * (16 - len(block))
            block_int = int.from_bytes(block, byteorder='big')
            y ^= block_int
            y = self._mult_gf(y, self.H)

        # Process ciphertext in 16-byte blocks
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            if len(block) < 16:
                block = block + b'\x00' * (16 - len(block))
            block_int = int.from_bytes(block, byteorder='big')
            y ^= block_int
            y = self._mult_gf(y, self.H)

        # Process length block
        len_int = int.from_bytes(len_block, byteorder='big')
        y ^= len_int
        y = self._mult_gf(y, self.H)

        return y

    def _inc32(self, counter):
        """Increment rightmost 32 bits of counter (NIST SP 800-38D)"""
        counter_bytes = counter.to_bytes(16, byteorder='big')

        # Extract last 4 bytes (32 bits)
        last_4_bytes = counter_bytes[12:]
        last_int = int.from_bytes(last_4_bytes, byteorder='big')

        # Increment modulo 2^32
        last_int = (last_int + 1) & 0xFFFFFFFF

        # Reconstruct counter
        new_counter_bytes = counter_bytes[:12] + last_int.to_bytes(4, byteorder='big')
        return int.from_bytes(new_counter_bytes, byteorder='big')

    def _generate_iv(self, nonce):
        """
        Generate IV from nonce (J0 in NIST terminology)
        For 12-byte nonce: IV = nonce || 0x00000001
        """
        if len(nonce) == 12:
            return int.from_bytes(nonce + b'\x00\x00\x00\x01', byteorder='big')
        else:
            raise ValueError("Only 12-byte nonce is currently supported")

    def _encrypt_block(self, block):
        """Encrypt a single 16-byte block using internal AES"""
        # Ensure block is 16 bytes
        if len(block) < 16:
            block = block + b'\x00' * (16 - len(block))
        elif len(block) > 16:
            block = block[:16]

        # Encrypt using our AES implementation
        encrypted = self.aes.encrypt(block)

        # Return first 16 bytes
        return encrypted[:16]

    def encrypt(self, plaintext: bytes, iv: bytes = None, aad: bytes = b"") -> bytes:
        """
        GCM Encryption
        """
        if iv is None:
            iv = generate_random_bytes(12)
        elif len(iv) != 12:
            raise ValueError(f"Nonce must be 12 bytes for GCM, got {len(iv)}")

        # Generate J0
        J0 = self._generate_iv(iv)

        # Generate initial counter for encryption
        init_counter = (J0 + 1) & ((1 << 128) - 1)

        # Encrypt plaintext using CTR mode logic
        ciphertext = b''
        counter = init_counter

        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i + 16]

            # Generate keystream block
            counter_bytes = counter.to_bytes(16, byteorder='big')
            keystream_block = self._encrypt_block(counter_bytes)

            # XOR with plaintext
            cipher_block = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
            ciphertext += cipher_block

            # Increment counter
            counter = self._inc32(counter)

        # Compute authentication tag
        J0_bytes = J0.to_bytes(16, byteorder='big')
        S = self._encrypt_block(J0_bytes)
        S_int = int.from_bytes(S, byteorder='big')

        ghash_result = self._ghash(aad, ciphertext)
        T = ghash_result ^ S_int

        tag = T.to_bytes(16, byteorder='big')

        return iv + ciphertext + tag

    def decrypt(self, data: bytes, iv: bytes = None, aad: bytes = b"") -> bytes:
        """
        GCM Decryption with authentication verification
        """
        # Parse input
        if iv is None:
            if len(data) < 28:
                raise ValueError("Input too short for GCM format")
            nonce = data[:12]
            ciphertext_tag = data[12:]
        else:
            nonce = iv
            ciphertext_tag = data

        if len(ciphertext_tag) < 16:
            raise ValueError("Input too short - missing tag")

        # Split ciphertext and tag
        ciphertext = ciphertext_tag[:-16]
        tag = ciphertext_tag[-16:]

        # Verify tag
        J0 = self._generate_iv(nonce)
        J0_bytes = J0.to_bytes(16, byteorder='big')
        S = self._encrypt_block(J0_bytes)
        S_int = int.from_bytes(S, byteorder='big')

        ghash_result = self._ghash(aad, ciphertext)
        expected_T = ghash_result ^ S_int
        expected_tag = expected_T.to_bytes(16, byteorder='big')

        # DEBUG: Print tags for comparison
        # print(f"Computed tag: {expected_tag.hex()}")
        # print(f"Received tag: {tag.hex()}")

        # Constant-time comparison
        if not self._constant_time_compare(tag, expected_tag):
            raise AuthenticationError("Authentication failed: AAD mismatch or ciphertext tampered")

        # Decrypt ciphertext
        J0 = self._generate_iv(nonce)
        init_counter = (J0 + 1) & ((1 << 128) - 1)

        plaintext = b''
        counter = init_counter

        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]

            counter_bytes = counter.to_bytes(16, byteorder='big')
            keystream_block = self._encrypt_block(counter_bytes)

            plain_block = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
            plaintext += plain_block

            counter = self._inc32(counter)

        return plaintext

    def _constant_time_compare(self, a, b):
        """Constant-time comparison to prevent timing attacks"""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0