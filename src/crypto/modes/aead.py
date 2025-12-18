from ..aes_ecb import AES_ECB_MODE
from src.mac.hmac import HMAC
from src.utils.csprng import generate_random_bytes
import hashlib
from .ctr import CTR_MODE
from .cbc import CBC_MODE
from .gcm import AuthenticationError


class AEAD_EncryptThenMAC:
    """
    Encrypt-then-MAC AEAD construction
    Combines any block cipher mode with HMAC
    """

    def __init__(self, key, mode='ctr', hash_algo='sha256'):
        """
        Args:
            key: Master key (bytes)
            mode: Block cipher mode ('ctr', 'cbc', etc.)
            hash_algo: Hash algorithm for HMAC
        """
        self.mode = mode
        self.hash_algo = hash_algo

        # Derive separate keys for encryption and MAC
        self.enc_key, self.mac_key = self._derive_keys(key)

        # Initialize cipher based on mode
        if mode == 'ctr':
            self.cipher = CTR_MODE(self.enc_key)
        elif mode == 'cbc':
            self.cipher = CBC_MODE(self.enc_key)
        else:
            raise ValueError(f"Unsupported mode for Encrypt-then-MAC: {mode}")

        # Initialize HMAC
        self.hmac = HMAC(self.mac_key, hash_algo)

    def _derive_keys(self, master_key):
        """
        Derive separate keys for encryption and MAC using HKDF-style
        """
        # Simple KDF using SHA256
        # enc_key = SHA256(master_key || "enc")
        # mac_key = SHA256(master_key || "mac")

        enc_key_digest = hashlib.sha256(master_key + b'enc').digest()
        mac_key_digest = hashlib.sha256(master_key + b'mac').digest()

        # Use appropriate lengths
        if len(master_key) <= 16:
            enc_key = enc_key_digest[:16]
            mac_key = mac_key_digest[:16]
        elif len(master_key) <= 24:
            enc_key = enc_key_digest[:24]
            mac_key = mac_key_digest[:24]
        else:
            enc_key = enc_key_digest[:32]
            mac_key = mac_key_digest[:32]

        return enc_key, mac_key

    def encrypt(self, plaintext, aad=b"", iv=None):
        """
        Encrypt-then-MAC: c = E(K_e, P), T = HMAC(K_m, C | AAD)

        Returns:
            iv + ciphertext + tag (16 bytes)
        """
        # Generate IV if not provided
        if iv is None:
            iv = generate_random_bytes(16)

        # Encrypt using the selected mode
        if self.mode == 'ctr':
            ciphertext = self.cipher.encrypt(plaintext, iv)
        elif self.mode == 'cbc':
            ciphertext = self.cipher.encrypt(plaintext, iv)
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")

        # Compute MAC: HMAC(K_m, ciphertext | AAD)
        mac_data = ciphertext + aad
        tag_hex = self.hmac.compute(mac_data)

        # Convert hex tag to bytes (use first 16 bytes for consistency with GCM)
        tag_bytes = bytes.fromhex(tag_hex)[:16]

        return iv + ciphertext + tag_bytes

    def decrypt(self, data, aad=b"", iv=None):
        """
        Decrypt and verify MAC

        Returns:
            Plaintext if authentication successful

        Raises:
            AuthenticationError: if MAC verification fails
        """
        # Extract components
        if iv is not None:
            # IV provided separately
            ciphertext_tag = data
            ciphertext = ciphertext_tag[:-16]
            tag = ciphertext_tag[-16:]
        else:
            # IV embedded in data
            if len(data) < 32:  # min: 16 IV + 0 ciphertext + 16 tag
                raise ValueError("Input too short")
            iv = data[:16]
            ciphertext = data[16:-16]
            tag = data[-16:]

        # Verify MAC
        mac_data = ciphertext + aad
        computed_tag_hex = self.hmac.compute(mac_data)
        computed_tag_bytes = bytes.fromhex(computed_tag_hex)[:16]

        if not self._constant_time_compare(tag, computed_tag_bytes):
            raise AuthenticationError("Authentication failed: MAC mismatch")

        # Decrypt using the selected mode
        if self.mode == 'ctr':
            plaintext = self.cipher.decrypt(ciphertext, iv)
        elif self.mode == 'cbc':
            plaintext = self.cipher.decrypt(ciphertext, iv)
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")

        return plaintext

    def _constant_time_compare(self, a, b):
        """Constant-time comparison to prevent timing attacks"""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0