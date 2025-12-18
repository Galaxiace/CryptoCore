import os
import tempfile
import pytest
from src.crypto.modes.gcm import GCM_MODE, AuthenticationError


class TestGCM:
    def test_gcm_encrypt_decrypt_basic(self):
        """Test basic GCM encryption and decryption"""
        key = os.urandom(16)
        plaintext = b"Hello GCM world!"
        aad = b"associated data"

        gcm = GCM_MODE(key)

        # Encrypt
        ciphertext = gcm.encrypt(plaintext, aad=aad)

        # Decrypt
        decrypted = gcm.decrypt(ciphertext, aad=aad)

        assert decrypted == plaintext
        assert len(ciphertext) == len(plaintext) + 12 + 16  # nonce + tag

    def test_gcm_aad_tamper(self):
        """Test that wrong AAD causes authentication failure"""
        key = os.urandom(16)
        plaintext = b"Secret message"
        aad_correct = b"correct_aad"
        aad_wrong = b"wrong_aad"

        gcm = GCM_MODE(key)

        # Encrypt with correct AAD
        ciphertext = gcm.encrypt(plaintext, aad=aad_correct)

        # Try to decrypt with wrong AAD
        with pytest.raises(AuthenticationError):
            gcm.decrypt(ciphertext, aad=aad_wrong)

    def test_gcm_ciphertext_tamper(self):
        """Test that ciphertext tampering causes authentication failure"""
        key = os.urandom(16)
        plaintext = b"Another secret message"
        aad = b"associated_data"

        gcm = GCM_MODE(key)

        # Encrypt
        ciphertext = gcm.encrypt(plaintext, aad=aad)

        # Tamper with ciphertext (flip one bit)
        tampered = bytearray(ciphertext)
        tampered[20] ^= 0x01  # Flip a bit in the ciphertext part

        # Try to decrypt tampered ciphertext
        with pytest.raises(AuthenticationError):
            gcm.decrypt(bytes(tampered), aad=aad)

    def test_gcm_tag_tamper(self):
        """Test that tag tampering causes authentication failure"""
        key = os.urandom(16)
        plaintext = b"Message"
        aad = b"aad"

        gcm = GCM_MODE(key)

        # Encrypt
        ciphertext = gcm.encrypt(plaintext, aad=aad)

        # Tamper with tag (last 16 bytes)
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0x01  # Flip last bit of tag

        # Try to decrypt
        with pytest.raises(AuthenticationError):
            gcm.decrypt(bytes(tampered), aad=aad)

    def test_gcm_empty_aad(self):
        """Test GCM with empty AAD"""
        key = os.urandom(16)
        plaintext = b"Test with empty AAD"

        gcm = GCM_MODE(key)

        ciphertext = gcm.encrypt(plaintext, aad=b"")
        decrypted = gcm.decrypt(ciphertext, aad=b"")

        assert decrypted == plaintext

    def test_gcm_long_aad(self):
        """Test GCM with long AAD"""
        key = os.urandom(16)
        plaintext = b"Short message"
        aad = b"A" * 1000  # 1000 bytes AAD

        gcm = GCM_MODE(key)

        ciphertext = gcm.encrypt(plaintext, aad=aad)
        decrypted = gcm.decrypt(ciphertext, aad=aad)

        assert decrypted == plaintext

    def test_gcm_nonce_uniqueness(self):
        """Test that nonce is unique for each encryption"""
        key = os.urandom(16)
        plaintext = b"Same plaintext"

        gcm = GCM_MODE(key)

        # Encrypt same plaintext twice
        ciphertext1 = gcm.encrypt(plaintext)
        ciphertext2 = gcm.encrypt(plaintext)

        # Nonces (first 12 bytes) should be different
        nonce1 = ciphertext1[:12]
        nonce2 = ciphertext2[:12]

        assert nonce1 != nonce2

        # Both should decrypt correctly
        decrypted1 = gcm.decrypt(ciphertext1)
        decrypted2 = gcm.decrypt(ciphertext2)

        assert decrypted1 == plaintext
        assert decrypted2 == plaintext

    def test_gcm_with_external_nonce(self):
        """Test GCM with provided nonce"""
        key = os.urandom(16)
        nonce = os.urandom(12)
        plaintext = b"Test with fixed nonce"
        aad = b"fixed aad"

        gcm = GCM_MODE(key)

        # Encrypt with fixed nonce
        ciphertext = gcm.encrypt(plaintext, iv=nonce, aad=aad)

        # Nonce in output should match provided nonce
        assert ciphertext[:12] == nonce

        # Decrypt
        decrypted = gcm.decrypt(ciphertext, aad=aad)
        assert decrypted == plaintext

        # Also test decryption with explicit nonce parameter
        decrypted2 = gcm.decrypt(ciphertext[12:], iv=nonce, aad=aad)
        assert decrypted2 == plaintext


def test_gcm_nist_test_vector():
    """Test with a known NIST test vector (simplified)"""
    # This is a simplified test. Real NIST vectors would be more complex.
    key = bytes.fromhex("00000000000000000000000000000000")
    nonce = bytes.fromhex("000000000000000000000000")
    plaintext = b""
    aad = b""

    gcm = GCM_MODE(key)

    # Encrypt with zero key, nonce, etc.
    ciphertext = gcm.encrypt(plaintext, iv=nonce, aad=aad)

    # For zero inputs, tag should be AES(key, J0)
    # This is a sanity check, not a full NIST test
    assert len(ciphertext) == 12 + 0 + 16  # nonce + empty ciphertext + tag

    # Should decrypt successfully
    decrypted = gcm.decrypt(ciphertext, aad=aad)
    assert decrypted == plaintext


if __name__ == "__main__":
    # Run tests
    test = TestGCM()
    test.test_gcm_encrypt_decrypt_basic()
    test.test_gcm_aad_tamper()
    test.test_gcm_ciphertext_tamper()
    test.test_gcm_empty_aad()
    print("All tests passed!")