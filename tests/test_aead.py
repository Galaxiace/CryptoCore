import os
import pytest
from src.crypto.modes.aead import AEAD_EncryptThenMAC
from src.crypto.modes.gcm import AuthenticationError


class TestAEADEncryptThenMAC:
    def test_encrypt_then_mac_ctr_basic(self):
        """Test basic Encrypt-then-MAC with CTR mode"""
        key = os.urandom(32)
        plaintext = b"Hello AEAD world!"
        aad = b"associated data"

        aead = AEAD_EncryptThenMAC(key, mode='ctr')

        # Encrypt
        ciphertext = aead.encrypt(plaintext, aad=aad)

        # Decrypt
        decrypted = aead.decrypt(ciphertext, aad=aad)

        assert decrypted == plaintext
        assert len(ciphertext) == len(plaintext) + 16 + 16  # IV + tag

    def test_encrypt_then_mac_cbc_basic(self):
        """Test basic Encrypt-then-MAC with CBC mode"""
        key = os.urandom(32)
        plaintext = b"Hello CBC AEAD!"
        aad = b"cbc aad"

        aead = AEAD_EncryptThenMAC(key, mode='cbc')

        # Encrypt
        ciphertext = aead.encrypt(plaintext, aad=aad)

        # Decrypt
        decrypted = aead.decrypt(ciphertext, aad=aad)

        assert decrypted == plaintext

    def test_encrypt_then_mac_aad_tamper(self):
        """Test that wrong AAD causes authentication failure"""
        key = os.urandom(32)
        plaintext = b"Secret AEAD message"
        aad_correct = b"correct_aad"
        aad_wrong = b"wrong_aad"

        aead = AEAD_EncryptThenMAC(key, mode='ctr')

        # Encrypt with correct AAD
        ciphertext = aead.encrypt(plaintext, aad=aad_correct)

        # Try to decrypt with wrong AAD
        with pytest.raises(AuthenticationError):
            aead.decrypt(ciphertext, aad=aad_wrong)

    def test_encrypt_then_mac_ciphertext_tamper(self):
        """Test that ciphertext tampering causes authentication failure"""
        key = os.urandom(32)
        plaintext = b"Tamper test"
        aad = b"aad"

        aead = AEAD_EncryptThenMAC(key, mode='ctr')

        # Encrypt
        ciphertext = aead.encrypt(plaintext, aad=aad)

        # Tamper with ciphertext (flip one bit)
        tampered = bytearray(ciphertext)
        tampered[25] ^= 0x01  # Flip a bit in the ciphertext part

        # Try to decrypt tampered ciphertext
        with pytest.raises(AuthenticationError):
            aead.decrypt(bytes(tampered), aad=aad)

    def test_encrypt_then_mac_tag_tamper(self):
        """Test that tag tampering causes authentication failure"""
        key = os.urandom(32)
        plaintext = b"Message"
        aad = b"aad"

        aead = AEAD_EncryptThenMAC(key, mode='ctr')

        # Encrypt
        ciphertext = aead.encrypt(plaintext, aad=aad)

        # Tamper with tag (last 16 bytes)
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0x01  # Flip last bit of tag

        # Try to decrypt
        with pytest.raises(AuthenticationError):
            aead.decrypt(bytes(tampered), aad=aad)

    def test_encrypt_then_mac_empty_aad(self):
        """Test with empty AAD"""
        key = os.urandom(32)
        plaintext = b"Test with empty AAD"

        aead = AEAD_EncryptThenMAC(key, mode='ctr')

        ciphertext = aead.encrypt(plaintext, aad=b"")
        decrypted = aead.decrypt(ciphertext, aad=b"")

        assert decrypted == plaintext

    def test_encrypt_then_mac_key_separation(self):
        """Test that encryption and MAC keys are different"""
        key = os.urandom(16)

        aead = AEAD_EncryptThenMAC(key, mode='ctr')

        # Keys should be derived and different
        assert aead.enc_key != aead.mac_key
        assert len(aead.enc_key) in [16, 24, 32]
        assert len(aead.mac_key) in [16, 24, 32]

    def test_encrypt_then_mac_with_external_iv(self):
        """Test with provided IV"""
        key = os.urandom(32)
        plaintext = b"Test with fixed IV"
        aad = b"fixed aad"
        iv = os.urandom(16)

        aead = AEAD_EncryptThenMAC(key, mode='ctr')

        # Encrypt with fixed IV
        ciphertext = aead.encrypt(plaintext, iv=iv, aad=aad)

        # IV in output should match provided IV
        assert ciphertext[:16] == iv

        # Decrypt with explicit IV
        decrypted = aead.decrypt(ciphertext[16:], iv=iv, aad=aad)
        assert decrypted == plaintext


def test_aead_key_derivation():
    """Test key derivation for different key lengths"""
    # Test 16-byte key
    key16 = os.urandom(16)
    aead16 = AEAD_EncryptThenMAC(key16, mode='ctr')
    assert len(aead16.enc_key) == 16
    assert len(aead16.mac_key) == 16

    # Test 24-byte key
    key24 = os.urandom(24)
    aead24 = AEAD_EncryptThenMAC(key24, mode='ctr')
    assert len(aead24.enc_key) == 24
    assert len(aead24.mac_key) == 24

    # Test 32-byte key
    key32 = os.urandom(32)
    aead32 = AEAD_EncryptThenMAC(key32, mode='ctr')
    assert len(aead32.enc_key) == 32
    assert len(aead32.mac_key) == 32


if __name__ == "__main__":
    test = TestAEADEncryptThenMAC()
    test.test_encrypt_then_mac_ctr_basic()
    test.test_encrypt_then_mac_aad_tamper()
    test.test_encrypt_then_mac_ciphertext_tamper()
    print("All AEAD tests passed!")