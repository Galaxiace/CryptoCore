import pytest
from src.crypto.aes_ecb import AES_ECB_MODE


class TestAESECB:
    def test_encrypt_decrypt(self):
        key = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
        plaintext = b"Test message for AES encryption"

        cipher = AES_ECB_MODE(key)
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)

        assert decrypted == plaintext
        assert len(ciphertext) % 16 == 0

    def test_padding(self):
        key = b'\x00' * 16
        cipher = AES_ECB_MODE(key)

        for length in [1, 15, 16, 17, 31, 32]:
            message = b'A' * length
            padded = cipher._pad(message)
            assert len(padded) % 16 == 0
            assert cipher._unpad(padded) == message

    def test_wrong_key_decryption(self):
        key1 = b'\x00' * 16
        key2 = b'\xFF' * 16
        plaintext = b"Secret message"

        cipher1 = AES_ECB_MODE(key1)
        ciphertext = cipher1.encrypt(plaintext)

        cipher2 = AES_ECB_MODE(key2)

        with pytest.raises(ValueError, match="Invalid padding"):
            cipher2.decrypt(ciphertext)

    def test_invalid_key_length(self):
        with pytest.raises(ValueError, match="Key must be 16, 24, or 32 bytes long"):
            AES_ECB_MODE(b'short_key')