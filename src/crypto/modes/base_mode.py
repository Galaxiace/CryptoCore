from abc import ABC, abstractmethod
from Crypto.Cipher import AES


class BaseMode(ABC):
    def __init__(self, key):
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes long")
        self.key = key
        self.block_size = 16

    @abstractmethod
    def encrypt(self, plaintext: bytes, iv: bytes = None) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes, iv: bytes = None) -> bytes:
        pass

    def _pad(self, data):
        """PKCS#7 padding - только для режимов, требующих дополнения"""
        pad_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data):
        """Remove PKCS#7 padding - только для режимов, требующих дополнения"""
        if len(data) == 0:
            return data

        pad_len = data[-1]
        if pad_len < 1 or pad_len > self.block_size:
            raise ValueError("Invalid padding")

        if not all(b == pad_len for b in data[-pad_len:]):
            raise ValueError("Invalid padding")

        return data[:-pad_len]