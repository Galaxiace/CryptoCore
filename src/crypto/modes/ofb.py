from .base_mode import BaseMode
from Crypto.Cipher import AES


class OFB_MODE(BaseMode):
    def __init__(self, key):
        super().__init__(key)
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, plaintext: bytes, iv: bytes = None) -> bytes:
        if iv is None:
            raise ValueError("IV is required for OFB mode")
        if len(iv) != self.block_size:
            raise ValueError(f"IV must be {self.block_size} bytes")

        ciphertext = b''
        keystream = iv

        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]

            # Генерируем следующий блок keystream
            keystream_block = self.cipher.encrypt(keystream)

            # XOR с открытым текстом
            cipher_block = bytes(a ^ b for a, b in zip(block, keystream_block))
            ciphertext += cipher_block

            # Для OFB keystream - это зашифрованный предыдущий keystream
            keystream = keystream_block

        return ciphertext

    def decrypt(self, ciphertext: bytes, iv: bytes = None) -> bytes:
        # OFB симметричен: дешифрование такое же как шифрование
        return self.encrypt(ciphertext, iv)