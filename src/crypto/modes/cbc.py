from .base_mode import BaseMode
from Crypto.Cipher import AES


class CBC_MODE(BaseMode):
    def __init__(self, key):
        super().__init__(key)
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, plaintext: bytes, iv: bytes = None) -> bytes:
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        if len(iv) != self.block_size:
            raise ValueError(f"IV must be {self.block_size} bytes")

        # Применяем padding для CBC
        padded_data = self._pad(plaintext)
        ciphertext = b''
        prev_block = iv

        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i + self.block_size]
            # XOR с предыдущим блоком шифротекста (или IV для первого блока)
            xored_block = bytes(a ^ b for a, b in zip(block, prev_block))
            encrypted_block = self.cipher.encrypt(xored_block)
            ciphertext += encrypted_block
            prev_block = encrypted_block

        return ciphertext

    def decrypt(self, ciphertext: bytes, iv: bytes = None) -> bytes:
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        if len(iv) != self.block_size:
            raise ValueError(f"IV must be {self.block_size} bytes")
        if len(ciphertext) % self.block_size != 0:
            raise ValueError("Ciphertext length must be multiple of block size")

        plaintext = b''
        prev_block = iv

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]
            decrypted_block = self.cipher.decrypt(block)
            # XOR с предыдущим блоком шифротекста (или IV для первого блока)
            plain_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
            plaintext += plain_block
            prev_block = block

        # Убираем padding для CBC
        return self._unpad(plaintext)