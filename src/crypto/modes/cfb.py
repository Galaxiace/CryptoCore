from .base_mode import BaseMode
from Crypto.Cipher import AES


class CFB_MODE(BaseMode):
    def __init__(self, key):
        super().__init__(key)
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, plaintext: bytes, iv: bytes = None) -> bytes:
        if iv is None:
            raise ValueError("IV is required for CFB mode")
        if len(iv) != self.block_size:
            raise ValueError(f"IV must be {self.block_size} bytes")

        ciphertext = b''
        feedback = iv

        # Обрабатываем данные блоками
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]

            # Шифруем feedback
            encrypted_feedback = self.cipher.encrypt(feedback)

            # XOR с открытым текстом для получения шифротекста
            cipher_block = bytes(a ^ b for a, b in zip(block, encrypted_feedback))
            ciphertext += cipher_block

            # Для CFB feedback - это шифротекст (не зашифрованный feedback)
            feedback = cipher_block

        return ciphertext

    def decrypt(self, ciphertext: bytes, iv: bytes = None) -> bytes:
        if iv is None:
            raise ValueError("IV is required for CFB mode")
        if len(iv) != self.block_size:
            raise ValueError(f"IV must be {self.block_size} bytes")

        plaintext = b''
        feedback = iv

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # Шифруем feedback
            encrypted_feedback = self.cipher.encrypt(feedback)

            # XOR с шифротекстом для получения открытого текста
            plain_block = bytes(a ^ b for a, b in zip(block, encrypted_feedback))
            plaintext += plain_block

            # Для CFB feedback - это шифротекст
            feedback = block

        return plaintext