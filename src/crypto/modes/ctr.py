from .base_mode import BaseMode
from Crypto.Cipher import AES


class CTR_MODE(BaseMode):
    def __init__(self, key):
        super().__init__(key)
        self.cipher = AES.new(key, AES.MODE_ECB)

    def _increment_counter(self, counter):
        """Инкрементирует 128-битный счетчик (big-endian)"""
        # Конвертируем в int, инкрементируем, и обратно в bytes
        counter_int = int.from_bytes(counter, byteorder='big')
        counter_int = (counter_int + 1) & ((1 << 128) - 1)  # Ограничиваем 128 битами
        return counter_int.to_bytes(16, byteorder='big')

    def encrypt(self, plaintext: bytes, iv: bytes = None) -> bytes:
        if iv is None:
            raise ValueError("IV is required for CTR mode")
        if len(iv) != self.block_size:
            raise ValueError(f"IV must be {self.block_size} bytes")

        ciphertext = b''
        counter = iv

        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]

            # Шифруем текущее значение счетчика
            keystream_block = self.cipher.encrypt(counter)

            # XOR с открытым текстом
            cipher_block = bytes(a ^ b for a, b in zip(block, keystream_block))
            ciphertext += cipher_block

            # Инкрементируем счетчик
            counter = self._increment_counter(counter)

        return ciphertext

    def decrypt(self, ciphertext: bytes, iv: bytes = None) -> bytes:
        # CTR симметричен: дешифрование такое же как шифрование
        return self.encrypt(ciphertext, iv)