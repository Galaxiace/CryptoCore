from .base_mode import BaseMode
from ..aes_ecb import AES_ECB_MODE  # Используем внутренний AES


class CTR_MODE(BaseMode):
    def __init__(self, key):
        super().__init__(key)
        # Используем наш внутренний AES
        self.cipher = AES_ECB_MODE(key)

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
            # Используем encrypt_block вместо encrypt
            keystream_block = self._encrypt_block(counter)

            # XOR с открытым текстом
            cipher_block = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
            ciphertext += cipher_block

            # Инкрементируем счетчик
            counter = self._increment_counter(counter)

        return ciphertext

    def decrypt(self, ciphertext: bytes, iv: bytes = None) -> bytes:
        # CTR симметричен: дешифрование такое же как шифрование
        return self.encrypt(ciphertext, iv)

    def _encrypt_block(self, block):
        """Вспомогательный метод для шифрования одного блока"""
        # Обеспечиваем, что блок 16 байт
        if len(block) < 16:
            block = block + b'\x00' * (16 - len(block))

        # Шифруем блок
        encrypted = self.cipher.encrypt(block)

        # Возвращаем первые 16 байт
        return encrypted[:16]