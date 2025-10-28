import pytest
import sys
import os
import tempfile

# Добавляем корневую директорию в путь для импорта
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Правильные импорты
from src.crypto.core import encrypt_file_aes, decrypt_file_aes
from src.utils.validation import validate_hex_key


@pytest.fixture
def test_key():
    """Фикстура для тестового ключа (строка)"""
    return "00112233445566778899aabbccddeeff"


@pytest.fixture
def test_key_bytes():
    """Фикстура для тестового ключа в bytes"""
    return bytes.fromhex("00112233445566778899aabbccddeeff")


@pytest.fixture
def text_file():
    """Создает временный текстовый файл для тестирования"""
    fd, path = tempfile.mkstemp(suffix='.txt')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write("This is a test message for encryption.\n")
            f.write("This is the second line of the test file.\n")
        yield path
    finally:
        os.unlink(path)


@pytest.fixture
def binary_file():
    """Создает временный бинарный файл для тестирования"""
    fd, path = tempfile.mkstemp(suffix='.bin')
    try:
        with os.fdopen(fd, 'wb') as f:
            # Генерируем случайные байты
            import random
            random_bytes = bytes([random.randint(0, 255) for _ in range(100)])
            f.write(random_bytes)
        yield path
    finally:
        os.unlink(path)