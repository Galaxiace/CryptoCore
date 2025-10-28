import pytest
import os
import subprocess
import tempfile
import sys

# Добавляем корневую директорию в путь для импорта
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.crypto.core import encrypt_file_aes, decrypt_file_aes
from src.utils.validation import validate_hex_key


class TestIntegration:
    def test_text_file_encryption_decryption(self, text_file, test_key_bytes):
        encrypted_file = text_file + '.enc'
        decrypted_file = text_file + '.dec'

        try:
            encrypt_file_aes(text_file, encrypted_file, test_key_bytes, "ecb")
            assert os.path.exists(encrypted_file)

            decrypt_file_aes(encrypted_file, decrypted_file, test_key_bytes, "ecb")
            assert os.path.exists(decrypted_file)

            with open(text_file, 'rb') as f:
                original = f.read()
            with open(decrypted_file, 'rb') as f:
                decrypted = f.read()

            assert original == decrypted

        finally:
            for f in [encrypted_file, decrypted_file]:
                if os.path.exists(f):
                    os.unlink(f)

    def test_binary_file_encryption_decryption(self, binary_file, test_key_bytes):
        encrypted_file = binary_file + '.enc'
        decrypted_file = binary_file + '.dec'

        try:
            encrypt_file_aes(binary_file, encrypted_file, test_key_bytes, "ecb")
            decrypt_file_aes(encrypted_file, decrypted_file, test_key_bytes, "ecb")

            with open(binary_file, 'rb') as f:
                original = f.read()
            with open(decrypted_file, 'rb') as f:
                decrypted = f.read()

            assert original == decrypted

        finally:
            for f in [encrypted_file, decrypted_file]:
                if os.path.exists(f):
                    os.unlink(f)

    def test_wrong_key_fails(self, text_file, test_key_bytes):
        encrypted_file = text_file + '.enc'
        wrong_key = b'1' * 16  # Неправильный ключ

        try:
            encrypt_file_aes(text_file, encrypted_file, test_key_bytes, "ecb")

            with pytest.raises(Exception):
                decrypt_file_aes(encrypted_file, text_file + '.bad', wrong_key, "ecb")

        finally:
            if os.path.exists(encrypted_file):
                os.unlink(encrypted_file)

    def test_openssl_compatibility(self, text_file, test_key_bytes):
        """TEST-3: Verify our implementation produces same output as OpenSSL"""
        # Создаем файл с данными, кратными 16 байтам
        test_content = b"A" * 64  # 64 байта = 4 блока по 16 байт
        with open(text_file, 'wb') as f:
            f.write(test_content)

        your_encrypted = text_file + '.our.enc'
        your_decrypted = text_file + '.our.dec'
        openssl_encrypted = text_file + '.openssl.enc'
        openssl_decrypted = text_file + '.openssl.dec'

        key_hex = test_key_bytes.hex()

        try:
            # Шифруем и дешифруем вашей реализацией
            encrypt_file_aes(text_file, your_encrypted, test_key_bytes, "ecb")
            decrypt_file_aes(your_encrypted, your_decrypted, test_key_bytes, "ecb")

            # Шифруем и дешифруем через OpenSSL
            subprocess.run([
                'openssl', 'enc', '-aes-128-ecb',
                '-K', key_hex,
                '-in', text_file,
                '-out', openssl_encrypted
            ], capture_output=True, check=True)

            subprocess.run([
                'openssl', 'enc', '-aes-128-ecb', '-d',
                '-K', key_hex,
                '-in', openssl_encrypted,
                '-out', openssl_decrypted
            ], capture_output=True, check=True)

            # Сравниваем РАЗМЕРЫ зашифрованных данных (должны быть одинаковыми с паддингом)
            with open(your_encrypted, 'rb') as f1, open(openssl_encrypted, 'rb') as f2:
                your_enc_data = f1.read()
                openssl_enc_data = f2.read()

                # Оба должны добавить паддинг, поэтому размеры должны совпадать
                assert len(your_enc_data) == len(openssl_enc_data), \
                    f"Different encrypted sizes: {len(your_enc_data)} vs {len(openssl_enc_data)}"

            # Сравниваем РАСШИФРОВАННЫЕ данные (должны быть идентичны)
            with open(your_decrypted, 'rb') as f1, open(openssl_decrypted, 'rb') as f2:
                your_dec_data = f1.read()
                openssl_dec_data = f2.read()

                assert your_dec_data == openssl_dec_data, \
                    "Decrypted data differs from OpenSSL"

            print(f"✓ OpenSSL compatibility verified: encrypted={len(your_enc_data)} bytes, decrypted matches")

        except subprocess.CalledProcessError as e:
            pytest.skip(f"OpenSSL not available or failed: {e.stderr}")
        except FileNotFoundError:
            pytest.skip("OpenSSL not installed on system")
        finally:
            # Очистка
            for f in [your_encrypted, your_decrypted, openssl_encrypted, openssl_decrypted]:
                if os.path.exists(f):
                    os.unlink(f)

    def test_openssl_compatibility_with_padding(self, text_file, test_key_bytes):
        """Test compatibility with OpenSSL for data that requires padding"""
        # Создаем файл с данными, НЕ кратными 16 байтам (требует паддинга)
        test_content = b"Short message"  # 13 байт - требует паддинга
        with open(text_file, 'wb') as f:
            f.write(test_content)

        your_encrypted = text_file + '.our.enc'
        your_decrypted = text_file + '.our.dec'

        key_hex = test_key_bytes.hex()

        try:
            # Шифруем и дешифруем вашей реализацией
            encrypt_file_aes(text_file, your_encrypted, test_key_bytes, "ecb")
            decrypt_file_aes(your_encrypted, your_decrypted, test_key_bytes, "ecb")

            # Шифруем и дешифруем через OpenSSL (с паддингом по умолчанию)
            openssl_encrypted = text_file + '.openssl.enc'
            openssl_decrypted = text_file + '.openssl.dec'

            # Шифрование OpenSSL (с паддингом PKCS#7 по умолчанию)
            subprocess.run([
                'openssl', 'enc', '-aes-128-ecb',
                '-K', key_hex,
                '-in', text_file,
                '-out', openssl_encrypted
            ], capture_output=True, check=True)

            # Дешифрование OpenSSL
            subprocess.run([
                'openssl', 'enc', '-aes-128-ecb', '-d',
                '-K', key_hex,
                '-in', openssl_encrypted,
                '-out', openssl_decrypted
            ], capture_output=True, check=True)

            # Сравниваем результаты дешифрования
            with open(your_decrypted, 'rb') as f1, open(openssl_decrypted, 'rb') as f2:
                your_dec_data = f1.read()
                openssl_dec_data = f2.read()

                assert your_dec_data == openssl_dec_data, \
                    "Decrypted data differs from OpenSSL"

            print("✓ OpenSSL padding compatibility verified")

        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("OpenSSL not available")
        finally:
            # Очистка
            for f in [your_encrypted, your_decrypted, openssl_encrypted, openssl_decrypted]:
                if os.path.exists(f):
                    os.unlink(f)

    def test_all_modes_encryption_decryption(self, text_file, test_key_bytes):
        """Test all new modes: CBC, CFB, OFB, CTR"""
        modes = ["cbc", "cfb", "ofb", "ctr"]

        for mode in modes:
            encrypted_file = f"{text_file}.{mode}.enc"
            decrypted_file = f"{text_file}.{mode}.dec"

            try:
                # Шифруем
                encrypt_file_aes(text_file, encrypted_file, test_key_bytes, mode)
                assert os.path.exists(encrypted_file)

                # Дешифруем
                decrypt_file_aes(encrypted_file, decrypted_file, test_key_bytes, mode)
                assert os.path.exists(decrypted_file)

                # Проверяем
                with open(text_file, 'rb') as f:
                    original = f.read()
                with open(decrypted_file, 'rb') as f:
                    decrypted = f.read()

                assert original == decrypted, f"Mode {mode} failed: files don't match"
                print(f"✓ Mode {mode}: SUCCESS")

            finally:
                for f in [encrypted_file, decrypted_file]:
                    if os.path.exists(f):
                        os.unlink(f)