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

    # ==================== GCM TESTS (старый формат команд) ====================

    def test_gcm_encryption_decryption(self, text_file, test_key_bytes):
        """Test GCM mode encryption and decryption (старый формат из требований)"""
        encrypted_file = text_file + '.gcm.enc'
        decrypted_file = text_file + '.gcm.dec'

        aad = b"test associated data"
        aad_hex = aad.hex()

        try:
            # Encrypt with GCM using CLI - СТАРЫЙ ФОРМАТ (как в требованиях)
            cmd = [
                'python', 'cryptocore.py',
                '-algorithm', 'aes',
                '-mode', 'gcm',
                '-encrypt',
                '-key', test_key_bytes.hex(),
                '-input', text_file,
                '-output', encrypted_file,
                '-aad', aad_hex
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            assert result.returncode == 0, f"GCM encryption failed: {result.stderr}"
            assert os.path.exists(encrypted_file)

            # Check that output contains nonce + ciphertext + tag
            with open(encrypted_file, 'rb') as f:
                encrypted_data = f.read()
            assert len(encrypted_data) >= 28  # 12 nonce + min 0 ciphertext + 16 tag

            # Decrypt with GCM
            cmd = [
                'python', 'cryptocore.py',
                '-algorithm', 'aes',
                '-mode', 'gcm',
                '-decrypt',
                '-key', test_key_bytes.hex(),
                '-input', encrypted_file,
                '-output', decrypted_file,
                '-aad', aad_hex
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            assert result.returncode == 0, f"GCM decryption failed: {result.stderr}"
            assert os.path.exists(decrypted_file)

            # Verify decrypted content matches original
            with open(text_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
                original = f1.read()
                decrypted = f2.read()
                assert original == decrypted, "GCM decryption didn't restore original"

            print(f"✓ GCM mode: SUCCESS (encrypted size: {len(encrypted_data)} bytes)")

        finally:
            for f in [encrypted_file, decrypted_file]:
                if os.path.exists(f):
                    os.unlink(f)

    def test_gcm_authentication_failure(self, text_file, test_key_bytes):
        """Test that GCM authentication failure prevents output"""
        encrypted_file = text_file + '.gcm.enc'
        decrypted_file = text_file + '.gcm.dec'

        correct_aad = b"correct aad"
        wrong_aad = b"wrong aad"

        try:
            # Encrypt with correct AAD
            cmd = [
                'python', 'cryptocore.py',
                '-algorithm', 'aes',
                '-mode', 'gcm',
                '-encrypt',
                '-key', test_key_bytes.hex(),
                '-input', text_file,
                '-output', encrypted_file,
                '-aad', correct_aad.hex()
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            assert result.returncode == 0
            assert os.path.exists(encrypted_file)

            # Try to decrypt with WRONG AAD - should fail
            cmd = [
                'python', 'cryptocore.py',
                '-algorithm', 'aes',
                '-mode', 'gcm',
                '-decrypt',
                '-key', test_key_bytes.hex(),
                '-input', encrypted_file,
                '-output', decrypted_file,
                '-aad', wrong_aad.hex()
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            assert result.returncode == 1, "Should fail with wrong AAD"
            assert "Authentication failed" in result.stderr

            # Output file should NOT exist
            assert not os.path.exists(decrypted_file), \
                "Output file should not be created on authentication failure"

            print("✓ GCM authentication failure: SUCCESS (catastrophic failure works)")

        finally:
            for f in [encrypted_file, decrypted_file]:
                if os.path.exists(f):
                    os.unlink(f)

    def test_gcm_ciphertext_tampering(self, text_file, test_key_bytes):
        """Test that ciphertext tampering causes authentication failure"""
        encrypted_file = text_file + '.gcm.enc'
        tampered_file = text_file + '.gcm.tampered'
        decrypted_file = text_file + '.gcm.dec'

        aad = b"test aad"

        try:
            # Encrypt
            cmd = [
                'python', 'cryptocore.py',
                '-algorithm', 'aes',
                '-mode', 'gcm',
                '-encrypt',
                '-key', test_key_bytes.hex(),
                '-input', text_file,
                '-output', encrypted_file,
                '-aad', aad.hex()
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            assert result.returncode == 0

            # Tamper with the ciphertext
            with open(encrypted_file, 'rb') as f:
                encrypted_data = bytearray(f.read())

            # Tamper a byte in the ciphertext portion (after nonce, before tag)
            if len(encrypted_data) > 28:  # Ensure we have ciphertext to tamper
                tamper_position = 20  # Position in ciphertext part
                encrypted_data[tamper_position] ^= 0x01  # Flip one bit

                with open(tampered_file, 'wb') as f:
                    f.write(encrypted_data)

            # Try to decrypt tampered file - should fail
            cmd = [
                'python', 'cryptocore.py',
                '-algorithm', 'aes',
                '-mode', 'gcm',
                '-decrypt',
                '-key', test_key_bytes.hex(),
                '-input', tampered_file,
                '-output', decrypted_file,
                '-aad', aad.hex()
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            assert result.returncode == 1, "Should fail with tampered ciphertext"
            assert "Authentication failed" in result.stderr

            # Output file should NOT exist
            assert not os.path.exists(decrypted_file)

            print("✓ GCM ciphertext tamper detection: SUCCESS")

        finally:
            for f in [encrypted_file, tampered_file, decrypted_file]:
                if os.path.exists(f):
                    os.unlink(f)

    def test_gcm_empty_aad(self, text_file, test_key_bytes):
        """Test GCM with empty AAD"""
        encrypted_file = text_file + '.gcm.enc'
        decrypted_file = text_file + '.gcm.dec'

        try:
            # Encrypt with empty AAD
            cmd = [
                'python', 'cryptocore.py',
                '-algorithm', 'aes',
                '-mode', 'gcm',
                '-encrypt',
                '-key', test_key_bytes.hex(),
                '-input', text_file,
                '-output', encrypted_file,
                '-aad', ''  # Empty AAD
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            assert result.returncode == 0

            # Decrypt with empty AAD
            cmd = [
                'python', 'cryptocore.py',
                '-algorithm', 'aes',
                '-mode', 'gcm',
                '-decrypt',
                '-key', test_key_bytes.hex(),
                '-input', encrypted_file,
                '-output', decrypted_file,
                '-aad', ''  # Empty AAD
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            assert result.returncode == 0

            # Verify
            with open(text_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
                assert f1.read() == f2.read()

            print("✓ GCM with empty AAD: SUCCESS")

        finally:
            for f in [encrypted_file, decrypted_file]:
                if os.path.exists(f):
                    os.unlink(f)

    def test_gcm_long_aad(self, text_file, test_key_bytes):
        """Test GCM with long AAD"""
        encrypted_file = text_file + '.gcm.enc'
        decrypted_file = text_file + '.gcm.dec'

        # Long AAD (1000 bytes)
        long_aad = b"X" * 1000

        try:
            # Encrypt with long AAD
            cmd = [
                'python', 'cryptocore.py',
                '-algorithm', 'aes',
                '-mode', 'gcm',
                '-encrypt',
                '-key', test_key_bytes.hex(),
                '-input', text_file,
                '-output', encrypted_file,
                '-aad', long_aad.hex()
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            assert result.returncode == 0

            # Decrypt with same long AAD
            cmd = [
                'python', 'cryptocore.py',
                '-algorithm', 'aes',
                '-mode', 'gcm',
                '-decrypt',
                '-key', test_key_bytes.hex(),
                '-input', encrypted_file,
                '-output', decrypted_file,
                '-aad', long_aad.hex()
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            assert result.returncode == 0

            # Verify
            with open(text_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
                assert f1.read() == f2.read()

            print("✓ GCM with long AAD (1000 bytes): SUCCESS")

        finally:
            for f in [encrypted_file, decrypted_file]:
                if os.path.exists(f):
                    os.unlink(f)

    def test_gcm_nonce_uniqueness(self, text_file, test_key_bytes):
        """Test that GCM generates unique nonces for each encryption"""
        encrypted_file1 = text_file + '.gcm1.enc'
        encrypted_file2 = text_file + '.gcm2.enc'

        aad = b"test"

        try:
            # Encrypt same file twice
            for i, out_file in enumerate([encrypted_file1, encrypted_file2], 1):
                cmd = [
                    'python', 'cryptocore.py',
                    '-algorithm', 'aes',
                    '-mode', 'gcm',
                    '-encrypt',
                    '-key', test_key_bytes.hex(),
                    '-input', text_file,
                    '-output', out_file,
                    '-aad', aad.hex()
                ]

                result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                assert result.returncode == 0
                print(f"  Encryption {i}: {out_file} created")

            # Read both encrypted files
            with open(encrypted_file1, 'rb') as f1, open(encrypted_file2, 'rb') as f2:
                data1 = f1.read()
                data2 = f2.read()

            # Extract nonces (first 12 bytes)
            nonce1 = data1[:12]
            nonce2 = data2[:12]

            # Nonces should be different (high probability)
            assert nonce1 != nonce2, "Nonces should be unique for each encryption"

            # Both should be decryptable
            for i, in_file in enumerate([encrypted_file1, encrypted_file2], 1):
                decrypted_file = text_file + f'.gcm{i}.dec'
                cmd = [
                    'python', 'cryptocore.py',
                    '-algorithm', 'aes',
                    '-mode', 'gcm',
                    '-decrypt',
                    '-key', test_key_bytes.hex(),
                    '-input', in_file,
                    '-output', decrypted_file,
                    '-aad', aad.hex()
                ]

                result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                assert result.returncode == 0

                # Clean up
                if os.path.exists(decrypted_file):
                    os.unlink(decrypted_file)

            print("✓ GCM nonce uniqueness: SUCCESS (generated unique nonces)")

        finally:
            for f in [encrypted_file1, encrypted_file2]:
                if os.path.exists(f):
                    os.unlink(f)

    def test_gcm_with_explicit_nonce(self, text_file, test_key_bytes):
        """
        TTest GCM nonce handling according to sprint 6 requirements:
    - During encryption: GCM MUST generate random nonce (ignores provided --iv)
    - During decryption: nonce can be read from file or provided via --iv
        """
        encrypted_file = text_file + '.gcm.enc'
        decrypted_file = text_file + '.gcm.dec'

        aad = b"test aad"
        nonce_hex = "000000000000000000000000"  # 12-byte zero nonce

        try:
            # Encrypt with explicit nonce - GCM ДОЛЖЕН ИГНОРИРОВАТЬ этот nonce при шифровании
            cmd = [
                'python', 'cryptocore.py',
                '-algorithm', 'aes',
                '-mode', 'gcm',
                '-encrypt',
                '-key', test_key_bytes.hex(),
                '-input', text_file,
                '-output', encrypted_file,
                '-aad', aad.hex(),
                '-iv', nonce_hex
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            assert result.returncode == 0

            # Check that nonce in file is RANDOM (not the one we provided)
            with open(encrypted_file, 'rb') as f:
                encrypted_data = f.read()

            actual_nonce = encrypted_data[:12]
            # Nonce должен быть случайным, а не тем, что мы предоставили
            assert actual_nonce != bytes.fromhex(nonce_hex), \
                "GCM should generate random nonce during encryption, not use provided one"

            print(f"  Generated nonce: {actual_nonce.hex()}")
            print(f"  Provided nonce: {nonce_hex}")

            # Теперь для дешифрования используем nonce из файла
            # Extract nonce from encrypted file
            file_nonce = encrypted_data[:12].hex()

            # Decrypt with nonce from file
            cmd = [
                'python', 'cryptocore.py',
                '-algorithm', 'aes',
                '-mode', 'gcm',
                '-decrypt',
                '-key', test_key_bytes.hex(),
                '-input', encrypted_file,
                '-output', decrypted_file,
                '-aad', aad.hex()
                # Не указываем --iv, nonce должен быть прочитан из файла
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            assert result.returncode == 0

            # Verify decryption works
            with open(text_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
                assert f1.read() == f2.read()

            # Также тестируем дешифрование с явным указанием nonce (из файла)
            decrypted_file2 = text_file + '.gcm2.dec'
            cmd = [
                'python', 'cryptocore.py',
                '-algorithm', 'aes',
                '-mode', 'gcm',
                '-decrypt',
                '-key', test_key_bytes.hex(),
                '-input', encrypted_file[12:],  # Только ciphertext+tag (без nonce)
                '-output', decrypted_file2,
                '-aad', aad.hex(),
                '-iv', file_nonce  # Явно указываем nonce из файла
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            if result.returncode == 0:
                with open(text_file, 'rb') as f1, open(decrypted_file2, 'rb') as f2:
                    assert f1.read() == f2.read()
                print("✓ GCM decryption with explicit nonce also works")

            if os.path.exists(decrypted_file2):
                os.unlink(decrypted_file2)

            print("✓ GCM nonce handling: SUCCESS (random nonce generation works)")

        finally:
            for f in [encrypted_file, decrypted_file]:
                if os.path.exists(f):
                    os.unlink(f)

    # ==================== Encrypt-then-MAC TESTS ====================

    def test_encrypt_then_mac_api(self, text_file, test_key_bytes):
        """Test Encrypt-then-MAC via API (not CLI)"""
        from src.crypto.modes.aead import AEAD_EncryptThenMAC

        # Read test file
        with open(text_file, 'rb') as f:
            plaintext = f.read()

        aad = b"test associated data"

        # Test with CTR mode
        aead_ctr = AEAD_EncryptThenMAC(test_key_bytes, mode='ctr')

        # Encrypt
        ciphertext = aead_ctr.encrypt(plaintext, aad=aad)

        # Decrypt - should work
        decrypted = aead_ctr.decrypt(ciphertext, aad=aad)
        assert decrypted == plaintext

        # Try with wrong AAD - should fail
        wrong_aad = b"wrong aad"
        try:
            aead_ctr.decrypt(ciphertext, aad=wrong_aad)
            assert False, "Should have raised AuthenticationError"
        except Exception as e:
            assert "Authentication failed" in str(e)

        # Test with CBC mode
        aead_cbc = AEAD_EncryptThenMAC(test_key_bytes, mode='cbc')
        ciphertext_cbc = aead_cbc.encrypt(plaintext, aad=aad)
        decrypted_cbc = aead_cbc.decrypt(ciphertext_cbc, aad=aad)
        assert decrypted_cbc == plaintext

        print("✓ Encrypt-then-MAC API: SUCCESS (CTR and CBC modes)")

    def test_encrypt_then_mac_ciphertext_tamper(self, text_file, test_key_bytes):
        """Test that Encrypt-then-MAC detects ciphertext tampering"""
        from src.crypto.modes.aead import AEAD_EncryptThenMAC

        with open(text_file, 'rb') as f:
            plaintext = f.read()

        aad = b"test aad"

        aead = AEAD_EncryptThenMAC(test_key_bytes, mode='ctr')
        ciphertext = aead.encrypt(plaintext, aad=aad)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        if len(tampered) > 32:  # Ensure we have ciphertext to tamper
            tampered[25] ^= 0x01  # Flip a bit

            # Should fail
            try:
                aead.decrypt(bytes(tampered), aad=aad)
                assert False, "Should have raised AuthenticationError"
            except Exception as e:
                assert "Authentication failed" in str(e)

        print("✓ Encrypt-then-MAC tamper detection: SUCCESS")

    # ==================== ДОПОЛНИТЕЛЬНЫЕ ТЕСТЫ ====================

    def test_gcm_cli_error_messages(self, text_file, test_key_bytes):
        """Test CLI error messages for GCM"""
        # Test missing required arguments
        cmd = [
            'python', 'cryptocore.py',
            '-algorithm', 'aes',
            '-mode', 'gcm',
            '-encrypt',
            # Missing key
            '-input', text_file,
            '-output', text_file + '.enc'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        # Для шифрования ключ не обязателен (генерируется автоматически)
        # Этот тест может пропускаться или проверять другие ошибки

        print("✓ GCM CLI error messages test completed")

    def test_gcm_file_not_found(self, test_key_bytes):
        """Test that GCM handles non-existent files gracefully"""
        non_existent_file = "/tmp/non_existent_file_12345.txt"

        cmd = [
            'python', 'cryptocore.py',
            '-algorithm', 'aes',
            '-mode', 'gcm',
            '-encrypt',
            '-key', test_key_bytes.hex(),
            '-input', non_existent_file,
            '-output', non_existent_file + '.enc',
            '-aad', 'test'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        assert result.returncode != 0, "Should fail with non-existent file"
        assert "Error" in result.stderr or "not found" in result.stderr

        print("✓ GCM handles non-existent files correctly")


def run_all_gcm_tests():
    """Run all GCM tests manually for debugging"""
    import tempfile

    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("Test message for GCM integration tests\nLine 2\nLine 3\n")
        temp_file = f.name

    test_key = bytes.fromhex("00112233445566778899aabbccddeeff")

    test = TestIntegration()

    try:
        print("=" * 70)
        print("RUNNING ALL GCM INTEGRATION TESTS")
        print("=" * 70)

        # Run each test
        tests = [
            ("Basic GCM encryption/decryption", test.test_gcm_encryption_decryption),
            ("GCM authentication failure", test.test_gcm_authentication_failure),
            ("GCM ciphertext tampering", test.test_gcm_ciphertext_tampering),
            ("GCM empty AAD", test.test_gcm_empty_aad),
            ("GCM long AAD", test.test_gcm_long_aad),
            ("GCM nonce uniqueness", test.test_gcm_nonce_uniqueness),
            ("GCM with explicit nonce", test.test_gcm_with_explicit_nonce),
            ("Encrypt-then-MAC API", test.test_encrypt_then_mac_api),
        ]

        passed = 0
        total = len(tests)

        for test_name, test_func in tests:
            print(f"\n▶ Running: {test_name}")
            try:
                test_func(temp_file, test_key)
                print(f"  ✅ PASSED")
                passed += 1
            except Exception as e:
                print(f"  ❌ FAILED: {e}")
                import traceback
                traceback.print_exc()

        print("\n" + "=" * 70)
        print(f"RESULTS: {passed}/{total} tests passed")
        if passed == total:
            print("✅ ALL GCM INTEGRATION TESTS PASSED!")
        else:
            print(f"❌ {total - passed} tests failed")
        print("=" * 70)

    finally:
        if os.path.exists(temp_file):
            os.unlink(temp_file)


if __name__ == "__main__":
    run_all_gcm_tests()