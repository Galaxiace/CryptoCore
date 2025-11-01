import subprocess
import pytest
import tempfile
import os
import sys


class TestCLI:
    def test_cli_help(self):
        """Test that CLI shows help without errors"""
        # Запускаем из текущей директории (корневой)
        result = subprocess.run([
            sys.executable, '-m', 'cryptocore', '--help'
        ], capture_output=True, text=True)

        print(f"Help stdout: {result.stdout}")
        print(f"Help stderr: {result.stderr}")
        assert result.returncode == 0
        assert 'usage:' in result.stdout

    def test_cli_encrypt_decrypt(self):
        """Test CLI using direct python execution"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("CLI test content")
            test_file = f.name

        encrypted_file = test_file + '.enc'
        decrypted_file = test_file + '.dec'

        try:
            # Encrypt
            result = subprocess.run([
                sys.executable, '-m', 'cryptocore',
                '-algorithm', 'aes',
                '-mode', 'ecb',
                '-encrypt',
                '-key', '00112233445566778899aabbccddeeff',
                '-input', test_file,
                '-output', encrypted_file
            ], capture_output=True, text=True)

            assert result.returncode == 0, f"Encryption failed: {result.stderr}"
            assert os.path.exists(encrypted_file)

            # Decrypt
            result = subprocess.run([
                sys.executable, '-m', 'cryptocore',
                '-algorithm', 'aes',
                '-mode', 'ecb',
                '-decrypt',
                '-key', '00112233445566778899aabbccddeeff',
                '-input', encrypted_file,
                '-output', decrypted_file
            ], capture_output=True, text=True)

            assert result.returncode == 0, f"Decryption failed: {result.stderr}"
            assert os.path.exists(decrypted_file)

            # Verify
            with open(test_file, 'rb') as f:
                original = f.read()
            with open(decrypted_file, 'rb') as f:
                decrypted = f.read()

            assert original == decrypted

        finally:
            for f in [test_file, encrypted_file, decrypted_file]:
                if os.path.exists(f):
                    os.unlink(f)

    def test_cli_missing_args(self):
        """Test that CLI fails with missing required arguments"""
        result = subprocess.run([
            sys.executable, '-m', 'cryptocore',
            '-algorithm', 'aes'
        ], capture_output=True, text=True)

        assert result.returncode != 0

    def test_cli_encrypt_without_key(self):
        """TEST-1: Encryption without --key should generate random key"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test content for auto key generation")
            test_file = f.name

        encrypted_file = test_file + '.enc'
        decrypted_file = test_file + '.dec'

        try:
            # Encrypt without --key
            result = subprocess.run([
                sys.executable, '-m', 'cryptocore',
                '-algorithm', 'aes',
                '-mode', 'ecb',
                '-encrypt',
                '-input', test_file,
                '-output', encrypted_file
            ], capture_output=True, text=True)

            assert result.returncode == 0, f"Encryption failed: {result.stderr}"
            assert os.path.exists(encrypted_file)

            # Check that key was generated and printed
            assert "Generated random key:" in result.stdout
            assert "[INFO]" in result.stdout

            # Extract the generated key from output
            lines = result.stdout.split('\n')
            key_line = [line for line in lines if "Generated random key:" in line][0]
            generated_key = key_line.split(": ")[1].strip()

            # Verify key format (32 hex chars = 16 bytes)
            assert len(generated_key) == 32
            assert all(c in '0123456789abcdef' for c in generated_key)

            # Decrypt with the generated key
            result = subprocess.run([
                sys.executable, '-m', 'cryptocore',
                '-algorithm', 'aes',
                '-mode', 'ecb',
                '-decrypt',
                '-key', generated_key,
                '-input', encrypted_file,
                '-output', decrypted_file
            ], capture_output=True, text=True)

            assert result.returncode == 0, f"Decryption failed: {result.stderr}"
            assert os.path.exists(decrypted_file)

            # Verify decryption worked
            with open(test_file, 'rb') as f:
                original = f.read()
            with open(decrypted_file, 'rb') as f:
                decrypted = f.read()

            assert original == decrypted

        finally:
            for f in [test_file, encrypted_file, decrypted_file]:
                if os.path.exists(f):
                    os.unlink(f)

    def test_cli_decrypt_without_key_fails(self):
        """Decryption without --key should fail"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test content")
            test_file = f.name

        try:
            # Try to decrypt without key
            result = subprocess.run([
                sys.executable, '-m', 'cryptocore',
                '-algorithm', 'aes',
                '-mode', 'ecb',
                '-decrypt',
                '-input', test_file,
                '-output', 'output.txt'
            ], capture_output=True, text=True)

            assert result.returncode != 0
            assert "Key is required for decryption" in result.stderr

        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)

    def test_cli_weak_key_warning(self):
        """Test that weak keys generate warnings"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test content")
            test_file = f.name

        encrypted_file = test_file + '.enc'

        try:
            # Use weak key (all zeros)
            result = subprocess.run([
                sys.executable, '-m', 'cryptocore',
                '-algorithm', 'aes',
                '-mode', 'ecb',
                '-encrypt',
                '-key', '0' * 32,  # All zeros - weak key
                '-input', test_file,
                '-output', encrypted_file
            ], capture_output=True, text=True)

            # Should still work but with warning
            assert result.returncode == 0
            assert "Warning: The provided key may be weak" in result.stdout

        finally:
            for f in [test_file, encrypted_file]:
                if os.path.exists(f):
                    os.unlink(f)

    def test_cli_auto_key_different_each_time(self):
        """Generated keys should be different each time"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test content for key uniqueness")
            test_file = f.name

        encrypted_file1 = test_file + '.1.enc'
        encrypted_file2 = test_file + '.2.enc'

        try:
            # First encryption
            result1 = subprocess.run([
                sys.executable, '-m', 'cryptocore',
                '-algorithm', 'aes',
                '-mode', 'ecb',
                '-encrypt',
                '-input', test_file,
                '-output', encrypted_file1
            ], capture_output=True, text=True)

            # Second encryption
            result2 = subprocess.run([
                sys.executable, '-m', 'cryptocore',
                '-algorithm', 'aes',
                '-mode', 'ecb',
                '-encrypt',
                '-input', test_file,
                '-output', encrypted_file2
            ], capture_output=True, text=True)

            assert result1.returncode == 0
            assert result2.returncode == 0

            # Extract keys
            key1 = [line for line in result1.stdout.split('\n') if "Generated random key:" in line][0].split(": ")[1]
            key2 = [line for line in result2.stdout.split('\n') if "Generated random key:" in line][0].split(": ")[1]

            # Keys should be different
            assert key1 != key2, "Auto-generated keys should be unique"

        finally:
            for f in [test_file, encrypted_file1, encrypted_file2]:
                if os.path.exists(f):
                    os.unlink(f)