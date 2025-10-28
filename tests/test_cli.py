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