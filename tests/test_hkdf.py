# tests/test_hkdf.py
import unittest
from src.kdf.hkdf import derive_key, derive_key_hex


class TestHKDF(unittest.TestCase):

    def test_deterministic(self):
        """Test that same inputs produce same output"""
        master_key = b'\x00' * 32
        context = "encryption"
        length = 32

        result1 = derive_key(master_key, context, length)
        result2 = derive_key(master_key, context, length)

        self.assertEqual(result1, result2)

    def test_context_separation(self):
        """Test that different contexts produce different keys"""
        master_key = b'\x01' * 32

        key1 = derive_key(master_key, "encryption", 32)
        key2 = derive_key(master_key, "authentication", 32)
        key3 = derive_key(master_key, "mac", 32)

        # All should be different
        self.assertNotEqual(key1, key2)
        self.assertNotEqual(key1, key3)
        self.assertNotEqual(key2, key3)

    def test_various_lengths(self):
        """Test deriving keys of various lengths"""
        master_key = b'\x02' * 32
        context = "test"

        for length in [1, 16, 32, 64, 100]:
            result = derive_key(master_key, context, length)
            self.assertEqual(len(result), length)

    def test_hex_output(self):
        """Test convenience hex function"""
        master_key = b'\x03' * 32
        context = "test"
        length = 32

        result_bytes = derive_key(master_key, context, length)
        result_hex = derive_key_hex(master_key, context, length)

        self.assertEqual(result_hex, result_bytes.hex())


if __name__ == '__main__':
    unittest.main()