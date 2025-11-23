import os
import tempfile
import subprocess
from src.hash.sha256 import SHA256
from src.file_io import read_file_chunks


def test_sha256_empty_string():
    """Test SHA-256 of empty string - NIST known answer"""
    print("Testing empty string...")
    hasher = SHA256()
    result = hasher.hash(b"")
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert result == expected, f"Empty string: Expected {expected}, got {result}"
    print("Empty string test passed")


def test_sha256_abc():
    """Test SHA-256 of 'abc' - NIST known answer"""
    print("Testing 'abc' string...")
    hasher = SHA256()
    result = hasher.hash("abc")
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert result == expected, f"'abc' test: Expected {expected}, got {result}"
    print("'abc' test passed")


def test_sha256_long_string():
    """Test SHA-256 of longer string"""
    print("Testing longer string...")
    test_str = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    hasher = SHA256()
    result = hasher.hash(test_str)
    expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    assert result == expected, f"Long string: Expected {expected}, got {result}"
    print("Long string test passed")


def test_sha256_file_chunk_processing():
    """Test that file processing in chunks works correctly"""
    print("Testing chunk processing...")

    # Create a temporary file
    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
        test_data = b"Test data for chunk processing " * 1000  # ~28KB
        f.write(test_data)
        temp_path = f.name

    try:
        # Method 1: Hash entire file at once
        hasher1 = SHA256()
        with open(temp_path, 'rb') as f:
            data = f.read()
        hash1 = hasher1.hash(data)

        # Method 2: Hash file in chunks (simulating large file processing)
        hasher2 = SHA256()
        for chunk in read_file_chunks(temp_path, chunk_size=4096):
            hasher2.update(chunk)
        hash2 = hasher2.hexdigest()

        # Both methods should produce identical results
        assert hash1 == hash2, f"Chunk processing failed: {hash1} != {hash2}"
        print("Chunk processing test passed")

    finally:
        os.unlink(temp_path)


def test_avalanche_effect():
    """Test that changing one bit produces completely different hash"""
    print("Testing avalanche effect...")

    original_data = b"Hello, world!"
    modified_data = b"Hello, world?"  # Changed last character

    sha256 = SHA256()
    hash1 = sha256.hash(original_data)

    sha256 = SHA256()  # Reset
    hash2 = sha256.hash(modified_data)

    # Convert to binary and count differing bits
    bin1 = bin(int(hash1, 16))[2:].zfill(256)
    bin2 = bin(int(hash2, 16))[2:].zfill(256)

    diff_count = sum(bit1 != bit2 for bit1, bit2 in zip(bin1, bin2))

    print(f"Bits changed: {diff_count}/256")
    # Avalanche effect: should be ~128 bits changed (50%)
    assert 100 < diff_count < 156, f"Avalanche effect weak: only {diff_count} bits changed"
    print("Avalanche effect test passed")


def test_cli_integration():
    """Test that CLI command works correctly"""
    print("Testing CLI integration...")

    # Create test file
    test_content = "CLI integration test"
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(test_content)
        input_file = f.name

    output_file = input_file + '.hash'

    try:
        # Run CLI command
        result = subprocess.run([
            'python', 'cryptocore.py',
            'dgst',
            '-algorithm', 'sha256',
            '-input', input_file,
            '-output', output_file
        ], capture_output=True, text=True)

        assert result.returncode == 0, f"CLI command failed: {result.stderr}"

        # Check output file was created and has content
        assert os.path.exists(output_file), "Output file was not created"

        with open(output_file, 'r') as f:
            output_content = f.read().strip()

        # Output should be in format: HASH_VALUE  FILENAME
        assert len(output_content) > 0, "Output file is empty"
        assert input_file in output_content, "Filename not in output"

        # Extract hash and verify it's correct
        hash_value = output_content.split()[0]
        assert len(hash_value) == 64, "Hash length incorrect"
        assert all(c in '0123456789abcdef' for c in hash_value), "Hash contains invalid characters"

        print("CLI integration test passed")

    finally:
        # Cleanup
        if os.path.exists(input_file):
            os.unlink(input_file)
        if os.path.exists(output_file):
            os.unlink(output_file)


def run_all_tests():
    """Run all hash tests"""
    print("Starting SHA-256 Test Suite...\n")

    tests = [
        test_sha256_empty_string,
        test_sha256_abc,
        test_sha256_long_string,
        test_sha256_file_chunk_processing,
        test_avalanche_effect,
        test_cli_integration
    ]

    for test in tests:
        try:
            test()
        except Exception as e:
            print(f"{test.__name__} failed: {e}")
            return False

    print(f"\nAll {len(tests)} tests passed! SHA-256 implementation is working correctly.")
    return True


if __name__ == "__main__":
    run_all_tests()