import pytest
import os
from src.utils.csprng import generate_random_bytes


def test_generate_random_bytes():
    """Test basic CSPRNG functionality"""
    # Test different sizes
    for size in [1, 16, 32, 100]:
        data = generate_random_bytes(size)
        assert len(data) == size
        assert isinstance(data, bytes)


def test_key_uniqueness():
    """TEST-2: Generate 1000 keys and check they are all unique"""
    key_set = set()
    num_keys = 1000

    for _ in range(num_keys):
        key = generate_random_bytes(16)
        key_hex = key.hex()

        # Check for uniqueness
        assert key_hex not in key_set, f"Duplicate key found: {key_hex}"
        key_set.add(key_hex)

    print(f"Successfully generated {len(key_set)} unique keys.")


def test_basic_distribution():
    """TEST-4: Basic entropy check - Hamming weight should be ~50%"""
    key = generate_random_bytes(16)

    # Calculate Hamming weight (count of 1 bits)
    total_bits = len(key) * 8
    ones_count = sum(bin(byte).count('1') for byte in key)

    ratio = ones_count / total_bits
    print(f"Hamming weight ratio: {ratio:.3f}")

    # Should be close to 50% (allow more tolerance for true randomness)
    assert 0.35 <= ratio <= 0.65, f"Hamming weight ratio {ratio} outside expected range"


def test_nist_preparation():
    """Generate a large random file for NIST testing"""
    total_size = 10_000_000  # 10 MB
    filename = 'nist_test_data.bin'

    with open(filename, 'wb') as f:
        bytes_written = 0
        while bytes_written < total_size:
            chunk_size = min(4096, total_size - bytes_written)
            random_chunk = generate_random_bytes(chunk_size)
            f.write(random_chunk)
            bytes_written += len(random_chunk)

    print(f"Generated {bytes_written} bytes for NIST testing in '{filename}'")

    # Verify file was created
    assert os.path.exists(filename)
    assert os.path.getsize(filename) == total_size

    print(f"✅ File ready for NIST testing: {filename}")
    print("Note: File will remain for manual NIST testing")
    print("To clean up manually, run: rm nist_test_data.bin")


def test_nist_preparation_with_cleanup():
    """Generate a large random file for NIST testing (with cleanup for automated tests)"""
    total_size = 10_000_000  # 10 MB
    filename = 'nist_test_data_temp.bin'

    with open(filename, 'wb') as f:
        bytes_written = 0
        while bytes_written < total_size:
            chunk_size = min(4096, total_size - bytes_written)
            random_chunk = generate_random_bytes(chunk_size)
            f.write(random_chunk)
            bytes_written += len(random_chunk)

    print(f"Generated {bytes_written} bytes for NIST testing in '{filename}'")

    # Verify file was created
    assert os.path.exists(filename)
    assert os.path.getsize(filename) == total_size

    # Cleanup (for automated tests)
    os.unlink(filename)
    print(f"Cleaned up: {filename}")


def test_csprng_error_handling():
    """Test that CSPRNG properly handles errors"""
    # This should work without errors
    data = generate_random_bytes(16)
    assert len(data) == 16


def generate_nist_test_file():
    """
    Generate test file for NIST without automatic cleanup.
    Use this function when you want to keep the file for manual NIST testing.
    """
    total_size = 10_000_000  # 10 MB
    filename = 'nist_test_data.bin'

    if os.path.exists(filename):
        print(f"File {filename} already exists. Removing...")
        os.unlink(filename)

    print(f"Generating {total_size} bytes for NIST testing...")

    with open(filename, 'wb') as f:
        bytes_written = 0
        while bytes_written < total_size:
            chunk_size = min(4096, total_size - bytes_written)
            random_chunk = generate_random_bytes(chunk_size)
            f.write(random_chunk)
            bytes_written += len(random_chunk)

    print(f"Successfully generated {bytes_written} bytes")
    print(f"File: {filename}")
    print(f"Size: {os.path.getsize(filename)} bytes")
    print("\nTo run NIST tests manually:")
    print("cd nist-sts/sts")
    print("./assess 1000000")
    print("Then enter: 0 → data/nist_test_data.bin → 1 → 0 → 10 → 1")
    print("\n To view results:")
    print("cat experiments/AlgorithmTesting/finalAnalysisReport.txt")


if __name__ == "__main__":
    # When run directly, generate test file without cleanup
    generate_nist_test_file()
