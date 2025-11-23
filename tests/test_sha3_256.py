from src.hash.sha3_256 import SHA3_256


def test_sha3_256_known_vectors():
    """Test SHA3-256 with known test vectors"""

    # Test 1: Empty string
    hasher = SHA3_256()
    result = hasher.hash(b"")
    expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    assert result == expected, f"Empty string: Expected {expected}, got {result}"
    print("SHA3-256 Empty string test passed")

    # Test 2: "abc"
    hasher = SHA3_256()
    result = hasher.hash("abc")
    expected = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    assert result == expected, f"'abc' test: Expected {expected}, got {result}"
    print("SHA3-256 'abc' test passed")

    # Test 3: Longer string
    hasher = SHA3_256()
    result = hasher.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    expected = "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
    assert result == expected, f"Long string: Expected {expected}, got {result}"
    print("SHA3-256 Long string test passed")


if __name__ == "__main__":
    test_sha3_256_known_vectors()
    print("All SHA3-256 tests passed!")