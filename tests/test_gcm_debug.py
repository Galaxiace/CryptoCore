# test_gcm_debug.py
import sys
sys.path.insert(0, '.')

from src.crypto.modes.gcm import GCM_MODE
from src.utils.csprng import generate_random_bytes

# Test 1: Basic
print("Test 1: Basic GCM with empty AAD")
key = generate_random_bytes(16)
gcm = GCM_MODE(key)
plaintext = b"Hello GCM"
aad = b""

print(f"Key: {key.hex()}")
print(f"Plaintext: {plaintext}")
print(f"AAD: {aad}")

# Encrypt
ciphertext = gcm.encrypt(plaintext, aad=aad)
print(f"Ciphertext length: {len(ciphertext)}")
print(f"Ciphertext hex: {ciphertext.hex()}")

# Decrypt
try:
    decrypted = gcm.decrypt(ciphertext, aad=aad)
    print(f"Decrypted: {decrypted}")
    if decrypted == plaintext:
        print("✓ SUCCESS")
    else:
        print(f"✗ FAIL: {decrypted} != {plaintext}")
except Exception as e:
    print(f"✗ ERROR: {e}")

# Test 2: With AAD
print("\n\nTest 2: GCM with AAD")
key = generate_random_bytes(16)
gcm = GCM_MODE(key)
plaintext = b"Hello GCM with AAD"
aad = b"my_aad_data"

print(f"Key: {key.hex()}")
print(f"Plaintext: {plaintext}")
print(f"AAD: {aad}")

# Encrypt
ciphertext = gcm.encrypt(plaintext, aad=aad)
print(f"Ciphertext length: {len(ciphertext)}")

# Decrypt with correct AAD
try:
    decrypted = gcm.decrypt(ciphertext, aad=aad)
    print(f"Decrypted with correct AAD: {decrypted}")
    if decrypted == plaintext:
        print("✓ SUCCESS with correct AAD")
    else:
        print(f"✗ FAIL: {decrypted} != {plaintext}")
except Exception as e:
    print(f"✗ ERROR with correct AAD: {e}")

# Try with wrong AAD
try:
    wrong_aad = b"wrong_aad"
    decrypted = gcm.decrypt(ciphertext, aad=wrong_aad)
    print(f"✗ SHOULD HAVE FAILED with wrong AAD but got: {decrypted}")
except Exception as e:
    print(f"✓ Correctly failed with wrong AAD: {e}")