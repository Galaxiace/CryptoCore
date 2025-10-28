from Crypto.Cipher import AES

class AES_ECB_MODE:
    def __init__(self, key):
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes long")
        self.key = key
        self.cipher = AES.new(key, AES.MODE_ECB)

    def _pad(self, data):
        """PKCS#7 padding"""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data):
        """Remove PKCS#7 padding"""
        if len(data) == 0:
            return data

        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding")

        if not all(b == pad_len for b in data[-pad_len:]):
            raise ValueError("Invalid padding")

        return data[:-pad_len]

    def encrypt(self, plaintext, iv=None):
        """Encrypt data using AES-ECB with PKCS#7 padding"""
        # ECB doesn't use IV, but we accept the parameter for compatibility
        padded_data = self._pad(plaintext)
        ciphertext = b''

        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i + 16]
            encrypted_block = self.cipher.encrypt(block)
            ciphertext += encrypted_block

        return ciphertext

    def decrypt(self, ciphertext, iv=None):
        """Decrypt data using AES-ECB with PKCS#7 padding removal"""
        # ECB doesn't use IV, but we accept the parameter for compatibility
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16 bytes")

        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            decrypted_block = self.cipher.decrypt(block)
            plaintext += decrypted_block

        return self._unpad(plaintext)