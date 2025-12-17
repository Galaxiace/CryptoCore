# src/mac/hmac.py
from src.hash.sha256 import SHA256


class HMAC:
    """HMAC implementation following RFC 2104"""

    def __init__(self, key, hash_function='sha256'):
        """
        Initialize HMAC with key

        Args:
            key: bytes or hex string (will be converted to bytes)
            hash_function: currently only 'sha256' supported
        """
        if hash_function != 'sha256':
            raise ValueError("Only SHA-256 is currently supported")

        # Convert hex string to bytes if needed
        if isinstance(key, str):
            key = bytes.fromhex(key)
        elif not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes or hex string, got {type(key)}")

        self.hash_class = SHA256  # Сохраняем класс, не экземпляр!
        self.block_size = 64  # bytes, for SHA-256
        self.key = self._process_key(key)

    def _process_key(self, key):
        """
        Process key according to RFC 2104:
        - If key longer than block size: hash it
        - If key shorter than block size: pad with zeros
        """
        # If key is longer than block size, hash it
        if len(key) > self.block_size:
            hasher = self.hash_class()
            hasher.update(key)
            key = hasher.digest()  # Get bytes

        # If key is shorter than block size, pad with zeros
        if len(key) < self.block_size:
            key = key + b'\x00' * (self.block_size - len(key))

        return key

    @staticmethod
    def _xor_bytes(a, b):
        """XOR two byte strings of equal length"""
        return bytes(x ^ y for x, y in zip(a, b))

    def compute(self, message):
        """
        Compute HMAC(K, m) = H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ m))

        Args:
            message: bytes to compute HMAC for

        Returns:
            HMAC as hex string
        """
        if isinstance(message, str):
            message = message.encode('utf-8')

        # Create inner and outer pads
        ipad = self._xor_bytes(self.key, b'\x36' * self.block_size)
        opad = self._xor_bytes(self.key, b'\x5c' * self.block_size)

        # Inner hash: H((K ⊕ ipad) ∥ message)
        inner_hasher = self.hash_class()  # НОВЫЙ экземпляр!
        inner_hasher.update(ipad)
        inner_hasher.update(message)
        inner_hash = inner_hasher.digest()  # bytes

        # Outer hash: H((K ⊕ opad) ∥ inner_hash)
        outer_hasher = self.hash_class()  # НОВЫЙ экземпляр!
        outer_hasher.update(opad)
        outer_hasher.update(inner_hash)

        return outer_hasher.hexdigest()  # Возвращаем hex строку

    def compute_file(self, file_path, chunk_size=8192):
        """
        Compute HMAC for file (process in chunks to handle large files)

        Args:
            file_path: path to file
            chunk_size: size of chunks to read

        Returns:
            HMAC as hex string
        """
        from src.file_io import read_file_chunks

        # Create inner and outer pads
        ipad = self._xor_bytes(self.key, b'\x36' * self.block_size)
        opad = self._xor_bytes(self.key, b'\x5c' * self.block_size)

        # Compute inner hash in chunks
        inner_hasher = self.hash_class()  # НОВЫЙ экземпляр!
        inner_hasher.update(ipad)  # Start with K ⊕ ipad

        # Process file in chunks
        for chunk in read_file_chunks(file_path, chunk_size):
            inner_hasher.update(chunk)

        inner_hash = inner_hasher.digest()  # Get as bytes

        # Compute outer hash
        outer_hasher = self.hash_class()  # НОВЫЙ экземпляр!
        outer_hasher.update(opad)
        outer_hasher.update(inner_hash)

        return outer_hasher.hexdigest()  # Возвращаем hex строку

    def verify(self, message, hmac_to_check):
        """
        Verify HMAC

        Args:
            message: original message
            hmac_to_check: HMAC to verify (hex string)

        Returns:
            True if HMAC matches, False otherwise
        """
        computed_hmac = self.compute(message)
        return computed_hmac == hmac_to_check.lower()

    def verify_file(self, file_path, hmac_to_check, chunk_size=8192):
        """
        Verify HMAC for file

        Args:
            file_path: path to file
            hmac_to_check: HMAC to verify (hex string)
            chunk_size: size of chunks to read

        Returns:
            True if HMAC matches, False otherwise
        """
        computed_hmac = self.compute_file(file_path, chunk_size)
        return computed_hmac == hmac_to_check.lower()