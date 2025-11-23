import struct


class SHA256:
    def __init__(self):
        # Initialize hash values (first 32 bits of fractional parts of square roots of first 8 primes 2..19)
        self.h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

        # Initialize round constants (first 32 bits of fractional parts of cube roots of first 64 primes 2..311)
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

        self.message_length = 0
        self.buffer = b''

    @staticmethod
    def right_rotate(n, b):
        return ((n >> b) | (n << (32 - b))) & 0xffffffff

    def padding(self, message_length):
        """Implement SHA-256 padding for final block"""
        ml = message_length * 8  # message length in bits

        # Padding: append bit '1', then zeros, then 64-bit length
        padding = b'\x80'  # append bit '1'

        # Calculate zeros needed
        length_with_padding = (message_length + len(padding)) * 8
        zeros_needed = (448 - length_with_padding) % 512
        if zeros_needed < 0:
            zeros_needed += 512
        zeros_needed = zeros_needed // 8

        padding += b'\x00' * zeros_needed
        padding += ml.to_bytes(8, byteorder='big')

        return padding

    def process_block(self, block):
        """Process one 512-bit (64-byte) block"""
        if len(block) != 64:
            raise ValueError(f"Block must be 64 bytes, got {len(block)}")

        # Break block into sixteen 32-bit big-endian words
        w = list(struct.unpack('>16L', block))

        # Extend the sixteen 32-bit words into sixty-four 32-bit words
        for i in range(16, 64):
            s0 = self.right_rotate(w[i - 15], 7) ^ self.right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = self.right_rotate(w[i - 2], 17) ^ self.right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)

        # Initialize working variables to current hash value
        a, b, c, d, e, f, g, h = self.h

        # Compression function main loop
        for i in range(64):
            s1 = self.right_rotate(e, 6) ^ self.right_rotate(e, 11) ^ self.right_rotate(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + s1 + ch + self.k[i] + w[i]) & 0xffffffff
            s0 = self.right_rotate(a, 2) ^ self.right_rotate(a, 13) ^ self.right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xffffffff

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        # Add this chunk's hash to result so far
        self.h[0] = (self.h[0] + a) & 0xffffffff
        self.h[1] = (self.h[1] + b) & 0xffffffff
        self.h[2] = (self.h[2] + c) & 0xffffffff
        self.h[3] = (self.h[3] + d) & 0xffffffff
        self.h[4] = (self.h[4] + e) & 0xffffffff
        self.h[5] = (self.h[5] + f) & 0xffffffff
        self.h[6] = (self.h[6] + g) & 0xffffffff
        self.h[7] = (self.h[7] + h) & 0xffffffff

    def update(self, data):
        """Update the hash with new data"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        self.message_length += len(data)
        self.buffer += data

        # Process full blocks
        while len(self.buffer) >= 64:
            self.process_block(self.buffer[:64])
            self.buffer = self.buffer[64:]

    def digest(self):
        """Return final hash as bytes"""
        # Process final block with padding
        padding = self.padding(self.message_length)
        final_data = self.buffer + padding

        # Process any remaining full blocks after padding
        for i in range(0, len(final_data), 64):
            if i + 64 <= len(final_data):
                self.process_block(final_data[i:i + 64])

        # Convert hash values to bytes (big-endian)
        return b''.join(struct.pack('>L', h) for h in self.h)

    def hexdigest(self):
        """Return final hash as hexadecimal string (lowercase)"""
        return self.digest().hex()

    def hash(self, data):
        """Convenience method to hash data in one call"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.update(data)
        return self.hexdigest()