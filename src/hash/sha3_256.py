import struct


class SHA3_256:
    """
    SHA3-256 implementation from scratch following NIST FIPS 202
    Using Keccak sponge construction
    """

    def __init__(self):
        # SHA3-256 parameters
        self.rate = 1088  # bits (136 bytes)
        self.capacity = 512  # bits
        self.output_length = 256  # bits

        # Initialize state: 5x5 matrix of 64-bit lanes (1600 bits total)
        self.state = [[0] * 5 for _ in range(5)]
        self.buffer = bytearray()
        self.total_length = 0

        # SHA3-256 uses padding 0x06 (SHA3) not 0x01 (Keccak)
        self.delimited_suffix = 0x06

    @staticmethod
    def rot64(a, n):
        """64-bit rotate left"""
        return ((a << n) | (a >> (64 - n))) & ((1 << 64) - 1)

    def keccak_f1600(self):
        """Keccak-f[1600] permutation"""
        # Round constants for Keccak-f[1600]
        RC = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
            0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
            0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
            0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
            0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        ]

        # 24 rounds of Keccak-f[1600]
        for round_ in range(24):
            # Theta step
            C = [self.state[x][0] ^ self.state[x][1] ^ self.state[x][2] ^
                 self.state[x][3] ^ self.state[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ self.rot64(C[(x + 1) % 5], 1) for x in range(5)]

            for x in range(5):
                for y in range(5):
                    self.state[x][y] ^= D[x]

            # Rho and Pi steps
            x, y = 1, 0
            current = self.state[x][y]

            for t in range(24):
                X, Y = y, (2 * x + 3 * y) % 5
                temp = self.state[X][Y]
                self.state[X][Y] = self.rot64(current, (t + 1) * (t + 2) // 2 % 64)
                current = temp
                x, y = X, Y

            # Chi step
            for y in range(5):
                T = [self.state[x][y] for x in range(5)]
                for x in range(5):
                    self.state[x][y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5])

            # Iota step
            self.state[0][0] ^= RC[round_]

    def absorb(self):
        """Absorb data from buffer into state"""
        block_size = self.rate // 8  # 136 bytes

        while len(self.buffer) >= block_size:
            block = self.buffer[:block_size]
            self.buffer = self.buffer[block_size:]

            # Convert block to lanes and XOR into state
            for i in range(block_size // 8):
                lane = struct.unpack('<Q', block[i * 8:(i + 1) * 8])[0]
                x, y = i % 5, i // 5
                self.state[x][y] ^= lane

            self.keccak_f1600()

    def pad(self):
        """Apply SHA3 padding"""
        block_size = self.rate // 8  # 136 bytes

        # Padding rule: M || 0x06 || 0x00... || 0x80
        self.buffer.append(self.delimited_suffix)

        # Pad with zeros until we have exactly block_size - 1
        while len(self.buffer) % block_size != block_size - 1:
            self.buffer.append(0x00)

        # Final byte
        self.buffer.append(0x80)

    def update(self, data):
        """Update hash with new data"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        self.total_length += len(data)
        self.buffer.extend(data)
        self.absorb()

    def digest(self):
        """Return final hash digest"""
        # Apply padding
        self.pad()
        self.absorb()

        # Squeeze output
        output_bytes = self.output_length // 8  # 32 bytes
        result = bytearray()
        block_size = self.rate // 8  # 136 bytes

        while len(result) < output_bytes:
            # Extract lanes to bytes (little-endian)
            for i in range(min(block_size // 8, (output_bytes - len(result) + 7) // 8)):
                x, y = i % 5, i // 5
                result.extend(struct.pack('<Q', self.state[x][y]))

            if len(result) < output_bytes:
                self.keccak_f1600()

        return bytes(result[:output_bytes])

    def hexdigest(self):
        """Return final hash as hexadecimal string"""
        return self.digest().hex()

    def hash(self, data):
        """Convenience method to hash data in one call"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.update(data)
        return self.hexdigest()