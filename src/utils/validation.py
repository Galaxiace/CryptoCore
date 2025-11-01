import os
import os.path  # Добавить этот импорт


def validate_hex_key(key_str, expected_length=32, key_name="Key"):
    """
    Validate and convert hex key string to bytes
    expected_length: length in hex characters (32 for 16 bytes, 48 for 24 bytes, 64 for 32 bytes)
    """
    try:
        if len(key_str) != expected_length:
            raise ValueError(f"{key_name} must be {expected_length} hexadecimal characters, got {len(key_str)}")
        return bytes.fromhex(key_str)
    except ValueError as e:
        raise ValueError(f"Invalid hex {key_name.lower()}: {e}")


def validate_file_exists(file_path):
    """Check if file exists and is readable"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Input file not found: {file_path}")
    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Cannot read file: {file_path}")
    return True


def is_weak_key(key_hex: str) -> bool:
    """
    Detect weak keys (all zeros, sequential bytes, etc.)
    Returns True if key is considered weak
    """
    try:
        key_bytes = bytes.fromhex(key_hex)

        # Check for all zeros
        if all(b == 0 for b in key_bytes):
            return True

        # Check for sequential bytes
        if len(key_bytes) >= 2:
            is_sequential = True
            for i in range(1, len(key_bytes)):
                if key_bytes[i] != (key_bytes[i - 1] + 1) % 256:
                    is_sequential = False
                    break
            if is_sequential:
                return True

        # Check for repeated patterns
        if len(key_bytes) >= 4:
            # Check for repeated 2-byte pattern
            pattern = key_bytes[:2]
            repeats = True
            for i in range(2, len(key_bytes), 2):
                if key_bytes[i:i + 2] != pattern:
                    repeats = False
                    break
            if repeats:
                return True

        return False

    except:
        return False