import os

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