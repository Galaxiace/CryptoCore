def validate_hex_key(key_str):
    """Validate and convert hex key string to bytes"""
    try:
        if len(key_str) != 32:  # 16 bytes = 32 hex chars
            raise ValueError("Key must be 32 hexadecimal characters (16 bytes) for AES-128")
        return bytes.fromhex(key_str)
    except ValueError as e:
        raise ValueError(f"Invalid hex key: {e}")

def validate_file_exists(file_path):
    """Check if file exists and is readable"""
    import os
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Input file not found: {file_path}")
    return True