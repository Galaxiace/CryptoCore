def read_file(file_path):
    """Read binary data from file"""
    with open(file_path, 'rb') as f:
        return f.read()

def write_file(file_path, data):
    """Write binary data to file"""
    with open(file_path, 'wb') as f:
        f.write(data)

def create_test_file(filename="plaintext.txt"):
    """Create a test file if it doesn't exist"""
    import os
    if not os.path.exists(filename):
        with open(filename, "w") as f:
            f.write("Это тестовое сообщение для проверки шифрования AES-ECB\n")
            f.write("This is a test message for AES-ECB encryption verification\n")
        return filename
    return None