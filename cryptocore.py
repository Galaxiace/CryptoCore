#!/usr/bin/env python3
import sys
import os

# Добавляем src в путь для импорта
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.crypto.core import encrypt_file_aes, decrypt_file_aes
from src.utils.validation import validate_hex_key, is_weak_key
from src.utils.logging_setup import setup_logger
from src.utils.csprng import generate_random_bytes
from src.hash.sha256 import SHA256
from src.hash.sha3_256 import SHA3_256
from src.file_io import read_file_chunks, write_file, file_exists


def compute_file_hash(file_path, algorithm):
    """Compute hash of a file using specified algorithm"""
    if algorithm == 'sha256':
        hasher = SHA256()

        # Process file in chunks to handle large files
        for chunk in read_file_chunks(file_path):
            hasher.update(chunk)

        return hasher.hexdigest()

    elif algorithm == 'sha3-256':
        hasher = SHA3_256()

        # Process file in chunks to handle large files
        for chunk in read_file_chunks(file_path):
            hasher.update(chunk)

        return hasher.hexdigest()

    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def handle_hash_command(args):
    """Handle the dgst subcommand"""
    # Check if input file exists
    if not file_exists(args.input):
        raise FileNotFoundError(f"Input file not found: {args.input}")

    # HMAC mode
    if args.hmac:
        return handle_hmac_command(args)

    # Regular hash mode
    return handle_regular_hash_command(args)


def handle_regular_hash_command(args):
    """Handle regular hash computation (non-HMAC)"""
    # Compute hash
    hash_value = compute_file_hash(args.input, args.algorithm)

    # Format output (standard *sum format) - 2 SPACES for compatibility
    output_line = f"{hash_value}  {args.input}\n"

    # Output to file or stdout
    if args.output:
        write_file(args.output, output_line.encode('utf-8'))
        print(f"Hash written to: {args.output}")
    else:
        # Print without extra newline since output_line already has it
        print(output_line, end='')

    return hash_value


def handle_hmac_command(args):
    """Handle HMAC computation and verification"""
    from src.mac.hmac import HMAC

    # Initialize HMAC with key
    try:
        hmac = HMAC(args.key)
    except Exception as e:
        raise ValueError(f"Failed to initialize HMAC: {e}")

    # Verification mode
    if args.verify:
        return handle_hmac_verification(args, hmac)

    # Generation mode
    return handle_hmac_generation(args, hmac)


def handle_hmac_generation(args, hmac):
    """Generate HMAC for file"""
    # Compute HMAC
    hmac_value = hmac.compute_file(args.input)

    # Format output: HMAC_VALUE INPUT_FILE_PATH
    output_line = f"{hmac_value} {args.input}\n"

    # Output to file or stdout
    if args.output:
        write_file(args.output, output_line.encode('utf-8'))
        print(f"HMAC written to: {args.output}")
    else:
        print(output_line, end='')

    return hmac_value


def handle_hmac_verification(args, hmac):
    """Verify HMAC against expected value"""
    # Read expected HMAC from file
    if not file_exists(args.verify):
        raise FileNotFoundError(f"HMAC verification file not found: {args.verify}")

    with open(args.verify, 'r') as f:
        expected_line = f.read().strip()

    # Parse expected HMAC (flexible parsing)
    # Format: HMAC_VALUE INPUT_FILE_PATH
    parts = expected_line.split()
    if not parts:
        raise ValueError(f"Empty HMAC verification file: {args.verify}")

    # Take first non-empty part as HMAC
    expected_hmac = parts[0].strip()
    if len(expected_hmac) != 64:
        # Also try to find 64-char hex string in the line
        import re
        hex_pattern = r'([0-9a-fA-F]{64})'
        matches = re.findall(hex_pattern, expected_line)
        if matches:
            expected_hmac = matches[0]
        else:
            raise ValueError(
                f"Invalid HMAC format in verification file. Expected 64 hex chars, got {len(expected_hmac)}")

    # Compute HMAC for input file
    computed_hmac = hmac.compute_file(args.input)

    # Compare (case-insensitive)
    if computed_hmac.lower() == expected_hmac.lower():
        print("[OK] HMAC verification successful")
        sys.exit(0)
    else:
        print("[ERROR] HMAC verification failed")
        print(f"  Expected: {expected_hmac}")
        print(f"  Computed: {computed_hmac}")
        sys.exit(1)


def handle_legacy_crypto(args):
    """Handle legacy crypto commands (without 'crypto' subcommand)"""
    if args.encrypt and not args.key:
        # Генерируем случайный ключ
        key_bytes = generate_random_bytes(16)
        key_hex = key_bytes.hex()
        print(f"[INFO] Generated random key: {key_hex}")
    else:
        # Используем предоставленный ключ
        key_bytes = validate_hex_key(args.key)

    if args.encrypt:
        encrypt_file_aes(args.input, args.output, key_bytes, args.mode)
        print(f"Encryption successful. Output: {args.output}")
    else:
        decrypt_file_aes(args.input, args.output, key_bytes, args.mode, args.iv)
        print(f"Decryption successful. Output: {args.output}")


def main():
    logger = setup_logger()

    try:
        from src.cli_parser import create_parser, validate_args
        parser = create_parser()
        args = parser.parse_args()
        args = validate_args(args)

        # Определяем тип команды
        if not hasattr(args, 'command'):
            # Legacy format - прямой вызов crypto операций
            handle_legacy_crypto(args)
        elif args.command == 'crypto':
            # New format crypto command
            handle_legacy_crypto(args)  # Та же логика
        elif args.command == 'dgst':
            # New hash command
            handle_hash_command(args)
        else:
            print("Error: No command specified. Use 'crypto' for encryption/decryption or 'dgst' for hashing.")
            print("Examples:")
            print("  cryptocore crypto -algorithm aes -mode cbc -encrypt -input file.txt")
            print("  cryptocore dgst -algorithm sha256 -input file.txt")
            print("  cryptocore -algorithm aes -mode cbc -encrypt -input file.txt (legacy)")
            sys.exit(1)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()