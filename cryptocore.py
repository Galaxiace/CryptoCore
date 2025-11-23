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