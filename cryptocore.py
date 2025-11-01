#!/usr/bin/env python3
import sys
import os

# Добавляем src в путь для импорта
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.crypto.core import encrypt_file_aes, decrypt_file_aes
from src.utils.validation import validate_hex_key, is_weak_key
from src.utils.logging_setup import setup_logger
from src.utils.csprng import generate_random_bytes


def create_parser():
    """Create CLI argument parser"""
    import argparse
    parser = argparse.ArgumentParser(description='AES Encryption/Decryption Tool')

    parser.add_argument('-algorithm', required=True, choices=['aes'],
                        help='Cipher algorithm')
    parser.add_argument('-mode', required=True,
                        choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'],
                        help='Mode of operation')
    # Сделать --key опциональным
    parser.add_argument('-key',
                        help='Encryption key as 32-character hexadecimal string (optional for encryption)')
    parser.add_argument('-input', required=True,
                        help='Input file path')
    parser.add_argument('-output',
                        help='Output file path (optional)')
    parser.add_argument('-iv',
                        help='Initialization Vector as 32-character hexadecimal string (for decryption)')

    # Mutually exclusive group for encrypt/decrypt
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-encrypt', action='store_true', help='Encrypt operation')
    group.add_argument('-decrypt', action='store_true', help='Decrypt operation')

    return parser


def validate_args(args):
    """Validate CLI arguments"""
    if args.algorithm == 'aes':
        # Для дешифрования ключ обязателен
        if args.decrypt and not args.key:
            raise ValueError("Key is required for decryption")

        # Для шифрования ключ может быть опциональным
        if args.key:
            validate_hex_key(args.key)
            # Проверка на слабый ключ (предупреждение)
            if is_weak_key(args.key):
                print(f"Warning: The provided key may be weak")

        # Validate IV if provided
        if args.iv:
            validate_hex_key(args.iv, 32, "IV")

    # Set default output filename if not provided
    if not args.output:
        if args.encrypt:
            args.output = args.input + '.enc'
        else:
            if args.input.endswith('.enc'):
                args.output = args.input[:-4]
            else:
                args.output = args.input + '.dec'

    return args


def main():
    logger = setup_logger()

    try:
        parser = create_parser()
        args = parser.parse_args()
        args = validate_args(args)

        # НОВАЯ ЛОГИКА: Генерация ключа если не предоставлен
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

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()