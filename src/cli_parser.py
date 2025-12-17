# src/cli_parser.py
import argparse
import sys
from src.utils.validation import validate_hex_key, is_weak_key


def create_parser():
    parser = argparse.ArgumentParser(description='CryptoCore - Encryption/Decryption and Hashing Tool')

    # Сначала пробуем старый формат (backward compatibility)
    try:
        # Проверяем аргументы для старого формата
        if any(arg in ['-encrypt', '-decrypt'] for arg in sys.argv):
            return create_legacy_parser()
    except:
        pass

    # Новый формат с подкомандами
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Encrypt/Decrypt command
    crypto_parser = subparsers.add_parser('crypto', help='Encryption/decryption operations')
    crypto_parser.add_argument('-algorithm', required=True, choices=['aes'],
                               help='Cipher algorithm')
    crypto_parser.add_argument('-mode', required=True,
                               choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'],
                               help='Mode of operation')
    crypto_parser.add_argument('-key',
                               help='Encryption key as 32-character hexadecimal string (optional for encryption)')
    crypto_parser.add_argument('-input', required=True,
                               help='Input file path')
    crypto_parser.add_argument('-output',
                               help='Output file path (optional)')
    crypto_parser.add_argument('-iv',
                               help='Initialization Vector as 32-character hexadecimal string (for decryption)')

    # Mutually exclusive group for encrypt/decrypt
    group = crypto_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-encrypt', action='store_true', help='Encrypt operation')
    group.add_argument('-decrypt', action='store_true', help='Decrypt operation')

    # Hash command (extended for HMAC)
    hash_parser = subparsers.add_parser('dgst', help='Compute message digests (hash) and HMAC')
    hash_parser.add_argument('-algorithm', required=True,
                             choices=['sha256', 'sha3-256', 'blake2'],
                             help='Hash algorithm')
    hash_parser.add_argument('-input', required=True,
                             help='Input file path to be hashed')
    hash_parser.add_argument('-output',
                             help='Output file to write hash (optional)')

    # HMAC-specific options
    hmac_group = hash_parser.add_argument_group('HMAC options')
    hmac_group.add_argument('--hmac', action='store_true',
                            help='Enable HMAC mode')
    hmac_group.add_argument('--key',
                            help='Key for HMAC as hexadecimal string (required when --hmac is used)')
    hmac_group.add_argument('--verify',
                            help='Verify HMAC against value in specified file')
    hmac_group.add_argument('--cmac', action='store_true',
                            help='Use AES-CMAC instead of HMAC')

    return parser


def create_legacy_parser():
    """Создает парсер для старого формата команд (backward compatibility)"""
    parser = argparse.ArgumentParser(description='AES Encryption/Decryption Tool')

    parser.add_argument('-algorithm', required=True, choices=['aes'],
                        help='Cipher algorithm')
    parser.add_argument('-mode', required=True,
                        choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'],
                        help='Mode of operation')
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
    # Определяем тип команды по наличию атрибута 'command'
    if not hasattr(args, 'command') or args.command == 'crypto':
        # Legacy format or crypto command
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

            # Validate mode-specific requirements
            if args.mode != 'ecb' and args.decrypt and not args.iv:
                # For non-ECB decryption without --iv, we'll read IV from file
                # This is allowed, so no validation error here
                pass

        # Set default output filename if not provided
        if not args.output:
            if args.encrypt:
                args.output = args.input + '.enc'
            else:
                if args.input.endswith('.enc'):
                    args.output = args.input[:-4]
                else:
                    args.output = args.input + '.dec'

    elif args.command == 'dgst':
        # Hash command validation
        if not args.input:
            raise ValueError("Input file is required for hash computation")

        # HMAC-specific validation
        if args.hmac:
            if not args.key:
                raise ValueError("Key is required when --hmac is used")
            # Validate key format
            try:
                # Accept any length for HMAC key
                key_bytes = bytes.fromhex(args.key)
                if len(key_bytes) == 0:
                    raise ValueError("Key cannot be empty")
            except ValueError as e:
                raise ValueError(f"Invalid key format: {e}")

            # CMAC validation (bonus)
            if args.cmac:
                if args.algorithm != 'sha256':
                    print("Warning: CMAC uses AES, not hash algorithm")
                # CMAC requires specific key lengths
                if len(key_bytes) not in [16, 24, 32]:
                    raise ValueError("CMAC key must be 16, 24, or 32 bytes (32, 48, or 64 hex chars)")

        # Check for conflicting options
        if args.verify and args.output:
            print("Warning: --verify and --output both specified, --verify takes precedence")

    return args