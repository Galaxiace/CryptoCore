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
                               choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr', 'gcm', 'encrypt-then-mac'],
                               help='Mode of operation')
    crypto_parser.add_argument('-key',
                               help='Encryption key as 32-character hexadecimal string (optional for encryption)')
    crypto_parser.add_argument('-input', required=True,
                               help='Input file path')
    crypto_parser.add_argument('-output',
                               help='Output file path (optional)')
    crypto_parser.add_argument('-iv',
                               help='Initialization Vector/Nonce as hex string')
    crypto_parser.add_argument('-aad',
                               help='Associated Authenticated Data as hex string (for GCM/EAAD modes)')
    crypto_parser.add_argument('--nonce',
                               help='Nonce for GCM mode (alias for -iv)')

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

    # Derive command (NEW - Sprint 7)
    derive_parser = subparsers.add_parser('derive', help='Key derivation from passwords')
    derive_parser.add_argument('--password', required=True,
                               help='Password string (use quotes for special characters)')
    derive_parser.add_argument('--salt',
                               help='Salt as hexadecimal string (if not provided, random salt will be generated)')
    derive_parser.add_argument('--iterations', type=int, default=100000,
                               help='Number of iterations (default: 100000)')
    derive_parser.add_argument('--length', type=int, default=32,
                               help='Key length in bytes (default: 32)')
    derive_parser.add_argument('--algorithm', default='pbkdf2',
                               choices=['pbkdf2'],
                               help='KDF algorithm (currently only pbkdf2)')
    derive_parser.add_argument('--output',
                               help='Output file to write derived key (optional)')
    derive_parser.add_argument('--show-salt', action='store_true',
                               help='Print generated salt (when no salt provided)')

    return parser


def create_legacy_parser():
    """Создает парсер для старого формата команд (backward compatibility)"""
    parser = argparse.ArgumentParser(description='AES Encryption/Decryption Tool')

    parser.add_argument('-algorithm', required=True, choices=['aes'],
                        help='Cipher algorithm')
    parser.add_argument('-mode', required=True,
                        choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr', 'gcm', 'encrypt-then-mac'],
                        help='Mode of operation')
    parser.add_argument('-key',
                        help='Encryption key as 32-character hexadecimal string (optional for encryption)')
    parser.add_argument('-input', required=True,
                        help='Input file path')
    parser.add_argument('-output',
                        help='Output file path (optional)')
    parser.add_argument('-iv',
                        help='Initialization Vector/Nonce as hex string')
    parser.add_argument('-aad',
                        help='Associated Authenticated Data as hex string (for GCM/EAAD modes)')

    # Mutually exclusive group for encrypt/decrypt
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-encrypt', action='store_true', help='Encrypt operation')
    group.add_argument('-decrypt', action='store_true', help='Decrypt operation')

    return parser


def validate_args(args):
    """Validate CLI arguments"""
    # Handle --nonce alias for -iv
    if hasattr(args, 'nonce') and args.nonce and not args.iv:
        args.iv = args.nonce

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

            # Validate IV/Nonce if provided
            if args.iv:
                # Для GCM используем специальную логику, так как nonce 12 байт (24 hex символа)
                if args.mode == 'gcm':
                    # GCM использует 12-байтный nonce (24 hex символа)
                    # Но ваша функция validate_hex_key требует 32 символа для IV
                    # Поэтому для GCM делаем отдельную проверку
                    try:
                        nonce_bytes = bytes.fromhex(args.iv)
                        if len(args.iv) != 24:
                            # Для GCM можно принять разную длину, но выведем предупреждение
                            print(f"Warning: GCM typically uses 12-byte nonce (24 hex chars), got {len(args.iv)}")
                            if len(args.iv) == 32:
                                print("Info: 32 hex chars detected - treating as 16-byte IV (not standard for GCM)")
                    except ValueError:
                        raise ValueError("IV/Nonce must be a valid hexadecimal string")
                else:
                    # Для других режимов используем стандартную валидацию (32 hex символа)
                    validate_hex_key(args.iv, 32, "IV")

            # Validate AAD if provided
            if args.aad:
                try:
                    aad_bytes = bytes.fromhex(args.aad)
                except ValueError:
                    raise ValueError("AAD must be a valid hexadecimal string")

            # GCM-specific validations
            if args.mode == 'gcm':
                # For GCM encryption without --iv, we'll generate random nonce
                if args.encrypt and args.iv:
                    print("Info: Using provided nonce for GCM encryption")
                elif args.encrypt and not args.iv:
                    print("Info: Generating random 12-byte nonce for GCM encryption")

                # For GCM decryption, either --iv must be provided or nonce must be in file
                if args.decrypt and not args.iv:
                    print("Info: No nonce provided via --iv, expecting nonce in input file")

                # Для совместимости с текущей валидацией, если указан 32-символьный IV,
                # преобразуем его в 24-символьный nonce (берем первые 24 символа)
                if args.iv and len(args.iv) == 32:
                    print("Info: Converting 32-char IV to 24-char nonce for GCM")
                    args.iv = args.iv[:24]

            # Encrypt-then-MAC specific validations
            if args.mode == 'encrypt-then-mac':
                # Для Encrypt-then-MAC используем стандартную валидацию IV (32 символа)
                if args.iv:
                    validate_hex_key(args.iv, 32, "IV")
                print("Info: Using Encrypt-then-MAC AEAD mode")

        # Set default output filename if not provided
        if not args.output:
            if args.encrypt:
                # Для GCM используем другое расширение, чтобы отличать
                if args.mode == 'gcm':
                    args.output = args.input + '.gcm'
                elif args.mode == 'encrypt-then-mac':
                    args.output = args.input + '.etm'
                else:
                    args.output = args.input + '.enc'
            else:
                # Пытаемся угадать правильное расширение для дешифрования
                if args.input.endswith('.gcm'):
                    args.output = args.input[:-4]
                elif args.input.endswith('.etm'):
                    args.output = args.input[:-4]
                elif args.input.endswith('.enc'):
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

    elif args.command == 'derive':
        # Validate iterations
        if args.iterations < 1:
            raise ValueError("Iterations must be at least 1")
        if args.iterations > 1000000:
            print(f"Warning: High iteration count ({args.iterations}) may be slow")

        # Validate key length
        if args.length < 1 or args.length > 1024:
            raise ValueError("Key length must be between 1 and 1024 bytes")

        # Validate algorithm
        if args.algorithm != 'pbkdf2':
            raise ValueError("Currently only 'pbkdf2' algorithm is supported")

        # Validate salt if provided
        if args.salt:
            try:
                # Try to parse as hex first
                salt_bytes = bytes.fromhex(args.salt)
                if len(salt_bytes) < 8:
                    print(f"Warning: Salt is short ({len(salt_bytes)} bytes). Minimum 8 bytes recommended.")
            except ValueError:
                # If not hex, it's treated as raw string - that's OK
                pass

    return args