import argparse
from src.utils.validation import validate_hex_key


def create_parser():
    parser = argparse.ArgumentParser(description='AES Encryption/Decryption Tool')

    parser.add_argument('-algorithm', required=True, choices=['aes'],
                        help='Cipher algorithm')
    parser.add_argument('-mode', required=True,
                        choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'],
                        help='Mode of operation')
    parser.add_argument('-key', required=True,
                        help='Encryption key as 32-character hexadecimal string')
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
        validate_hex_key(args.key)

        # Validate IV if provided
        if args.iv:
            validate_hex_key(args.iv, 32, "IV")  # 32 hex chars = 16 bytes

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

    return args