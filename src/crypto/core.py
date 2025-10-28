from .aes_ecb import AES_ECB_MODE
from .modes import CBC_MODE, CFB_MODE, OFB_MODE, CTR_MODE
from src.file_io import read_file, write_file
from src.utils.validation import validate_file_exists
import os
import logging

logger = logging.getLogger(__name__)


def get_crypto_mode(mode, key):
    """Get appropriate crypto mode instance"""
    if mode == 'ecb':
        return AES_ECB_MODE(key)
    elif mode == 'cbc':
        return CBC_MODE(key)
    elif mode == 'cfb':
        return CFB_MODE(key)
    elif mode == 'ofb':
        return OFB_MODE(key)
    elif mode == 'ctr':
        return CTR_MODE(key)
    else:
        raise ValueError(f"Unsupported mode: {mode}")


def encrypt_file_aes(input_path: str, output_path: str, key: bytes, mode: str = 'ecb'):
    try:
        logger.info(f"Starting AES-{mode.upper()} encryption: {input_path} -> {output_path}")
        validate_file_exists(input_path)

        plaintext = read_file(input_path)
        crypto = get_crypto_mode(mode, key)

        # Generate IV for modes that require it
        if mode != 'ecb':
            iv = os.urandom(16)  # CSPRNG
            ciphertext = crypto.encrypt(plaintext, iv)
            # Prepend IV to ciphertext
            final_output = iv + ciphertext
        else:
            # ECB doesn't use IV
            ciphertext = crypto.encrypt(plaintext)
            final_output = ciphertext

        write_file(output_path, final_output)
        logger.info(f"File encrypted successfully: {output_path}")

    except Exception as e:
        logger.error(f"AES-{mode.upper()} encryption failed: {str(e)}", exc_info=True)
        raise


def decrypt_file_aes(input_path: str, output_path: str, key: bytes, mode: str = 'ecb', iv_hex: str = None):
    try:
        logger.info(f"Starting AES-{mode.upper()} decryption: {input_path} -> {output_path}")
        validate_file_exists(input_path)

        ciphertext_data = read_file(input_path)

        # Handle IV for different modes
        if mode != 'ecb':
            if iv_hex:
                # Use provided IV - decrypt entire file as ciphertext
                iv = bytes.fromhex(iv_hex)
                ciphertext = ciphertext_data  # Весь файл - это ciphertext
            else:
                # Extract IV from file - first 16 bytes are IV, rest is ciphertext
                if len(ciphertext_data) < 16:
                    raise ValueError("Input file too short to contain IV")
                iv = ciphertext_data[:16]
                ciphertext = ciphertext_data[16:]
        else:
            # ECB doesn't use IV
            iv = None
            ciphertext = ciphertext_data

        crypto = get_crypto_mode(mode, key)
        plaintext = crypto.decrypt(ciphertext, iv)

        write_file(output_path, plaintext)
        logger.info(f"File decrypted successfully: {output_path}")

    except Exception as e:
        logger.error(f"AES-{mode.upper()} decryption failed: {str(e)}", exc_info=True)
        raise