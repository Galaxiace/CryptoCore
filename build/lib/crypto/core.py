from .aes_ecb import AES_ECB_MODE
from src.file_io import read_file, write_file
from src.utils.validation import validate_file_exists
import logging

logger = logging.getLogger(__name__)


def encrypt_file_aes(input_path: str, output_path: str, key: bytes):
    try:
        logger.info(f"Starting AES encryption: {input_path} -> {output_path}")
        validate_file_exists(input_path)

        plaintext = read_file(input_path)
        crypto = AES_ECB_MODE(key)
        ciphertext = crypto.encrypt(plaintext)

        write_file(output_path, ciphertext)
        logger.info(f"File encrypted successfully: {output_path}")

    except Exception as e:
        logger.error(f"AES encryption failed: {str(e)}", exc_info=True)
        raise


def decrypt_file_aes(input_path: str, output_path: str, key: bytes):
    try:
        logger.info(f"Starting AES decryption: {input_path} -> {output_path}")
        validate_file_exists(input_path)

        ciphertext = read_file(input_path)
        crypto = AES_ECB_MODE(key)
        plaintext = crypto.decrypt(ciphertext)

        write_file(output_path, plaintext)
        logger.info(f"File decrypted successfully: {output_path}")

    except Exception as e:
        logger.error(f"AES decryption failed: {str(e)}", exc_info=True)
        raise