from .aes_ecb import AES_ECB_MODE
from .modes import CBC_MODE, CFB_MODE, OFB_MODE, CTR_MODE, GCM_MODE, AEAD_EncryptThenMAC, AuthenticationError
from src.file_io import read_file, write_file
from src.utils.validation import validate_file_exists
from src.utils.csprng import generate_random_bytes
import logging
import os

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
    elif mode == 'gcm':
        return GCM_MODE(key)
    elif mode == 'encrypt-then-mac':
        return AEAD_EncryptThenMAC(key, mode='ctr')
    else:
        raise ValueError(f"Unsupported mode: {mode}")


def encrypt_file_aes(input_path: str, output_path: str, key: bytes, mode: str = 'ecb', aad: bytes = b""):
    try:
        logger.info(f"Starting AES-{mode.upper()} encryption: {input_path} -> {output_path}")
        validate_file_exists(input_path)

        plaintext = read_file(input_path)
        crypto = get_crypto_mode(mode, key)

        if mode == 'gcm':
            # GCM всегда генерирует случайный nonce при шифровании
            # Предоставленный iv (если есть) игнорируется
            ciphertext = crypto.encrypt(plaintext, aad=aad)
            # Output уже содержит nonce + ciphertext + tag
            final_output = ciphertext
            logger.info("GCM encryption: generated random nonce")

        elif mode == 'encrypt-then-mac':
            # Encrypt-then-MAC AEAD
            ciphertext = crypto.encrypt(plaintext, aad=aad)
            final_output = ciphertext

        elif mode != 'ecb':
            # Other modes use 16-byte IV
            iv = generate_random_bytes(16)
            ciphertext = crypto.encrypt(plaintext, iv)
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


def decrypt_file_aes(input_path: str, output_path: str, key: bytes, mode: str = 'ecb',
                     iv_hex: str = None, aad: bytes = b""):
    try:
        logger.info(f"Starting AES-{mode.upper()} decryption: {input_path} -> {output_path}")
        validate_file_exists(input_path)

        ciphertext_data = read_file(input_path)

        if mode == 'gcm':
            crypto = get_crypto_mode(mode, key)

            # For GCM, nonce can be in file or provided via --iv
            if iv_hex:
                # Nonce provided separately
                nonce = bytes.fromhex(iv_hex)
                # Only ciphertext + tag remains
                ciphertext_tag = ciphertext_data
                try:
                    plaintext = crypto.decrypt(ciphertext_tag, nonce, aad)
                    write_file(output_path, plaintext)
                    logger.info(f"File decrypted successfully: {output_path}")
                except AuthenticationError as e:
                    # Authentication failed - don't write output file
                    logger.error(f"Authentication failed: {e}")
                    # Delete any partially created file
                    if os.path.exists(output_path):
                        os.remove(output_path)
                    raise
            else:
                # Nonce is first 12 bytes of the file
                if len(ciphertext_data) < 28:  # min: 12 nonce + 0 data + 16 tag
                    raise ValueError("Input file too short for GCM format")

                # Nonce is included in the file, pass entire data to decrypt
                try:
                    plaintext = crypto.decrypt(ciphertext_data, aad=aad)
                    write_file(output_path, plaintext)
                    logger.info(f"File decrypted successfully: {output_path}")
                except AuthenticationError as e:
                    # Authentication failed
                    logger.error(f"Authentication failed: {e}")
                    if os.path.exists(output_path):
                        os.remove(output_path)
                    raise

        elif mode == 'encrypt-then-mac':
            crypto = get_crypto_mode(mode, key)
            try:
                plaintext = crypto.decrypt(ciphertext_data, aad=aad, iv=iv_hex)
                write_file(output_path, plaintext)
                logger.info(f"File decrypted successfully: {output_path}")
            except AuthenticationError as e:
                logger.error(f"Authentication failed: {e}")
                if os.path.exists(output_path):
                    os.remove(output_path)
                raise

        else:
            # Handle IV for other modes
            if mode != 'ecb':
                if iv_hex:
                    iv = bytes.fromhex(iv_hex)
                    ciphertext = ciphertext_data
                else:
                    if len(ciphertext_data) < 16:
                        raise ValueError("Input file too short to contain IV")
                    iv = ciphertext_data[:16]
                    ciphertext = ciphertext_data[16:]
            else:
                iv = None
                ciphertext = ciphertext_data

            crypto = get_crypto_mode(mode, key)
            plaintext = crypto.decrypt(ciphertext, iv)
            write_file(output_path, plaintext)
            logger.info(f"File decrypted successfully: {output_path}")

    except AuthenticationError:
        # Re-raise authentication errors
        raise
    except Exception as e:
        logger.error(f"AES-{mode.upper()} decryption failed: {str(e)}", exc_info=True)
        raise