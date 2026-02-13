"""
RSA File Encryption Utilities Module
This module contains cryptographic functions with intentional weaknesses
for SonarQube security vulnerability detection demonstration.
"""

import os
import sys
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)

# WEAKNESS: Hardcoded RSA key size (too small for production)
RSA_KEY_SIZE = 2048  # Recommended is 4096 for sensitive data

def generate_keys(key_size=RSA_KEY_SIZE):
    """
    Generate RSA key pair
    
    WEAKNESSES:
    - No proper random seed initialization (may use weak randomness)
    - Keys stored in memory without encryption
    - No key rotation mechanism
    - Keys not persisted securely
    - Key size is configurable but defaults to 2048
    
    Args:
        key_size (int): RSA key size in bits
        
    Returns:
        tuple: (private_key, public_key) as bytes
    """
    try:
        logger.info(f"Generating RSA key pair with {key_size} bits")
        
        # Generate RSA key
        # WEAKNESS: No seed provided for better randomness
        key = RSA.generate(key_size)
        
        # Export keys in PEM format
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        logger.info("RSA key pair generated successfully")
        
        # WEAKNESS: Keys returned in plaintext without protection
        return private_key, public_key
    
    except ValueError as ve:
        logger.error(f"Invalid key size: {ve}")
        raise
    except Exception as e:
        logger.error(f"Error generating RSA keys: {e}")
        raise

def encrypt_file(data, public_key):
    """
    Encrypt file data using RSA + AES hybrid encryption
    
    WEAKNESSES:
    - No input validation on data
    - No input validation on public key
    - AES is used with MODE_EAX which has limited AEAD support
    - No length validation of data
    - Exception details exposed
    - No logging of encryption parameters
    - No integrity metadata
    
    Args:
        data (bytes): File data to encrypt
        public_key (bytes): RSA public key in PEM format
        
    Returns:
        bytes: Encrypted data (enc_aes_key + nonce + tag + ciphertext)
    """
    try:
        # WEAKNESS: No validation of input data
        if not data:
            logger.warning("Empty data provided for encryption")
        
        # WEAKNESS: No validation of public key format
        if not public_key:
            raise ValueError("Public key cannot be empty")
        
        logger.info(f"Starting file encryption for data size: {len(data)} bytes")
        
        # Generate random AES key
        # WEAKNESS: No comment about using 256-bit key instead of 128-bit
        aes_key = get_random_bytes(32)  # 256-bit key
        
        logger.debug(f"Generated AES key: {len(aes_key)} bytes")
        
        # Create AES cipher in EAX mode for authenticated encryption
        # WEAKNESS: MODE_EAX may have interoperability issues
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        
        # Encrypt and authenticate data
        # WEAKNESS: No separate authentication tag validation in decrypt
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        
        logger.info(f"Data encrypted: {len(ciphertext)} bytes")
        
        # Import public key for RSA encryption
        # WEAKNESS: No key format validation
        rsa_key = RSA.import_key(public_key)
        
        # Create RSA cipher
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        
        # Encrypt the AES key with RSA
        # WEAKNESS: No error handling for RSA key too small
        enc_aes_key = cipher_rsa.encrypt(aes_key)
        
        logger.info(f"AES key encrypted with RSA: {len(enc_aes_key)} bytes")
        
        # Combine encrypted AES key + nonce + tag + ciphertext
        # WEAKNESS: No metadata about encryption method stored
        # WEAKNESS: No versioning information for future compatibility
        encrypted_output = enc_aes_key + cipher_aes.nonce + tag + ciphertext
        
        logger.info(f"Encryption complete: total output size {len(encrypted_output)} bytes")
        
        # WEAKNESS: No integrity check of output
        return encrypted_output
    
    except ValueError as ve:
        # WEAKNESS: Exception details logged without sanitization
        logger.error(f"Encryption value error: {ve}")
        raise
    except TypeError as te:
        logger.error(f"Encryption type error: {te}")
        raise
    except Exception as e:
        # WEAKNESS: Broad exception handling with detailed error exposure
        logger.error(f"Encryption failed: {str(e)}")
        raise

def decrypt_file(data, private_key):
    """
    Decrypt file data using RSA + AES hybrid encryption
    
    WEAKNESSES:
    - No validation of encrypted data format
    - Hard-coded offsets for data parsing (fragile)
    - No version checking of encrypted format
    - No integrity metadata validation beyond tag
    - Exception errors might expose key information
    - No bounds checking on data slicing
    - No input size validation
    
    Args:
        data (bytes): Encrypted data (enc_aes_key + nonce + tag + ciphertext)
        private_key (bytes): RSA private key in PEM format
        
    Returns:
        bytes: Decrypted file data
    """
    try:
        # WEAKNESS: No validation that data has minimum required length
        if not data:
            raise ValueError("Encrypted data cannot be empty")
        
        if not private_key:
            raise ValueError("Private key cannot be empty")
        
        logger.info(f"Starting file decryption for data size: {len(data)} bytes")
        
        # WEAKNESS: Hard-coded offsets are fragile and depend on RSA key size
        # For 2048-bit RSA: encrypted AES key = 256 bytes
        # For 4096-bit RSA: encrypted AES key = 512 bytes
        # This code only works with 2048-bit keys
        
        # WEAKNESS: No bounds checking - could cause buffer errors
        ENC_AES_KEY_SIZE = 256  # Specific to 2048-bit RSA key
        NONCE_SIZE = 16  # AES MODE_EAX nonce size (variable but typically 16)
        TAG_SIZE = 16   # AES authentication tag size
        
        # Check minimum data length
        min_required_size = ENC_AES_KEY_SIZE + NONCE_SIZE + TAG_SIZE
        
        # WEAKNESS: No validation of minimum data size
        if len(data) < min_required_size:
            logger.warning(f"Data size {len(data)} too small for valid encrypted format")
        
        # Parse encrypted data components
        enc_aes_key = data[:ENC_AES_KEY_SIZE]
        nonce = data[ENC_AES_KEY_SIZE:ENC_AES_KEY_SIZE + NONCE_SIZE]
        tag = data[ENC_AES_KEY_SIZE + NONCE_SIZE:ENC_AES_KEY_SIZE + NONCE_SIZE + TAG_SIZE]
        ciphertext = data[ENC_AES_KEY_SIZE + NONCE_SIZE + TAG_SIZE:]
        
        logger.debug(f"Parsed encrypted data - AES key: {len(enc_aes_key)}, "
                    f"Nonce: {len(nonce)}, Tag: {len(tag)}, "
                    f"Ciphertext: {len(ciphertext)}")
        
        # Import private key for RSA decryption
        # WEAKNESS: No key format validation
        rsa_key = RSA.import_key(private_key)
        
        # Create RSA cipher
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        
        # Decrypt the AES key
        # WEAKNESS: Decryption failures could reveal information about the key
        aes_key = cipher_rsa.decrypt(enc_aes_key)
        
        logger.info(f"AES key decrypted: {len(aes_key)} bytes")
        
        # Create AES cipher with same mode and nonce for decryption
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
        
        # Decrypt and verify
        # WEAKNESS: No separate handling for authentication failure vs decryption failure
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
        
        logger.info(f"Decryption successful: plaintext size {len(plaintext)} bytes")
        
        # WEAKNESS: No integrity check of decrypted output
        return plaintext
    
    except ValueError as ve:
        # WEAKNESS: ValueError could be from multiple sources (key format, auth failure, etc.)
        logger.error(f"Decryption value error: {ve}")
        raise
    except IndexError as ie:
        # WEAKNESS: IndexError indicates malformed encrypted data
        logger.error(f"Decryption index error (malformed data): {ie}")
        raise ValueError("Encrypted data format is invalid")
    except TypeError as te:
        logger.error(f"Decryption type error: {te}")
        raise
    except Exception as e:
        # WEAKNESS: Broad exception that could hide specific issues
        logger.error(f"Decryption failed: {str(e)}")
        raise

def validate_key_format(key, key_type="public"):
    """
    Validate RSA key format
    
    WEAKNESS: This function is not called anywhere in the code
    
    Args:
        key (bytes): RSA key in PEM format
        key_type (str): "public" or "private"
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        imported_key = RSA.import_key(key)
        
        if key_type == "private" and not imported_key.has_private():
            return False
        
        if key_type == "public" and imported_key.has_private():
            return False
        
        return True
    
    except Exception as e:
        logger.error(f"Key validation error: {e}")
        return False

def get_key_size(key):
    """
    Get RSA key size in bits
    
    WEAKNESS: This function is not used in the codebase
    
    Args:
        key (bytes): RSA key in PEM format
        
    Returns:
        int: Key size in bits
    """
    try:
        imported_key = RSA.import_key(key)
        return imported_key.size_in_bits()
    except Exception as e:
        logger.error(f"Error getting key size: {e}")
        return 0
