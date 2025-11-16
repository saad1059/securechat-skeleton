#!/usr/bin/env python3
"""
AES-128 Encryption and Decryption using ECB mode with PKCS#7 padding.

Provides functions to:
- Encrypt plaintext with AES-128
- Decrypt ciphertext with AES-128
- Handle PKCS#7 padding automatically

Note: ECB mode is NOT secure for general use, but acceptable for protocol
where each message is encrypted with a fresh key or the message structure
doesn't reveal patterns (as in this chat protocol where messages are short
and varied). For production, CBC or GCM would be preferred.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AES128:
    """AES-128 encryption/decryption operations."""
    
    @staticmethod
    def validate_key(key):
        """
        Validate that key is 16 bytes (128 bits).
        
        Args:
            key: bytes, must be 16 bytes for AES-128
            
        Raises:
            ValueError: If key is not 16 bytes
        """
        if not isinstance(key, bytes):
            raise TypeError("Key must be bytes")
        if len(key) != 16:
            raise ValueError(f"AES-128 requires 16-byte key, got {len(key)}")
    
    @staticmethod
    def pad(data, block_size=16):
        """
        Apply PKCS#7 padding to data.
        
        Adds padding bytes equal to the number of bytes needed to reach
        a multiple of block_size. If data is already a multiple of
        block_size, a full block of padding is added.
        
        Args:
            data: bytes to pad
            block_size: block size for padding (default 16 for AES)
            
        Returns:
            bytes: padded data
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")
        
        # Calculate padding length
        padding_length = block_size - (len(data) % block_size)
        
        # Create padding bytes
        padding = bytes([padding_length] * padding_length)
        
        return data + padding
    
    @staticmethod
    def unpad(data, block_size=16):
        """
        Remove PKCS#7 padding from data.
        
        Args:
            data: bytes to unpad
            block_size: block size for padding (default 16 for AES)
            
        Returns:
            bytes: unpadded data
            
        Raises:
            ValueError: If padding is invalid
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")
        
        if len(data) == 0:
            raise ValueError("Cannot unpad empty data")
        
        # Get padding length from last byte
        padding_length = data[-1]
        
        # Validate padding
        if padding_length > block_size or padding_length == 0:
            raise ValueError(f"Invalid padding length: {padding_length}")
        
        # Verify all padding bytes are correct
        for i in range(padding_length):
            if data[-(i+1)] != padding_length:
                raise ValueError("Invalid PKCS#7 padding")
        
        return data[:-padding_length]
    
    @staticmethod
    def encrypt(plaintext, key):
        """
        Encrypt plaintext using AES-128 in ECB mode.
        
        Args:
            plaintext: bytes or str to encrypt
            key: 16-byte AES key
            
        Returns:
            bytes: ciphertext (hex-encoded string for easy transmission)
        """
        # Convert string to bytes if needed
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes or str")
        
        # Validate key
        AES128.validate_key(key)
        
        # Apply PKCS#7 padding
        padded_plaintext = AES128.pad(plaintext, block_size=16)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        # Return as hex string for easy serialization
        return ciphertext.hex()
    
    @staticmethod
    def decrypt(ciphertext_hex, key):
        """
        Decrypt ciphertext using AES-128 in ECB mode.
        
        Args:
            ciphertext_hex: ciphertext as hex string
            key: 16-byte AES key
            
        Returns:
            bytes: plaintext
            
        Raises:
            ValueError: If padding is invalid or decryption fails
        """
        if not isinstance(ciphertext_hex, str):
            raise TypeError("Ciphertext must be hex string")
        
        # Validate key
        AES128.validate_key(key)
        
        # Convert hex string to bytes
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
        except ValueError:
            raise ValueError("Invalid hex string for ciphertext")
        
        # Validate ciphertext length (must be multiple of 16)
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        plaintext = AES128.unpad(padded_plaintext, block_size=16)
        
        return plaintext
    
    @staticmethod
    def decrypt_str(ciphertext_hex, key):
        """
        Decrypt ciphertext and return as UTF-8 string.
        
        Args:
            ciphertext_hex: ciphertext as hex string
            key: 16-byte AES key
            
        Returns:
            str: decrypted plaintext
        """
        plaintext_bytes = AES128.decrypt(ciphertext_hex, key)
        return plaintext_bytes.decode('utf-8')


def encrypt_message(message, key):
    """
    Convenience function to encrypt a message.
    
    Args:
        message: str or bytes to encrypt
        key: 16-byte AES-128 key
        
    Returns:
        str: ciphertext as hex string
    """
    return AES128.encrypt(message, key)


def decrypt_message(ciphertext_hex, key, as_string=True):
    """
    Convenience function to decrypt a message.
    
    Args:
        ciphertext_hex: ciphertext as hex string
        key: 16-byte AES-128 key
        as_string: if True, return str; if False, return bytes
        
    Returns:
        str or bytes: decrypted plaintext
    """
    if as_string:
        return AES128.decrypt_str(ciphertext_hex, key)
    else:
        return AES128.decrypt(ciphertext_hex, key)
