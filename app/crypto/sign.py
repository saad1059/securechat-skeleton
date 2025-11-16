#!/usr/bin/env python3
"""
RSA Digital Signatures using PKCS#1 v1.5 with SHA-256.

Provides functions to:
- Sign data with a private key
- Verify signatures with a public key
- Load keys from PEM files
"""

from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509


class RSASignature:
    """RSA signature operations using PKCS#1 v1.5 padding."""
    
    @staticmethod
    def load_private_key(key_path):
        """
        Load a private key from a PEM file.
        
        Args:
            key_path: Path to the .key file
            
        Returns:
            RSA private key object
        """
        with open(key_path, 'rb') as f:
            key_data = f.read()
        
        private_key = serialization.load_pem_private_key(
            key_data,
            password=None
        )
        
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Key is not an RSA private key")
        
        return private_key
    
    @staticmethod
    def load_public_key(key_path):
        """
        Load a public key from a PEM file or certificate.
        
        Args:
            key_path: Path to the .crt or .pub file
            
        Returns:
            RSA public key object
        """
        with open(key_path, 'rb') as f:
            key_data = f.read()
        
        # Try loading as certificate first
        try:
            cert = x509.load_pem_x509_certificate(key_data)
            return cert.public_key()
        except Exception:
            pass
        
        # Try loading as public key
        try:
            public_key = serialization.load_pem_public_key(key_data)
            return public_key
        except Exception as e:
            raise ValueError(f"Could not load public key: {e}")
    
    @staticmethod
    def sign(data, private_key):
        """
        Sign data using RSA private key.
        
        Uses:
        - Algorithm: RSA PKCS#1 v1.5
        - Hash: SHA-256
        
        Args:
            data: Bytes to sign
            private_key: RSA private key object
            
        Returns:
            Signature as bytes (hex-encoded string)
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")
        
        signature = private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Return as hex string for easy serialization
        return signature.hex()
    
    @staticmethod
    def verify(data, signature_hex, public_key):
        """
        Verify a signature using RSA public key.
        
        Args:
            data: Original data that was signed (bytes)
            signature_hex: Signature as hex string
            public_key: RSA public key object
            
        Returns:
            True if signature is valid, False otherwise
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")
        
        if not isinstance(signature_hex, str):
            raise TypeError("Signature must be hex string")
        
        try:
            # Convert hex string back to bytes
            signature_bytes = bytes.fromhex(signature_hex)
            
            # Verify the signature
            public_key.verify(
                signature_bytes,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


def sign_message(data, private_key_path):
    """
    Convenience function to sign a message.
    
    Args:
        data: Data to sign (bytes or str)
        private_key_path: Path to .key file
        
    Returns:
        Signature as hex string
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    private_key = RSASignature.load_private_key(private_key_path)
    return RSASignature.sign(data, private_key)


def verify_message(data, signature_hex, public_key_path):
    """
    Convenience function to verify a message signature.
    
    Args:
        data: Original data (bytes or str)
        signature_hex: Signature as hex string
        public_key_path: Path to .crt or public key file
        
    Returns:
        True if valid, False otherwise
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    public_key = RSASignature.load_public_key(public_key_path)
    return RSASignature.verify(data, signature_hex, public_key)
