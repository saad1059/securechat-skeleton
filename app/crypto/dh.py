#!/usr/bin/env python3
"""
Diffie-Hellman Key Exchange with SHA-256 Key Derivation.

Provides functions to:
- Generate DH parameters (p, g)
- Generate DH key pairs (private/public)
- Compute shared secrets
- Derive session keys using SHA-256
"""

import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization


class DiffieHellman:
    """Diffie-Hellman key exchange operations."""
    
    # Standard DH parameters (RFC 3526 - 2048-bit MODP Group)
    # These are well-tested parameters used widely in cryptography
    DH_P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
        16
    )
    
    DH_G = 2
    
    @staticmethod
    def get_parameters():
        """
        Get DH parameters (p, g).
        
        Returns:
            tuple: (p, g) where p is prime modulus, g is generator
        """
        return DiffieHellman.DH_P, DiffieHellman.DH_G
    
    @staticmethod
    def generate_private_key():
        """
        Generate a private key for DH key exchange.
        
        Uses cryptography library's built-in DH parameter generation
        with 2048-bit prime (RFC 3526).
        
        Returns:
            DHPrivateKey object
        """
        # Create DH parameters
        parameters = dh.DHParameterNumbers(
            p=DiffieHellman.DH_P,
            g=DiffieHellman.DH_G,
            q=None  # q is optional for DH
        ).parameters()
        
        # Generate private key
        private_key = parameters.generate_private_key()
        return private_key
    
    @staticmethod
    def get_public_key(private_key):
        """
        Derive public key from private key.
        
        Args:
            private_key: DHPrivateKey object
            
        Returns:
            DHPublicKey object
        """
        return private_key.public_key()
    
    @staticmethod
    def serialize_public_key(public_key):
        """
        Serialize public key to bytes for transmission.
        
        Args:
            public_key: DHPublicKey object
            
        Returns:
            bytes: Serialized public key
        """
        # Get the public key value (y)
        y = public_key.public_numbers().y
        
        # Convert to bytes (256 bytes for 2048-bit)
        return y.to_bytes(256, byteorder='big')
    
    @staticmethod
    def deserialize_public_key(key_bytes):
        """
        Deserialize public key from bytes.
        
        Args:
            key_bytes: bytes representation of public key
            
        Returns:
            DHPublicKey object
        """
        # Convert bytes to integer
        y = int.from_bytes(key_bytes, byteorder='big')
        
        # Reconstruct DHPublicNumbers
        public_numbers = dh.DHPublicNumbers(
            y=y,
            parameter_numbers=dh.DHParameterNumbers(
                p=DiffieHellman.DH_P,
                g=DiffieHellman.DH_G,
                q=None
            )
        )
        
        # Return public key object
        return public_numbers.public_key()
    
    @staticmethod
    def compute_shared_secret(private_key, peer_public_key):
        """
        Compute shared secret from peer's public key.
        
        Args:
            private_key: Our DHPrivateKey
            peer_public_key: Peer's DHPublicKey
            
        Returns:
            bytes: Shared secret (256 bytes)
        """
        shared_secret = private_key.exchange(peer_public_key)
        return shared_secret
    
    @staticmethod
    def derive_key(shared_secret, key_length=16):
        """
        Derive a session key from shared secret using SHA-256.
        
        Uses Trunc16(SHA256(shared_secret)) to derive AES-128 key.
        
        Args:
            shared_secret: Shared secret from DH exchange (bytes)
            key_length: Length of derived key in bytes (default 16 for AES-128)
            
        Returns:
            bytes: Derived key
        """
        if not isinstance(shared_secret, bytes):
            raise TypeError("Shared secret must be bytes")
        
        # Hash the shared secret with SHA-256
        hash_obj = hashlib.sha256(shared_secret)
        hash_digest = hash_obj.digest()  # 32 bytes
        
        # Truncate to desired length (typically 16 bytes for AES-128)
        derived_key = hash_digest[:key_length]
        
        return derived_key


def perform_dh_exchange():
    """
    Perform a complete DH key exchange.
    
    Returns:
        dict: Contains 'shared_secret' and 'session_key'
    """
    # Alice generates key pair
    alice_private = DiffieHellman.generate_private_key()
    alice_public = DiffieHellman.get_public_key(alice_private)
    
    # Bob generates key pair
    bob_private = DiffieHellman.generate_private_key()
    bob_public = DiffieHellman.get_public_key(bob_private)
    
    # Alice computes shared secret using Bob's public key
    alice_shared = DiffieHellman.compute_shared_secret(alice_private, bob_public)
    
    # Bob computes shared secret using Alice's public key
    bob_shared = DiffieHellman.compute_shared_secret(bob_private, alice_public)
    
    # Verify they match
    assert alice_shared == bob_shared, "Shared secrets don't match!"
    
    shared_secret = alice_shared
    
    # Derive session key
    session_key = DiffieHellman.derive_key(shared_secret, key_length=16)
    
    return {
        'alice_private': alice_private,
        'alice_public': alice_public,
        'bob_private': bob_private,
        'bob_public': bob_public,
        'shared_secret': shared_secret,
        'session_key': session_key
    }


def exchange_public_keys(private_key):
    """
    Generate and return public key for exchange.
    
    Args:
        private_key: DH private key
        
    Returns:
        tuple: (public_key_object, serialized_bytes)
    """
    public_key = DiffieHellman.get_public_key(private_key)
    serialized = DiffieHellman.serialize_public_key(public_key)
    return public_key, serialized


def complete_exchange(private_key, peer_public_key_bytes):
    """
    Complete DH exchange with peer's public key bytes.
    
    Args:
        private_key: Our DH private key
        peer_public_key_bytes: Peer's serialized public key
        
    Returns:
        dict: Contains 'shared_secret' and 'session_key'
    """
    # Deserialize peer's public key
    peer_public_key = DiffieHellman.deserialize_public_key(peer_public_key_bytes)
    
    # Compute shared secret
    shared_secret = DiffieHellman.compute_shared_secret(private_key, peer_public_key)
    
    # Derive session key
    session_key = DiffieHellman.derive_key(shared_secret, key_length=16)
    
    return {
        'shared_secret': shared_secret,
        'session_key': session_key,
        'key_length': len(session_key)
    }
