#!/usr/bin/env python3
"""
X.509 Certificate Validation.

Provides functions to:
- Load certificates from PEM files
- Verify certificate signatures (signed by CA)
- Check certificate validity (expiry dates)
- Validate certificate chain
- Extract certificate information
"""

from pathlib import Path
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtensionOID


class CertificateValidator:
    """X.509 certificate validation operations."""
    
    @staticmethod
    def load_certificate(cert_path):
        """
        Load an X.509 certificate from a PEM file.
        
        Args:
            cert_path: Path to .crt file (str or Path)
            
        Returns:
            x509.Certificate object
            
        Raises:
            FileNotFoundError: If certificate file not found
            ValueError: If certificate is invalid
        """
        cert_path = Path(cert_path)
        
        if not cert_path.exists():
            raise FileNotFoundError(f"Certificate not found: {cert_path}")
        
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        
        try:
            cert = x509.load_pem_x509_certificate(cert_data)
            return cert
        except Exception as e:
            raise ValueError(f"Failed to load certificate: {e}")
    
    @staticmethod
    def is_valid_now(cert):
        """
        Check if certificate is valid at the current time.
        
        Args:
            cert: x509.Certificate object
            
        Returns:
            tuple: (is_valid, message)
        """
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        
        if now < not_before:
            return False, f"Certificate not yet valid (starts {not_before})"
        
        if now > not_after:
            return False, f"Certificate expired (expired {not_after})"
        
        return True, "Certificate is valid"
    
    @staticmethod
    def verify_signature(cert, issuer_cert):
        """
        Verify that certificate is signed by issuer.
        
        Args:
            cert: x509.Certificate to verify
            issuer_cert: x509.Certificate of issuer (CA)
            
        Returns:
            tuple: (is_valid, message)
        """
        try:
            # Get issuer's public key
            issuer_public_key = issuer_cert.public_key()
            
            # Determine hash algorithm (assuming SHA256, which is standard)
            # Verify the signature using RSA with SHA256
            from cryptography.hazmat.primitives.asymmetric import padding
            
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            return True, "Signature verified"
        except Exception as e:
            return False, f"Signature verification failed: {e}"
    
    @staticmethod
    def verify_self_signed(cert):
        """
        Verify that certificate is self-signed.
        
        Args:
            cert: x509.Certificate to check
            
        Returns:
            tuple: (is_self_signed, message)
        """
        try:
            # Check if subject == issuer
            if cert.subject != cert.issuer:
                return False, "Subject != Issuer (not self-signed)"
            
            # Verify signature with own public key
            from cryptography.hazmat.primitives.asymmetric import padding
            
            public_key = cert.public_key()
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            return True, "Self-signed certificate verified"
        except Exception as e:
            return False, f"Self-signed verification failed: {e}"
    
    @staticmethod
    def verify_chain(cert, issuer_cert, root_cert=None):
        """
        Verify a certificate chain.
        
        Args:
            cert: End-entity certificate to verify
            issuer_cert: Issuer certificate (CA)
            root_cert: Root CA certificate (optional, if issuer is self-signed)
            
        Returns:
            tuple: (is_valid, message)
        """
        # Step 1: Verify cert is signed by issuer
        is_valid, msg = CertificateValidator.verify_signature(cert, issuer_cert)
        if not is_valid:
            return False, f"Chain verification failed at leaf: {msg}"
        
        # Step 2: Verify issuer is valid now
        is_valid, msg = CertificateValidator.is_valid_now(issuer_cert)
        if not is_valid:
            return False, f"Chain verification failed at issuer: {msg}"
        
        # Step 3: Verify cert is valid now
        is_valid, msg = CertificateValidator.is_valid_now(cert)
        if not is_valid:
            return False, f"Chain verification failed at leaf: {msg}"
        
        # Step 4: Verify issuer is self-signed (or verify against root)
        if root_cert is None:
            # Assume issuer is self-signed (root CA)
            is_valid, msg = CertificateValidator.verify_self_signed(issuer_cert)
            if not is_valid:
                return False, f"Issuer verification failed: {msg}"
        else:
            # Verify issuer is signed by root
            is_valid, msg = CertificateValidator.verify_signature(issuer_cert, root_cert)
            if not is_valid:
                return False, f"Root CA verification failed: {msg}"
            
            # Verify root is valid and self-signed
            is_valid, msg = CertificateValidator.is_valid_now(root_cert)
            if not is_valid:
                return False, f"Root CA validity check failed: {msg}"
            
            is_valid, msg = CertificateValidator.verify_self_signed(root_cert)
            if not is_valid:
                return False, f"Root CA self-signed check failed: {msg}"
        
        return True, "Certificate chain verified successfully"
    
    @staticmethod
    def get_common_name(cert):
        """
        Extract Common Name (CN) from certificate.
        
        Args:
            cert: x509.Certificate object
            
        Returns:
            str: Common Name
        """
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attrs:
                return cn_attrs[0].value
        except Exception:
            pass
        return None
    
    @staticmethod
    def get_subject_alternative_names(cert):
        """
        Extract Subject Alternative Names (SANs) from certificate.
        
        Args:
            cert: x509.Certificate object
            
        Returns:
            list: List of SANs (DNS names, IP addresses, etc.)
        """
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            return []
    
    @staticmethod
    def get_issuer_name(cert):
        """
        Extract Issuer Common Name from certificate.
        
        Args:
            cert: x509.Certificate object
            
        Returns:
            str: Issuer Common Name
        """
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            if issuer_cn:
                return issuer_cn[0].value
        except Exception:
            pass
        return None
    
    @staticmethod
    def get_certificate_info(cert):
        """
        Extract comprehensive information from certificate.
        
        Args:
            cert: x509.Certificate object
            
        Returns:
            dict: Certificate information
        """
        return {
            'subject': CertificateValidator.get_common_name(cert),
            'issuer': CertificateValidator.get_issuer_name(cert),
            'serial': cert.serial_number,
            'valid_from': cert.not_valid_before_utc,
            'valid_to': cert.not_valid_after_utc,
            'key_size': cert.public_key().key_size,
            'signature_algorithm': str(cert.signature_algorithm_oid._name),
            'subject_alt_names': CertificateValidator.get_subject_alternative_names(cert)
        }


def validate_certificate(cert_path, ca_cert_path):
    """
    Convenience function to validate a certificate against a CA.
    
    Args:
        cert_path: Path to certificate to validate
        ca_cert_path: Path to CA certificate
        
    Returns:
        tuple: (is_valid, info_dict)
    """
    cert = CertificateValidator.load_certificate(cert_path)
    ca_cert = CertificateValidator.load_certificate(ca_cert_path)
    
    # Verify chain
    is_valid, msg = CertificateValidator.verify_chain(cert, ca_cert)
    
    # Get certificate info
    info = CertificateValidator.get_certificate_info(cert)
    info['validation_message'] = msg
    
    return is_valid, info


def validate_peer_certificate(peer_cert_path, ca_cert_path, expected_cn=None):
    """
    Validate a peer certificate (client or server).
    
    Args:
        peer_cert_path: Path to peer certificate
        ca_cert_path: Path to CA certificate
        expected_cn: Expected Common Name (optional)
        
    Returns:
        tuple: (is_valid, message)
    """
    cert = CertificateValidator.load_certificate(peer_cert_path)
    ca_cert = CertificateValidator.load_certificate(ca_cert_path)
    
    # Verify chain
    is_valid, msg = CertificateValidator.verify_chain(cert, ca_cert)
    if not is_valid:
        return False, msg
    
    # Check Common Name if expected
    if expected_cn:
        cn = CertificateValidator.get_common_name(cert)
        if cn != expected_cn:
            return False, f"Common Name mismatch: expected '{expected_cn}', got '{cn}'"
    
    return True, "Peer certificate validated successfully"
