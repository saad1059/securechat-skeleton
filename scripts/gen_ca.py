#!/usr/bin/env python3
"""
Generate a self-signed root CA certificate and private key.

This script creates:
1. RSA private key (2048-bit)
2. Self-signed X.509 certificate valid for 365 days
3. Saves to certs/ca.key and certs/ca.crt
"""

import os
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID


def generate_ca():
    """Generate a self-signed root CA certificate and private key."""
    
    # Ensure certs directory exists
    certs_dir = Path(__file__).parent.parent / 'certs'
    certs_dir.mkdir(exist_ok=True)
    
    ca_key_path = certs_dir / 'ca.key'
    ca_crt_path = certs_dir / 'ca.crt'
    
    print("🔐 Generating Root CA...")
    print(f"📁 Using directory: {certs_dir}")
    
    # Step 1: Generate RSA private key (2048-bit)
    print("1️⃣  Generating RSA private key (2048-bit)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    print("   ✅ Private key generated")
    
    # Step 2: Create self-signed certificate
    print("2️⃣  Creating self-signed X.509 certificate...")
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat CA"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc).replace(tzinfo=None)
    ).not_valid_after(
        (datetime.now(timezone.utc) + timedelta(days=365)).replace(tzinfo=None)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    print("   ✅ Certificate created")
    
    # Step 3: Save private key to file
    print(f"3️⃣  Saving private key to {ca_key_path}...")
    with open(ca_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print("   ✅ Private key saved")
    
    # Step 4: Save certificate to file
    print(f"4️⃣  Saving certificate to {ca_crt_path}...")
    with open(ca_crt_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("   ✅ Certificate saved")
    
    # Step 5: Print certificate info
    print("\n📋 CA Certificate Details:")
    print(f"   Subject: {cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"   Issuer: {cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"   Serial: {cert.serial_number}")
    print(f"   Valid From: {cert.not_valid_before_utc}")
    print(f"   Valid To: {cert.not_valid_after_utc}")
    print(f"   Key Size: 2048 bits")
    print(f"   Signature Algorithm: SHA-256 with RSA")
    
    print("\n✅ Root CA generation complete!")
    print(f"   Private Key: {ca_key_path}")
    print(f"   Certificate: {ca_crt_path}")


if __name__ == '__main__':
    generate_ca()
