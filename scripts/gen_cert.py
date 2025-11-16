#!/usr/bin/env python3
"""
Generate client and server certificates signed by the Root CA.

This script:
1. Loads the CA certificate and private key
2. Generates RSA key pairs for client and server
3. Creates CSRs (Certificate Signing Requests)
4. Signs them with the CA to create X.509 certificates
5. Saves certificates to certs/ directory
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID


def load_ca():
    """Load the CA certificate and private key."""
    certs_dir = Path(__file__).parent.parent / 'certs'
    
    ca_key_path = certs_dir / 'ca.key'
    ca_crt_path = certs_dir / 'ca.crt'
    
    if not ca_key_path.exists() or not ca_crt_path.exists():
        print("❌ Error: CA files not found!")
        print(f"   Missing: {ca_key_path} or {ca_crt_path}")
        print("   Run: python scripts/gen_ca.py first")
        sys.exit(1)
    
    # Load CA private key
    with open(ca_key_path, 'rb') as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    # Load CA certificate
    with open(ca_crt_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    return ca_key, ca_cert


def generate_certificate(common_name, cert_type='server'):
    """
    Generate a certificate signed by the CA.
    
    Args:
        common_name: CN for the certificate (hostname or identifier)
        cert_type: 'server' or 'client'
    
    Returns:
        (private_key, certificate)
    """
    # Load CA
    ca_key, ca_cert = load_ca()
    
    print(f"\n🔐 Generating {cert_type.upper()} certificate...")
    print(f"   Common Name: {common_name}")
    
    # Step 1: Generate private key for this entity
    print(f"1️⃣  Generating RSA private key (2048-bit)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    print("   ✅ Private key generated")
    
    # Step 2: Create CSR (Certificate Signing Request)
    print(f"2️⃣  Creating Certificate Signing Request...")
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    print("   ✅ CSR created")
    
    # Step 3: Sign CSR with CA
    print(f"3️⃣  Signing certificate with CA...")
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.issuer
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc).replace(tzinfo=None)
    ).not_valid_after(
        (datetime.now(timezone.utc) + timedelta(days=365)).replace(tzinfo=None)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage(
            [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH] if cert_type == 'server' 
            else [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
        ),
        critical=True,
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False,
    ).sign(ca_key, hashes.SHA256())
    print("   ✅ Certificate signed by CA")
    
    return private_key, cert


def save_certificate(private_key, cert, filename_base):
    """Save private key and certificate to files."""
    certs_dir = Path(__file__).parent.parent / 'certs'
    
    key_path = certs_dir / f'{filename_base}.key'
    crt_path = certs_dir / f'{filename_base}.crt'
    
    # Save private key
    print(f"4️⃣  Saving private key to {key_path.name}...")
    with open(key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print("   ✅ Private key saved")
    
    # Save certificate
    print(f"5️⃣  Saving certificate to {crt_path.name}...")
    with open(crt_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("   ✅ Certificate saved")
    
    return key_path, crt_path


def print_cert_info(cert, cert_type):
    """Print certificate information."""
    print(f"\n📋 {cert_type.upper()} Certificate Details:")
    print(f"   Subject: {cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"   Issuer: {cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"   Serial: {cert.serial_number}")
    print(f"   Valid From: {cert.not_valid_before_utc}")
    print(f"   Valid To: {cert.not_valid_after_utc}")
    print(f"   Key Size: 2048 bits")
    print(f"   Signature Algorithm: SHA-256 with RSA")
    
    # Print SAN
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [name.value for name in san_ext.value]
        print(f"   Subject Alternative Names: {', '.join(sans)}")
    except x509.ExtensionNotFound:
        print("   Subject Alternative Names: None")


def main():
    """Generate both server and client certificates."""
    print("=" * 60)
    print("🔐 SecureChat Certificate Generation")
    print("=" * 60)
    
    # Generate Server Certificate
    server_key, server_cert = generate_certificate('server', cert_type='server')
    server_key_path, server_crt_path = save_certificate(
        server_key, server_cert, 'server'
    )
    print_cert_info(server_cert, 'server')
    
    # Generate Client Certificate
    client_key, client_cert = generate_certificate('client', cert_type='client')
    client_key_path, client_crt_path = save_certificate(
        client_key, client_cert, 'client'
    )
    print_cert_info(client_cert, 'client')
    
    # Summary
    print("\n" + "=" * 60)
    print("✅ Certificate generation complete!")
    print("=" * 60)
    print(f"\n📁 Generated files:")
    print(f"   Server Key:  {server_key_path}")
    print(f"   Server Cert: {server_crt_path}")
    print(f"   Client Key:  {client_key_path}")
    print(f"   Client Cert: {client_crt_path}")
    print(f"\n✅ All certificates ready for mutual authentication!")


if __name__ == '__main__':
    main()
