#!/usr/bin/env python3
"""Offline public-certificate issuance for PPS; never reads an ESP32 private key."""
import argparse
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

VERSION = "1.0.0"
PEM = serialization.Encoding.PEM
DER = serialization.Encoding.DER


def now_utc():
    return datetime.now(timezone.utc).replace(microsecond=0)


def spki(key):
    return key.public_bytes(DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def require_p256(key):
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("The public ECDSA P-256 key from the original PPS firmware is required.")


def fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def normalize_fingerprint(value):
    value = re.sub(r"[\s:]", "", value).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("The fingerprint must contain all 64 hexadecimal SHA-256 characters.")
    return value


def load_certificate(path):
    path = Path(path)
    if path.stat().st_size > 16384:
        raise ValueError("The certificate file is too large.")
    data = path.read_bytes()
    if b"PRIVATE KEY" in data:
        raise ValueError("A public certificate is required, not a private key.")
    if data.lstrip().startswith(b"-----BEGIN CERTIFICATE-----"):
        pattern = rb"\s*-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*"
        if not re.fullmatch(pattern, data):
            raise ValueError("Exactly one PEM certificate is required, with no extra blocks.")
        cert = x509.load_pem_x509_certificate(data)
    else:
        cert = x509.load_der_x509_certificate(data)
        if cert.public_bytes(DER) != data:
            raise ValueError("Unexpected data after the DER certificate.")
    return cert


def write_new(path, data, private=False):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def fetch_device(host, expected_fingerprint, output, port=443):
    """Bootstrap with physical SHA-256 pinning, not CA validation.

    No HTTP request, password, token or client certificate is sent. The peer
    certificate is used/saved ONLY after its full fingerprint matches the pin.
    This context is local to this one connection; browser TLS is unchanged.
    """
    expected = normalize_fingerprint(expected_fingerprint)
    if not host or len(host) > 253 or any(c in host for c in "/\\@ \t\r\n"):
        raise ValueError("Specify the device hostname or IP address, without https:// or a path.")
    if Path(output).exists():
        raise ValueError("The output file already exists; choose a different filename.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Authentication below uses the physical SHA-256 pin.
    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname="pps.local") as peer:
            encoded = peer.getpeercert(binary_form=True)
    if not encoded or len(encoded) > 16384:
        raise ValueError("No valid public certificate was received from the device.")
    cert = x509.load_der_x509_certificate(encoded)
    if cert.public_bytes(DER) != encoded or fingerprint(cert) != expected:
        raise ValueError("The fingerprint DOES NOT match the device screen. The file was not saved.")
    write_new(output, encoded)
    return cert


def create_directory(path):
    path = Path(path).resolve()
    path.mkdir(parents=True, exist_ok=False, mode=0o700)
    return path


def root_usage():
    return x509.KeyUsage(digital_signature=False, content_commitment=False,
                         key_encipherment=False, data_encipherment=False,
                         key_agreement=False, key_cert_sign=True, crl_sign=True,
                         encipher_only=False, decipher_only=False)


def leaf_usage():
    return x509.KeyUsage(digital_signature=True, content_commitment=False,
                         key_encipherment=False, data_encipherment=False,
                         key_agreement=False, key_cert_sign=False, crl_sign=False,
                         encipher_only=False, decipher_only=False)


def init_ca(directory, password, current=None):
    if len(password) < 12:
        raise ValueError("The CA private key password must be at least 12 characters long.")
    current = current or now_utc()
    key = ec.generate_private_key(ec.SECP256R1())
    identifier = hashlib.sha256(spki(key.public_key())).hexdigest()[:12]
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PPS Local CA " + identifier)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(current - timedelta(days=1))
            .not_valid_after(current + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(root_usage(), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    encoded = key.private_bytes(PEM, serialization.PrivateFormat.PKCS8,
                                serialization.BestAvailableEncryption(password.encode("utf-8")))
    directory = create_directory(directory)
    # Never overwrite existing CA material. If creation is interrupted, keep the
    # partial directory for operator inspection and use a NEW directory on retry.
    write_new(directory / "ca-private-key.pem", encoded, private=True)
    write_new(directory / "PPS-root-ca.pem", cert.public_bytes(PEM))
    write_new(directory / "PPS-root-ca.crt", cert.public_bytes(DER))
    return cert


def load_ca(directory, password, current):
    directory = Path(directory)
    cert = load_certificate(directory / "PPS-root-ca.pem")
    encoded_path = directory / "ca-private-key.pem"
    if encoded_path.stat().st_size > 16384:
        raise ValueError("The CA private key file is too large.")
    encoded = encoded_path.read_bytes()
    if not encoded.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"):
        raise ValueError("The CA private key must be encrypted PKCS#8.")
    try:
        key = serialization.load_pem_private_key(encoded, password=password.encode("utf-8"))
    except (ValueError, TypeError):
        raise ValueError("Could not open the CA: incorrect password or corrupted key.") from None
    require_p256(cert.public_key())
    if not isinstance(key, ec.EllipticCurvePrivateKey) or spki(key.public_key()) != spki(cert.public_key()):
        raise ValueError("The CA key does not match the CA certificate.")
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    if not bc.ca or bc.path_length != 0 or not ku.key_cert_sign or cert.issuer != cert.subject:
        raise ValueError("The CA does not match this kit's required profile.")
    if not isinstance(cert.signature_hash_algorithm, hashes.SHA256):
        raise ValueError("The CA must use SHA-256.")
    cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    if not cert.not_valid_before_utc <= current < cert.not_valid_after_utc:
        raise ValueError("The CA is not yet valid or has expired. Check the computer clock.")
    return cert, key


def as_array(name, data):
    rows = ["  " + ",".join(f"0x{b:02x}" for b in data[i:i + 12]) + "," for i in range(0, len(data), 12)]
    return "static const unsigned char " + name + "[] = {\n" + "\n".join(rows) + "\n};\n"


def make_header(leaf, root):
    return ("// Generated by PPS TLS Trust Kit 1.0.0: PUBLIC certificates only.\n"
            "#pragma once\nnamespace PpsTlsBundle {\nstatic const unsigned format = 1;\n"
            "// Active leaf SHA-256: " + fingerprint(leaf) + "\n"
            "// Root CA SHA-256: " + fingerprint(root) + "\n"
            + as_array("leaf", leaf.public_bytes(DER))
            + as_array("root", root.public_bytes(DER)) + "}\n")


def issue(directory, device_path, expected_fingerprint, password, output, days=365, current=None):
    if not 1 <= days <= 365:
        raise ValueError("Device certificate validity must be between 1 and 365 days.")
    current = current or now_utc()
    device = load_certificate(device_path)
    if fingerprint(device) != normalize_fingerprint(expected_fingerprint):
        raise ValueError("The fingerprint DOES NOT match the device screen. Certificate issuance stopped.")
    require_p256(device.public_key())
    if device.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("An ESP32 server certificate is expected, not a CA certificate.")
    root, ca_key = load_ca(directory, password, current)
    end = current + timedelta(days=days)
    if end > root.not_valid_after_utc:
        raise ValueError("The CA expires before the new device certificate; renew the CA first.")
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pps.local"),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PPS")])
    leaf = (x509.CertificateBuilder().subject_name(subject).issuer_name(root.subject)
            .public_key(device.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(max(current - timedelta(days=1), root.not_valid_before_utc))
            .not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(leaf_usage(), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("pps.local"),
                            x509.IPAddress(ipaddress.ip_address("192.168.4.1"))]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(device.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    root.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    if spki(leaf.public_key()) != spki(device.public_key()):
        raise ValueError("Internal error: the device public key has changed.")
    if len(leaf.public_bytes(DER)) > 2048 or len(root.public_bytes(DER)) > 2048:
        raise ValueError("The certificates exceed the firmware size limit.")
    output = create_directory(output)
    files = {"pps_tls_certificate.h": make_header(leaf, root).encode("ascii"),
             "PPS-device.pem": leaf.public_bytes(PEM), "PPS-device.crt": leaf.public_bytes(DER),
             "PPS-root-ca.pem": root.public_bytes(PEM), "PPS-root-ca.crt": root.public_bytes(DER)}
    for name, data in files.items():
        write_new(output / name, data)
    manifest = {"kit_version": VERSION, "input_fingerprint_sha256": fingerprint(device),
                "device_spki_sha256": hashlib.sha256(spki(device.public_key())).hexdigest(),
                "active_certificate_sha256": fingerprint(leaf), "root_ca_sha256": fingerprint(root),
                "not_before_utc": leaf.not_valid_before_utc.isoformat(),
                "not_after_utc": leaf.not_valid_after_utc.isoformat(),
                "names": ["pps.local", "192.168.4.1"],
                "files_sha256": {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}}
    write_new(output / "public_manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    return manifest


def password_prompt(confirm=False):
    if not sys.stdin.isatty():
        raise ValueError("Run the command in an interactive terminal: the CA password cannot be supplied as an argument or through a pipe.")
    password = getpass.getpass("CA private key password: ")
    if confirm and password != getpass.getpass("Confirm CA password: "):
        raise ValueError("The passwords do not match.")
    return password


def main(argv=None):
    parser = argparse.ArgumentParser(description="PPS: issue a public TLS certificate for the device's existing key.")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("inspect", help="Display the fingerprint of a public device.crt certificate")
    p.add_argument("certificate", type=Path)
    p = sub.add_parser("fetch-device", help="Fetch a public certificate and verify its SHA-256 fingerprint against the device screen")
    p.add_argument("--host", default="pps.local", help="Device hostname or IP address; default: pps.local")
    p.add_argument("--fingerprint", required=True, help="All 64 SHA-256 fingerprint characters from the physical ESP32 screen")
    p.add_argument("--output", type=Path, required=True, help="New public certificate file")
    p = sub.add_parser("init-ca", help="Create a private CA in a new protected directory on this computer")
    p.add_argument("--directory", type=Path, required=True)
    p = sub.add_parser("issue", help="Sign the public key after verifying the fingerprint against the device screen")
    p.add_argument("--ca-directory", type=Path, required=True)
    p.add_argument("--device-certificate", type=Path, required=True)
    p.add_argument("--fingerprint", required=True, help="SHA-256 fingerprint from the physical ESP32 screen, all 64 characters")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--days", type=int, default=365)
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            cert = load_certificate(args.certificate)
            print("Certificate SHA-256:", fingerprint(cert))
            print("Public key SHA-256:", hashlib.sha256(spki(cert.public_key())).hexdigest())
            print("Valid until UTC:", cert.not_valid_after_utc.isoformat())
        elif args.command == "fetch-device":
            cert = fetch_device(args.host, args.fingerprint, args.output)
            print("The fingerprint matches the expected value. Public certificate saved:", args.output)
            print("Certificate SHA-256:", fingerprint(cert))
        elif args.command == "init-ca":
            cert = init_ca(args.directory, password_prompt(confirm=True))
            print("CA created. Keep the private key in this directory on your computer; do not include it in the firmware sketch.")
            print("Root CA SHA-256:", fingerprint(cert))
        else:
            # Verify the physical fingerprint before asking for the CA password.
            cert = load_certificate(args.device_certificate)
            if fingerprint(cert) != normalize_fingerprint(args.fingerprint):
                raise ValueError("The fingerprint DOES NOT match the device screen. Certificate issuance stopped.")
            manifest = issue(args.ca_directory, args.device_certificate, args.fingerprint,
                             password_prompt(), args.output, args.days)
            print("Only public files were created. New fingerprint after flashing the firmware:")
            print(manifest["active_certificate_sha256"])
            print("Root CA SHA-256:", manifest["root_ca_sha256"])
            print("Valid until UTC:", manifest["not_after_utc"])
        return 0
    except (ValueError, OSError, x509.ExtensionNotFound, InvalidSignature, EOFError) as error:
        print("Error:", str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
