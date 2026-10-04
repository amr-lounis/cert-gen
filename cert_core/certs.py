"""X.509 certificate builders (pure construction, no file IO)."""
from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID

from .subject import default_cn_san, san_extension


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _validity(days_valid: int) -> tuple[datetime.datetime, datetime.datetime]:
    now = _now()
    return now - datetime.timedelta(minutes=5), now + datetime.timedelta(days=int(days_valid))


def create_self_signed_ca(key, subject: x509.Name, days_valid: int = 3650, path_length: int | None = None):
    not_before, not_after = _validity(days_valid)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
    )
    return builder.sign(private_key=key, algorithm=hashes.SHA256())


def create_intermediate_ca(ca_key, ca_cert, int_key, subject: x509.Name,
                           days_valid: int = 1825, path_length: int = 0):
    not_before, not_after = _validity(days_valid)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(int_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )
    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())


def create_signed_cert(ca_key, ca_cert, leaf_key, subject: x509.Name,
                       san_dns: list[str] | None = None, san_ips: list[str] | None = None,
                       days_valid: int = 825, is_client: bool = False, is_server: bool = True):
    not_before, not_after = _validity(days_valid)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )
    ekus = []
    if is_server:
        ekus.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if is_client:
        ekus.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if ekus:
        builder = builder.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)

    san = san_extension(san_dns, san_ips) or default_cn_san(subject)
    if san is not None:
        builder = builder.add_extension(san, critical=False)
    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())


def create_standalone_self_signed(key, subject: x509.Name,
                                  san_dns: list[str] | None = None, san_ips: list[str] | None = None,
                                  days_valid: int = 825):
    not_before, not_after = _validity(days_valid)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    san = san_extension(san_dns, san_ips) or default_cn_san(subject)
    if san is not None:
        builder = builder.add_extension(san, critical=False)
    return builder.sign(private_key=key, algorithm=hashes.SHA256())
