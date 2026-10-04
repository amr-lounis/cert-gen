"""File storage: save/load keys and certificates (PEM)."""
from __future__ import annotations

import os

from cryptography import x509
from cryptography.hazmat.primitives import serialization

_INVALID_CHARS = '<>:"/\\|?*'


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def sanitize_filename(name: str, fallback: str = "cert") -> str:
    name = (name or "").strip() or fallback
    for ch in _INVALID_CHARS:
        name = name.replace(ch, "_")
    return name


def key_path(out_dir: str, filename: str) -> str:
    return os.path.join(out_dir, sanitize_filename(filename) + ".key")


def cert_path(out_dir: str, filename: str) -> str:
    return os.path.join(out_dir, sanitize_filename(filename) + ".crt")


def chain_path(out_dir: str, filename: str) -> str:
    return os.path.join(out_dir, sanitize_filename(filename) + ".chain.crt")


def save_private_key(key, path: str, password: str | None = None) -> str:
    enc = serialization.NoEncryption()
    if password:
        enc = serialization.BestAvailableEncryption(password.encode())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=enc,
    )
    with open(path, "wb") as f:
        f.write(pem)
    return path


def save_cert(cert, path: str) -> str:
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return path


def save_chain(leaf_cert, issuer_cert, path: str) -> str:
    with open(path, "wb") as f:
        f.write(leaf_cert.public_bytes(serialization.Encoding.PEM))
        f.write(issuer_cert.public_bytes(serialization.Encoding.PEM))
    return path


def load_private_key(path: str, password: str | None = None):
    with open(path, "rb") as f:
        data = f.read()
    pw = password.encode() if password else None
    return serialization.load_pem_private_key(data, password=pw)


def load_cert(path: str):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())
