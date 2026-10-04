"""High-level workflows used by both GUI and CLI (thin layers stay thin)."""
from __future__ import annotations

from dataclasses import dataclass

from . import certs as cert_builders
from . import keys, storage
from .models import CaRequest, LeafRequest
from .storage import cert_path, chain_path, ensure_dir, key_path
from .subject import build_subject


@dataclass
class IssuedFiles:
    key_file: str
    cert_file: str
    chain_file: str | None = None


def issue_self_signed_ca(req: CaRequest) -> IssuedFiles:
    req.validate()
    key = keys.generate_private_key(req.key.key_type, req.key.rsa_key_size, req.key.ec_curve)
    cert = cert_builders.create_self_signed_ca(key, build_subject(req.subject), days_valid=req.days_valid)
    ensure_dir(req.output.out_dir)
    kp = storage.save_private_key(key, key_path(req.output.out_dir, req.output.filename), req.key.password)
    cp = storage.save_cert(cert, cert_path(req.output.out_dir, req.output.filename))
    return IssuedFiles(key_file=kp, cert_file=cp)


def issue_intermediate_ca(req: CaRequest, issuer_cert_path: str, issuer_key_path: str,
                          issuer_key_password: str | None = None) -> IssuedFiles:
    req.validate()
    ca_key = storage.load_private_key(issuer_key_path, issuer_key_password)
    ca_cert = storage.load_cert(issuer_cert_path)
    int_key = keys.generate_private_key(req.key.key_type, req.key.rsa_key_size, req.key.ec_curve)
    cert = cert_builders.create_intermediate_ca(ca_key, ca_cert, int_key,
                                                build_subject(req.subject), days_valid=req.days_valid)
    ensure_dir(req.output.out_dir)
    kp = storage.save_private_key(int_key, key_path(req.output.out_dir, req.output.filename), req.key.password)
    cp = storage.save_cert(cert, cert_path(req.output.out_dir, req.output.filename))
    return IssuedFiles(key_file=kp, cert_file=cp)


def issue_signed_leaf(req: LeafRequest, issuer_cert_path: str, issuer_key_path: str,
                      issuer_key_password: str | None = None) -> IssuedFiles:
    req.validate()
    ca_key = storage.load_private_key(issuer_key_path, issuer_key_password)
    ca_cert = storage.load_cert(issuer_cert_path)
    leaf_key = keys.generate_private_key(req.key.key_type, req.key.rsa_key_size, req.key.ec_curve)
    cert = cert_builders.create_signed_cert(ca_key, ca_cert, leaf_key, build_subject(req.subject),
                                            san_dns=req.san_dns, san_ips=req.san_ips,
                                            days_valid=req.days_valid,
                                            is_client=req.is_client, is_server=req.is_server)
    ensure_dir(req.output.out_dir)
    kp = storage.save_private_key(leaf_key, key_path(req.output.out_dir, req.output.filename), req.key.password)
    cp = storage.save_cert(cert, cert_path(req.output.out_dir, req.output.filename))
    ch = storage.save_chain(cert, ca_cert, chain_path(req.output.out_dir, req.output.filename))
    return IssuedFiles(key_file=kp, cert_file=cp, chain_file=ch)


def issue_standalone(req: LeafRequest) -> IssuedFiles:
    req.validate()
    key = keys.generate_private_key(req.key.key_type, req.key.rsa_key_size, req.key.ec_curve)
    cert = cert_builders.create_standalone_self_signed(key, build_subject(req.subject),
                                                       san_dns=req.san_dns, san_ips=req.san_ips,
                                                       days_valid=req.days_valid)
    ensure_dir(req.output.out_dir)
    kp = storage.save_private_key(key, key_path(req.output.out_dir, req.output.filename), req.key.password)
    cp = storage.save_cert(cert, cert_path(req.output.out_dir, req.output.filename))
    return IssuedFiles(key_file=kp, cert_file=cp)
