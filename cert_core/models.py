"""Data models for certificate requests (no crypto logic here)."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SubjectInfo:
    cn: str
    c: str = "SA"
    st: str = ""
    l: str = ""
    o: str = ""
    ou: str = ""
    email: str = ""

    def validate(self) -> None:
        if not self.cn or not self.cn.strip():
            raise ValueError("CN field is required")


@dataclass
class KeySpec:
    key_type: str = "rsa"  # "rsa" | "ec"
    rsa_key_size: int = 2048
    ec_curve: str = "SECP256R1"
    password: str | None = None  # private-key encryption password (optional)

    def validate(self) -> None:
        if self.key_type.lower() not in ("rsa", "ec", "ecdsa"):
            raise ValueError("key_type must be 'rsa' or 'ec'")
        if self.key_type.lower() == "rsa" and self.rsa_key_size not in (2048, 3072, 4096):
            raise ValueError("rsa_key_size must be one of 2048, 3072, 4096")


@dataclass
class OutputSpec:
    out_dir: str = "./certs"
    filename: str = "cert"

    def validate(self) -> None:
        if not self.filename or not self.filename.strip():
            raise ValueError("filename is required")


@dataclass
class LeafRequest:
    subject: SubjectInfo
    key: KeySpec = field(default_factory=KeySpec)
    output: OutputSpec = field(default_factory=OutputSpec)
    san_dns: list[str] = field(default_factory=list)
    san_ips: list[str] = field(default_factory=list)
    days_valid: int = 825
    is_client: bool = False
    is_server: bool = True

    def validate(self) -> None:
        self.subject.validate()
        self.key.validate()
        self.output.validate()
        if self.days_valid <= 0:
            raise ValueError("days_valid must be a positive number")


@dataclass
class CaRequest:
    subject: SubjectInfo
    key: KeySpec = field(default_factory=KeySpec)
    output: OutputSpec = field(default_factory=OutputSpec)
    days_valid: int = 3650

    def validate(self) -> None:
        self.subject.validate()
        self.key.validate()
        self.output.validate()
        if self.days_valid <= 0:
            raise ValueError("days_valid must be a positive number")
