"""Subject (DN) and SAN helpers."""
from __future__ import annotations

import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID

from .models import SubjectInfo


def build_subject(info: SubjectInfo) -> x509.Name:
    """Build an x509.Name from a SubjectInfo."""
    info.validate()
    attrs: list[x509.NameAttribute] = []
    if info.c:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, info.c))
    if info.st:
        attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, info.st))
    if info.l:
        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, info.l))
    if info.o:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, info.o))
    if info.ou:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, info.ou))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, info.cn.strip()))
    if info.email:
        attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, info.email))
    return x509.Name(attrs)


def parse_san_list(text: str | None) -> list[str]:
    """Split a SAN string by comma, semicolon, space or newline."""
    if not text:
        return []
    parts = text.replace(";", ",").replace("\n", ",").replace(" ", ",").split(",")
    return [p.strip() for p in parts if p.strip()]


def san_extension(san_dns: list[str] | None, san_ips: list[str] | None) -> x509.SubjectAlternativeName | None:
    names: list[x509.GeneralName] = []
    for d in san_dns or []:
        d = d.strip()
        if d:
            names.append(x509.DNSName(d))
    for ip in san_ips or []:
        ip = ip.strip()
        if ip:
            names.append(x509.IPAddress(ipaddress.ip_address(ip)))
    if not names:
        return None
    return x509.SubjectAlternativeName(names)


def default_cn_san(subject: x509.Name) -> x509.SubjectAlternativeName | None:
    """Fallback SAN from CN (browsers require SAN, not only CN)."""
    try:
        cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        return x509.SubjectAlternativeName([x509.DNSName(cn)])
    except IndexError:
        return None
