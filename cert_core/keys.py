"""Private-key generation."""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec, rsa

_EC_CURVES = {
    "SECP256R1": ec.SECP256R1,
    "SECP384R1": ec.SECP384R1,
    "SECP521R1": ec.SECP521R1,
}


def generate_private_key(key_type: str = "rsa", rsa_key_size: int = 2048, ec_curve: str = "SECP256R1"):
    """Generate an RSA or ECDSA private key object."""
    kt = (key_type or "rsa").lower()
    if kt == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=int(rsa_key_size))
    if kt in ("ec", "ecdsa"):
        curve_cls = _EC_CURVES.get((ec_curve or "SECP256R1").upper(), ec.SECP256R1)
        return ec.generate_private_key(curve_cls())
    raise ValueError("key_type must be 'rsa' or 'ec'")
