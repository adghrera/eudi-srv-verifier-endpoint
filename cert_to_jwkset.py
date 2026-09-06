#!/usr/bin/env python3
import json
import base64
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def int_to_base64url(val: int, length: int = None) -> str:
    if length is None:
        length = (val.bit_length() + 7) // 8
    val_bytes = val.to_bytes(length, byteorder="big")
    return base64url_encode(val_bytes)

def generate_jwk_set(cert_pem_path: str, kid: str = "verifier-key") -> str:
    with open(cert_pem_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    pub_key = cert.public_key()

    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        numbers = pub_key.public_numbers()
        curve_map = {
            "secp256r1": ("P-256", 32),
            "secp384r1": ("P-384", 48),
            "secp521r1": ("P-521", 66),
        }
        crv, coord_len = curve_map[pub_key.curve.name]

        key_dict = {
            "kty": "EC",
            "crv": crv,
            "x": int_to_base64url(numbers.x, coord_len),
            "y": int_to_base64url(numbers.y, coord_len),
            "use": "sig",
            "kid": kid
        }

    elif isinstance(pub_key, rsa.RSAPublicKey):
        numbers = pub_key.public_numbers()
        key_dict = {
            "kty": "RSA",
            "n": int_to_base64url(numbers.n),
            "e": int_to_base64url(numbers.e),
            "use": "sig",
            "kid": kid
        }
    else:
        raise ValueError(f"Unsupported key type: {type(pub_key)}")

    return json.dumps({"keys": [key_dict]}, indent=2)

if __name__ == "__main__":
    jwk_set_json = generate_jwk_set("verifier_cert.pem", kid="verifier-key")
    print(jwk_set_json)
    