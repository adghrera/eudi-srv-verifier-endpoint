#!/usr/bin/env python3
import sys
import json
import base64
import jks
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

def base64url_encode(data: bytes) -> str:
    """Encode bytes to unpadded base64url string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def int_to_base64url(val: int, length: int = None) -> str:
    """Convert an integer to big-endian bytes and base64url encode it."""
    if length is None:
        length = (val.bit_length() + 7) // 8
    val_bytes = val.to_bytes(length, byteorder="big")
    return base64url_encode(val_bytes)

def extract_jwk_from_cert(cert_der: bytes, kid: str) -> dict:
    """Parse DER certificate and build JWK representation for EC or RSA."""
    cert = x509.load_der_x509_certificate(cert_der)
    pub_key = cert.public_key()

    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        numbers = pub_key.public_numbers()
        curve_name = pub_key.curve.name
        
        # Determine curve and byte length
        curve_map = {
            "secp256r1": ("P-256", 32),
            "secp384r1": ("P-384", 48),
            "secp521r1": ("P-521", 66),
        }
        
        if curve_name not in curve_map:
            raise ValueError(f"Unsupported EC curve: {curve_name}")
            
        crv, coord_len = curve_map[curve_name]
        
        return {
            "kty": "EC",
            "crv": crv,
            "x": int_to_base64url(numbers.x, coord_len),
            "y": int_to_base64url(numbers.y, coord_len),
            "use": "sig",
            "kid": kid
        }

    elif isinstance(pub_key, rsa.RSAPublicKey):
        numbers = pub_key.public_numbers()
        return {
            "kty": "RSA",
            "n": int_to_base64url(numbers.n),
            "e": int_to_base64url(numbers.e),
            "use": "sig",
            "kid": kid
        }
    else:
        raise ValueError(f"Unsupported public key type: {type(pub_key)}")

def jks_to_jwkset(keystore_path: str, storepass: str, target_alias: str = None) -> str:
    keystore = jks.KeyStore.load(keystore_path, storepass)
    keys = []

    # Check both private keys and cert entries in JKS
    entries = {}
    entries.update(keystore.private_keys)
    entries.update(keystore.certs)

    if not entries:
        raise ValueError("No entries found in KeyStore.")

    if target_alias:
        if target_alias not in entries:
            raise KeyError(f"Alias '{target_alias}' not found in KeyStore. Available: {list(entries.keys())}")
        selected_aliases = [target_alias]
    else:
        selected_aliases = list(entries.keys())

    for alias in selected_aliases:
        entry = entries[alias]
        
        # Get certificate DER bytes
        if hasattr(entry, "cert_chain") and entry.cert_chain:
            # PrivateKeyEntry has cert_chain
            cert_der = entry.cert_chain[0][1]
        elif hasattr(entry, "cert"):
            # TrustedCertEntry
            cert_der = entry.cert
        else:
            continue

        jwk = extract_jwk_from_cert(cert_der, kid=alias)
        keys.append(jwk)

    jwk_set = {"keys": keys}
    return json.dumps(jwk_set, indent=2)

if __name__ == "__main__":
    # Configure your paths and credentials here
    KEYSTORE_FILE = "keystore.jks"
    KEYSTORE_PASS = "changeit"
    TARGET_ALIAS  = "verifier-key"  # Set to None to export all aliases

    try:
        jwkset_json = jks_to_jwkset(KEYSTORE_FILE, KEYSTORE_PASS, TARGET_ALIAS)
        print("Generated JWK Set:")
        print(jwkset_json)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)