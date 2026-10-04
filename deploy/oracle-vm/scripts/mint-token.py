#!/usr/bin/env python3
"""Generate the OIDC signing key/JWKS this deployment uses, and mint bearer
tokens against it — for the admin panel (needs the "admin" tag) and for
client devices (--token-file on `ferrum up-mesh`).

This is a self-issued auth setup, not a real external identity provider: the
coordinator's OidcVerifier just checks a token was signed by the key in
secrets/jwks.json and carries the configured issuer/audience/tags — this
script is the only "issuer" that exists. See crates/coordinator/src/auth.rs.

Usage:
    python3 mint-token.py init
        Generates secrets/signing-key.pem (private — never share, never
        mount into a container) and secrets/jwks.json (public — this is what
        gets mounted read-only into the coordinator via docker-compose.yml).
        Refuses to overwrite an existing key.

    python3 mint-token.py mint --sub alice --tags admin --issuer https://ferrum.internal --audience ferrum-admin [--ttl 3600]
        Prints a signed bearer token to stdout. Match --issuer/--audience to
        the coordinator's OIDC_ISSUER/OIDC_AUDIENCE (.env) or verification
        fails. Use --tags admin for the admin panel; use --tags <device-tag>
        (e.g. dev, server) for a device's --token-file; use --tags relay for a
        self-announcing relay's --token-file (`ferrum relay --coordinator`;
        the coordinator refuses relay heartbeats from other tokens, SEC-013).

Requires: pip install cryptography
"""
import argparse
import base64
import json
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.utils import int_to_bytes

KID = "k1"
SCRIPT_DIR = Path(__file__).resolve().parent
SECRETS_DIR = SCRIPT_DIR.parent / "secrets"
KEY_PATH = SECRETS_DIR / "signing-key.pem"
JWKS_PATH = SECRETS_DIR / "jwks.json"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def cmd_init(_args):
    SECRETS_DIR.mkdir(exist_ok=True)
    if KEY_PATH.exists():
        sys.exit(f"refusing to overwrite existing {KEY_PATH}")

    private_key = ec.generate_private_key(ec.SECP256R1())
    KEY_PATH.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    KEY_PATH.chmod(0o600)

    nums = private_key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": KID,
                "x": b64u(int_to_bytes(nums.x, 32)),
                "y": b64u(int_to_bytes(nums.y, 32)),
            }
        ]
    }
    JWKS_PATH.write_text(json.dumps(jwks))
    print(f"wrote {KEY_PATH} (private — keep this off the coordinator host if you can)")
    print(f"wrote {JWKS_PATH} (public — mount this read-only into the coordinator)")


def cmd_mint(args):
    if not KEY_PATH.exists():
        sys.exit(f"{KEY_PATH} not found — run `mint-token.py init` first")
    private_key = serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)

    tags = [t.strip() for t in args.tags.split(",") if t.strip()]
    exp = int(time.time()) + args.ttl
    header = {"alg": "ES256", "kid": KID, "typ": "JWT"}
    payload = {
        "iss": args.issuer,
        "aud": args.audience,
        "sub": args.sub,
        "exp": exp,
        "tags": tags,
    }
    signing_input = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(payload).encode())}"
    der_sig = private_key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = int_to_bytes(r, 32) + int_to_bytes(s, 32)
    print(f"{signing_input}.{b64u(raw_sig)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="generate the signing key + JWKS (once)")

    p_mint = sub.add_parser("mint", help="mint a bearer token")
    p_mint.add_argument("--sub", required=True, help="token subject, e.g. a device or operator name")
    p_mint.add_argument("--tags", required=True, help="comma-separated tags, e.g. admin or dev,server")
    p_mint.add_argument("--issuer", required=True, help="must match the coordinator's --oidc-issuer / OIDC_ISSUER")
    p_mint.add_argument("--audience", required=True, help="must match the coordinator's --oidc-audience / OIDC_AUDIENCE")
    p_mint.add_argument("--ttl", type=int, default=3600, help="seconds until expiry (default 3600)")

    args = parser.parse_args()
    {"init": cmd_init, "mint": cmd_mint}[args.command](args)


if __name__ == "__main__":
    main()
