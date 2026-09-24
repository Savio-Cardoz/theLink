#!/usr/bin/env python3
"""
Verify a signed theLink firmware image produced by scripts/sign_update.py.

Checks that <image>.sig is a valid ECDSA P-256 signature over the SHA-256
digest of <image>, using the given public key. Mirrors exactly what the
device does in main.cpp verify_firmware_signature().

Examples:
    python3 scripts/verify_update.py update.bin
    python3 scripts/verify_update.py --pub keys/prod_signing_pub.pem update.bin
"""

import argparse
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PUB = os.path.join(ROOT, "keys", "firmware_signing_pub.pem")


def main():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    from cryptography.exceptions import InvalidSignature

    parser = argparse.ArgumentParser(
        description="Verify a theLink signed OTA firmware image.")
    parser.add_argument("image", help="Firmware binary to verify")
    parser.add_argument("--pub", default=DEFAULT_PUB,
                        help="Public key PEM path (default: %s)" % DEFAULT_PUB)
    parser.add_argument("--sig", default=None,
                        help="Signature file (default: <image>.sig)")
    args = parser.parse_args()

    sig_path = args.sig or (args.image + ".sig")

    try:
        with open(args.pub, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        with open(args.image, "rb") as f:
            data = f.read()
        with open(sig_path, "rb") as f:
            signature = f.read()
    except OSError as e:
        sys.exit("error: %s" % e)

    digest = hashlib.sha256(data).digest()
    try:
        pub.verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature:
        sys.exit("FAIL: signature is NOT valid for %s" % args.image)

    print("OK: signature valid for %s (SHA-256 %s)" % (args.image, digest.hex()))


if __name__ == "__main__":
    main()