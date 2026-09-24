# Signed OTA firmware updates (theLink)

This document describes how theLink OTA firmware images are signed and
verified, end to end.

**Implemented (Tier A): application-level ECDSA P-256 verification.**
The device hashes `update.bin` with SHA-256, then verifies a DER-encoded
ECDSA P-256 signature against a public key embedded in the firmware. No
eFuses are touched, so it is easy to adopt and to rotate.

**Documented but not enabled (Tier B): ESP-IDF Secure Boot v2 + Flash
Encryption.** Hardware-backed, irreversible boot lockdown. See
[Tier B](#tier-b-secure-boot-v2--flash-encryption) for the steps if you want
to move to it later.

---

## 1. Threat model

| Threat | Attack | Mitigated by |
|--------|--------|--------------|
| Fake firmware over the broker | Attacker publishes a malicious `update.bin` to `thelink/<id>/cmd/ota` | HMAC command gate (optional, `CONFIG_MQTT_HMAC_MODE`) **and** image signature |
| Tampered download | MITM replaces `update.bin` while it is downloaded over (plain) HTTP | Image signature — the digest won't verify |
| SD card swap | Someone replaces `/sdcard/update.bin` in the field | Image signature (and `update.bin.sig` must match) |
| Replay of an old signed image | Attacker replays an *old, still-signed* image to downgrade | Optional version/downgrade counter in NVS (section 4) |
| Physical flash attack | Attacker flashes the chip directly | **Not** covered by Tier A — only Tier B (secure boot) covers this |

Tier A protects the **update channel** but not a device that is physically
attacked with a flasher. Tier B protects the device itself.

---

## 2. Algorithm

```
digest    = SHA-256(update.bin)                    # 32 bytes
signature = ECDSA-Sign(P-256, privkey, digest)     # DER/ASN.1, ~70 bytes
```

- **Hash-then-sign**: only the 32-byte SHA-256 digest is signed, never the
  whole binary. ECDSA signs digests by design, so this is both the natural
  and the correct construction.
- The signature is DER-encoded ASN.1 (`SEQUENCE { INTEGER r, INTEGER s }`),
  exactly what mbedTLS's `mbedtls_pk_verify()` expects.
- Curve: `SECP256R1` (NIST P-256), deterministic (RFC 6979) — `cryptography`
  uses deterministic ECDSA by default.
- Signature file name: `<image>.sig` (e.g. `update.bin.sig`) placed next to
  the image on the SD card.

---

## 3. Host-side workflow

### 3.1 One-time: generate the signing key

```bash
python3 scripts/sign_update.py --genkey
```

This creates:

| File | Purpose |
|------|---------|
| `keys/firmware_signing.pem` | **PRIVATE key — never commit, back it up offline** (mode 0600) |
| `keys/firmware_signing_pub.pem` | Public key (for CI verification) |
| `main/firmware_pubkey.h` | Public key embedded in the firmware |

`keys/` is in `.gitignore`. After generating a key you **must rebuild the
firmware** so the new public key is embedded:

```bash
python3 scripts/build.py -p Prod
```

> A device only accepts images signed by the key whose public half it was
> **built with**. There is no runtime key update.

### 3.2 Every release: sign the image

```bash
python3 scripts/sign_update.py build/thelink_esp32s3.bin
# -> build/thelink_esp32s3.bin.sig
```

Upload both files; the OTA command must point the downloader at the `.bin`,
and the device picks up the sibling `.sig` automatically
(`verify_firmware_signature()` in `main/main.cpp` opens `update.bin.sig`).

### 3.3 CI check (optional)

```bash
python3 scripts/verify_update.py build/thelink_esp32s3.bin
# OK: signature valid for ...
```

Exit code is 0 on success, 1 on failure/tamper.

### 3.4 Alternatives / no `cryptography`?

Any ECDSA-capable tool works, as long as the output is DER and keys are
P-256. For example with OpenSSL (sign the digest produced beforehand):

```bash
openssl dgst -sha256 -binary update.bin > digest.bin
openssl pkeyutl -sign -inkey keys/firmware_signing.pem \
        -in digest.bin -out update.bin.sig
```

The `--key` flag lets you keep the production key out of the default path:

```bash
python3 scripts/sign_update.py --key /secure/offline/prod.pem build/thelink_esp32s3.bin
```

---

## 4. Device-side verification

`verify_firmware_signature()` in `main/main.cpp` runs inside
`handle_firmware_update()` **after** the image size/magic checks and **before**
any NVS update intent or boot-partition change:

1. Stream `update.bin` through SHA-256 (`mbedtls_md_*`) → 32-byte digest.
2. Read `update.bin.sig` (≤ 256 bytes; must be ≥ 64 bytes).
3. `mbedtls_pk_parse_public_key(THELINK_FIRMWARE_PUBKEY_PEM)` (from
   `main/firmware_pubkey.h`).
4. `mbedtls_pk_verify(MBEDTLS_MD_SHA256, digest, 32, sig, sig_len)`.
5. Fail ⇒ `publish_ota_event("failed", "bad firmware signature")`, abort —
   the boot partition is never changed.

Gate: `CONFIG_OTA_SIGNATURE_VERIFY` (default `y`). Set to `n` to accept
unsigned images (not recommended).

### 4.1 Downgrade protection (optional, not implemented)

Tier A verifies *authenticity*, not *freshness*. To block downgrades, store
the last accepted firmware version in NVS and reject any signed image whose
version ≤ the stored one (e.g. in the `ota` NVS namespace used by the OTA
handshake, next to `ota/state`). This is deliberately left as a per-product
decision: version reporting from `update.bin` is not currently part of the
image header.

---

## 5. Key management & rotation

- **Protect the private key.** Keep it on an offline machine or HSM; make an
  encrypted backup. Loss = you can never sign again. Leak = anyone can sign.
- **Rotation** = generate a new key, rebuild the firmware (embeds the new
  public key), ship it via the *old* key, then sign future releases with the
  new key. Devices still on the old firmware keep accepting old-key images;
  devices on the new firmware accept only new-key images.
- The generated `firmware_pubkey.h` is safe to commit (public material).

---

## 6. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `signature file update.bin.sig is missing` | Sign the image, or disable `CONFIG_OTA_SIGNATURE_VERIFY` |
| `signature check failed (mbedtls rc=...)` | Wrong key embedded, tampered image, or mangled `.sig` |
| Works in `verify_update.py` but fails on device | Device firmware embedded a *different* public key — rebuild after `--genkey` |
| Wrong tool versions / P-521 keys | Keys must be P-256 (`SECP256R1`); DER (not raw R||S) signatures |

---

## 7. Tier B — Secure Boot v2 + Flash Encryption

Optional hardware-backed hardening (ESP-IDF). This is **irreversible** in
production — burn the eFuses only on units you are committed to.

1. **Flash encryption** — `CONFIG_SECURE_FLASH_ENC_ENABLED=y`; the whole
   flash content (firmware, partition table) is encrypted with a key in
   eFuse. Encrypt the bootloader first (`espsecure.py
   encrypt_bootloader`) or the chain breaks.
2. **Secure Boot v2** — `CONFIG_SECURE_BOOT=y`. The second-stage bootloader
   is signed with an RSA/ECDSA key generated by
   `espsecure.py generate_signing_key`; the public key hash is burned into
   eFuse (`CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y`). Every app image and
   the bootloader itself must then be signed with
   `espsecure.py sign_data`, and only digest-signed `update.bin` content
   that passes the ROM/app verification chain will run.
3. **Release flow with Tier B:**
   ```bash
   espsecure.py sign_data --key keys/secure_boot_signing_key.pem \
       --output build/thelink_esp32s3.sig.bin build/thelink_esp32s3.bin
   esptool.py --flash-mode dio write_flash <offset> build/thelink_esp32s3.sig.bin
   ```
   Signing happens **again** at bootloader/app level, in addition to the
   OTA-channel signature from Tier A.
4. **Key handling** — the signing key lives offline; only the SHA-256 of its
   public key goes into the fuses (`CONFIG_SECURE_BOOT_VERIFY_KEY` /
   `espsecure.py digest_rsa_public_key`).

With Tier B, an attacker cannot boot modified firmware even with physical
access, closing the last gap of the threat model in section 1.

---

## Appendix — reference parameters

| Parameter | Value |
|-----------|-------|
| Curve | `SECP256R1` (NIST P-256) |
| Hash | SHA-256 |
| Signature scheme | ECDSA (digest-signed), DER/ASN.1 |
| Signature file | `<image>.sig`, read up to 256 bytes, min 64 |
| Embedded key | `main/firmware_pubkey.h` → `THELINK_FIRMWARE_PUBKEY_PEM` |
| Device hook | `verify_firmware_signature()` in `main/main.cpp` |
| Tools | `scripts/sign_update.py`, `scripts/verify_update.py` |