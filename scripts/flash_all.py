#!/usr/bin/env python3
"""
Flash the full production TheLink stack (ESP32-S3, 8 MB flash):

    0x0       bootloader
    0x8000    partition table
    0xe000    otadata     -> selects ota_0 (programmed, default state NEW)
    0x10000   factory     -> bootloader app (esp32_factory_app)
    0x210000  ota_0       -> TheLink main app

The otadata partition is programmed so the very first boot goes straight into
the freshly flashed main app (ota_0) instead of the factory app. With state
NEW (the default) the bootloader marks it PENDING_VERIFY and TheLink confirms
it VALID on first boot, so crash-back protection is preserved. Pass
--no-otadata to skip programming otadata (device boots the factory app, the
pre-OTA behavior).

esptool is launched with the ESP-IDF Python interpreter, which has esptool
installed (see idf_env.py). Run this from any terminal; running the ESP-IDF
export script first is optional.

Examples:
    python3 scripts/flash_all.py
    python3 scripts/flash_all.py -p COM6
    python3 scripts/flash_all.py --ota valid
    python3 scripts/flash_all.py --no-otadata
"""

import argparse
import os
import struct
import subprocess
import sys
import tempfile
import zlib

import idf_env

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FACTORY_APP_BUILD = os.path.join(os.path.dirname(ROOT), "esp32_factory_app", "build")

# esp_ota_select_entry_t state values (ESP_IDF esp_flash_partitions.h)
OTA_STATE_NEW = 0x0            # bootloader -> PENDING_VERIFY, app confirms VALID
OTA_STATE_VALID = 0x2          # app pre-confirmed; no first-boot rollback
OTA_STATES = {"new": OTA_STATE_NEW, "valid": OTA_STATE_VALID}

OTADATA_ADDR = 0xE000
OTADATA_SIZE = 0x2000          # 2 x 4 KB sectors; two 32-byte entries, one per sector

# The production layout flash_all.py flashes: [bootloader][ptable][otadata]
# [factory app][ota_0].
EXPECTED_PARTITIONS = {
    "otadata": (0xE000, 0x2000),
    "factory": (0x10000, 0x200000),
    "ota_0": (0x210000, 0x500000),
}


def check_partition_table(path):
    """Parse an ESP-IDF partition-table binary and require the OTA layout.

    Aborts with a clear message when the build's partition table does not match
    (e.g. a stale build directory that still used the dev/old single-app
    table), instead of bricking the first boot by flashing a table without
    otadata.
    """
    with open(path, "rb") as f:
        data = f.read()
    found = {}
    idx = 0
    while idx + 32 <= len(data):
        magic = struct.unpack("<H", data[idx:idx + 2])[0]
        if magic != 0x50AA:
            break
        subtype = data[idx + 3]
        offset, size = struct.unpack("<II", data[idx + 4:idx + 12])
        label = data[idx + 12:idx + 28].decode("latin-1").rstrip("\x00")
        found[label] = (offset, size, subtype)
        idx += 32
    for name, (exp_off, exp_size) in EXPECTED_PARTITIONS.items():
        if name not in found:
            sys.exit("error: partition table %s has no '%s' partition\n"
                     "  Make sure the Prod build is up to date (scripts/build.py -p Prod)"
                     " and that build/partition_table/partition-table.bin contains the OTA"
                     " layout." % (path, name))
        offset, size = found[name][0], found[name][1]
        if offset != exp_off or size < exp_size:
            sys.exit("error: partition table %s has '%s' at 0x%x size 0x%x, expected"
                     " 0x%x / >= 0x%x (stale build dir?)" % (
                         path, name, offset, size, exp_off, exp_size))
    return found


def make_otadata(ota_seq=1, label=b"", state=OTA_STATE_NEW):
    """
    Build a full-size otadata image selecting an OTA app.

    Mirrors the ESP-IDF esp_ota_select_entry_t layout (32 bytes, little
    endian, two copies one per 4 KB sector) and the bootloader CRC
    (esp_rom_crc32_le(UINT32_MAX, &ota_seq, 4), i.e. reflected CRC-32 of the
    4-byte ota_seq field with init register 0xFFFFFFFF and no final xor).
    """
    # Python zlib.crc32 returns (register ^ 0xFFFFFFFF); XOR back to get the
    # raw register value esp_rom_crc32_le returns.
    crc = zlib.crc32(struct.pack("<I", ota_seq), 0) ^ 0xFFFFFFFF
    entry = struct.pack("<I", ota_seq) + label[:20].ljust(20, b"\x00") \
        + struct.pack("<I", state) + struct.pack("<I", crc)
    assert len(entry) == 32, "esp_ota_select_entry_t must be 32 bytes"

    image = bytearray(b"\xFF" * OTADATA_SIZE)
    image[0:32] = entry          # slot 0 selects ota_0
    return entry, bytes(image)


def validate_otadata(entry, state, ota_seq=1):
    """Recompute the bootloader CRC for a generated entry (self-check)."""
    crc = zlib.crc32(struct.pack("<I", ota_seq), 0) ^ 0xFFFFFFFF
    assert struct.unpack("<I", entry[28:32])[0] == crc, "otadata CRC mismatch"
    assert struct.unpack("<I", entry[24:28])[0] == state, "otadata state mismatch"
    assert struct.unpack("<I", entry[0:4])[0] == ota_seq, "otadata seq mismatch"


def main():
    parser = argparse.ArgumentParser(
        description="Flash the full production TheLink stack (bootloader, partition table, "
                    "otadata, esp32_factory_app + main app).")
    parser.add_argument("-p", "--port", default=os.environ.get("ESPPORT"),
                        help="Serial port (default: $ESPPORT)")
    parser.add_argument("--thelink-build", default=os.path.join(ROOT, "build"),
                        help="TheLink main app build dir (default: <root>/build)")
    parser.add_argument("--factory-app-build", default=FACTORY_APP_BUILD,
                        help="esp32_factory_app build dir (default: %s)" % FACTORY_APP_BUILD)
    ota_group = parser.add_mutually_exclusive_group()
    ota_group.add_argument("--ota", choices=sorted(OTA_STATES), default="new",
                           help="otadata state selecting ota_0 on first boot: 'new' "
                                "(default, rollback-safe, app confirms VALID on first boot) "
                                "or 'valid' (no first-boot rollback protection).")
    ota_group.add_argument("--no-otadata", action="store_true",
                           help="Do not program otadata; first boot goes to the factory app "
                                "(pre-OTA behavior).")
    args = parser.parse_args()

    port = args.port
    if not port:
        sys.exit("error: no COM port found. Pass -p COMxx.")

    bootloader = os.path.join(args.thelink_build, "bootloader", "bootloader.bin")
    part_table = os.path.join(args.thelink_build, "partition_table", "partition-table.bin")
    thelink_app = os.path.join(args.thelink_build, "theLink_esp32s3.bin")
    factory_app = os.path.join(args.factory_app_build, "factory_app.bin")

    for f in (bootloader, part_table, thelink_app, factory_app):
        if not os.path.isfile(f):
            sys.exit("error: missing build artifact: %s" % f)

    part_table_entries = check_partition_table(part_table)

    invoke = idf_env.find_esptool()
    if not invoke:
        sys.exit("error: esptool not found in the ESP-IDF Python environment and not "
                 "importable by %s. Install ESP-IDF or run the ESP-IDF export script "
                 "(export.ps1/export.bat) first." % sys.executable)

    print("Flashing TheLink stack to %s" % port)
    print("  interpreter:     %s" % invoke[0])
    print("  bootloader:      %s" % bootloader)
    print("  partition table: %s" % part_table)
    print("  factory app:     %s (bootloader app)" % factory_app)
    print("  ota_0 app:       %s (main app)" % thelink_app)

    cmd = invoke + [
        "--chip", "esp32s3", "--port", port, "write_flash",
        "--flash_mode", "dio", "--flash_size", "8MB", "--flash_freq", "80m",
        "0x0", bootloader,
        "0x8000", part_table,
        "0x10000", factory_app,
        "0x210000", thelink_app,
    ]

    if not args.no_otadata:
        state = OTA_STATES[args.ota]
        entry, otadata = make_otadata(state=state)
        validate_otadata(entry, state)
        tmp = os.path.join(tempfile.gettempdir(), "thelink_otadata.bin")
        with open(tmp, "wb") as f:
            f.write(otadata)
        cmd += [hex(OTADATA_ADDR), tmp]
        print("  otadata:         @ 0x%04x seq=1 state=%s -> ota_0 (%s)" % (
            OTADATA_ADDR, args.ota, tmp))
    else:
        print("  otadata:         not programmed (first boot -> factory app)")

    print("Running: %s" % " ".join(cmd))
    sys.exit(subprocess.call(cmd, env=idf_env.build_env()))


if __name__ == "__main__":
    main()


if __name__ == "__main__":
    main()