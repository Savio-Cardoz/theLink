#!/usr/bin/env python3
"""
TheLink build-profile switch. Dev is the default: a plain
`python3 scripts/build.py` produces a development build WITHOUT OTA.

    Dev  : standard partition table WITHOUT OTA (partitions_dev.csv). idf.py
           flashes the app straight to the 'factory' partition; the
           esp32_factory_app bootloader is NOT used. Build dir: build-dev
    Prod : production partition table for OTA via esp32_factory_app
           (partitions.csv). Build dir: build

Every build that produces a binary also asks for the MQTT broker settings - the
broker URL and its credentials - the first time, and caches them in the
gitignored sdkconfig.secrets (see mqtt_secrets.py). Answer the prompt once and
every later build reuses the cache. Skipping the prompt is fine: the broker URL
then comes from menuconfig and the firmware connects anonymously, exactly as it
did before. Use --reprompt to change the settings, --no-prompt to never be asked
(for CI or for a scripted build), or set THELINK_BROKER_URL,
THELINK_MQTT_USERNAME and THELINK_MQTT_PASSWORD to supply them
non-interactively.

idf.py is launched with the ESP-IDF Python interpreter (see idf_env.py). Run
this from any terminal; running the ESP-IDF export script first is optional.

Examples:
    python3 scripts/build.py
    python3 scripts/build.py -p Dev flash
    python3 scripts/build.py flash           # Dev (default) + flash
    python3 scripts/build.py -p Prod
    python3 scripts/build.py -p Prod flash
    python3 scripts/build.py -p Dev menuconfig
    python3 scripts/build.py -p Dev --clean
    python3 scripts/build.py --reprompt      # ask for new MQTT credentials
    python3 scripts/build.py --no-prompt     # fail soft, never prompt
"""

import argparse
import hashlib
import os
import subprocess
import sys

import idf_env
import mqtt_secrets as secrets

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PROFILES = {
    "Dev": {
        "build_dir": os.path.join(ROOT, "build-dev"),
        "sdkconfig_defaults": "sdkconfig.defaults;sdkconfig.dev",
        "partition": "partitions_dev.csv (standard, no OTA)",
    },
    "Prod": {
        "build_dir": os.path.join(ROOT, "build"),
        "sdkconfig_defaults": "sdkconfig.defaults;sdkconfig.prod",
        "partition": "partitions.csv (esp32_factory_app OTA)",
    },
}


def defaults_signature(defaults_spec):
    """SHA-256 of the SDKCONFIG_DEFAULTS files (missing files hash as '<missing>')."""
    h = hashlib.sha256()
    for name in defaults_spec.split(";"):
        path = os.path.join(ROOT, name) if not os.path.isabs(name) else name
        try:
            with open(path, "rb") as f:
                h.update(f.read())
        except OSError:
            h.update(b"<missing>")
    return h.hexdigest()


def ensure_sdkconfig(build_dir, defaults_spec):
    """
    Make sure the per-profile sdkconfig inside the build dir matches the current
    defaults. ESP-IDF keeps values already present in an existing sdkconfig and
    only applies defaults for missing keys, so switching profiles (or editing
    the partitions CSV) would silently keep the old configuration. We remove the
    generated sdkconfig whenever the defaults have changed (tracked via a stamp
    file) so idf.py regenerates it from scratch.
    """
    os.makedirs(build_dir, exist_ok=True)
    sdkconfig = os.path.join(build_dir, "sdkconfig")
    stamp = os.path.join(build_dir, ".sdkconfig-defaults-sha")
    sig = defaults_signature(defaults_spec)
    try:
        with open(stamp, "r") as f:
            prev = f.read()
    except OSError:
        prev = None
    if prev != sig:
        print("SDKCONFIG_DEFAULTS changed - regenerating %s" % sdkconfig)
        for f in (sdkconfig,
                  os.path.join(build_dir, "config", "sdkconfig.h"),
                  os.path.join(build_dir, "config", "sdkconfig.cmake"),
                  os.path.join(build_dir, "config", "sdkconfig.json")):
            try:
                os.remove(f)
            except OSError:
                pass
        with open(stamp, "w") as f:
            f.write(sig)
    return sdkconfig


def main():
    parser = argparse.ArgumentParser(
        description="TheLink ESP-IDF build-profile switch (Dev is the default).")
    parser.add_argument("-p", "--profile", choices=sorted(PROFILES), default="Dev",
                        help="Build profile, Dev or Prod (default: Dev)")
    parser.add_argument("-a", "--action", default="build",
                        help="idf.py action, e.g. build, flash, menuconfig (default: build)")
    parser.add_argument("--port", default=os.environ.get("ESPPORT"),
                        help="Serial port (default: $ESPPORT)")
    parser.add_argument("--reprompt", action="store_true",
                        help="Ask for the MQTT credentials again, replacing the "
                             "ones cached in %s" % secrets.SECRETS_BASENAME)
    parser.add_argument("--no-prompt", action="store_true",
                        help="Never ask for the MQTT credentials. Use the "
                             "environment variables or the cached %s, and build "
                             "anonymously if there are none"
                             % secrets.SECRETS_BASENAME)
    parser.add_argument("--clean", action="store_true",
                        help="idf.py fullclean the build dir first")
    parser.add_argument("idf_args", nargs="*",
                        help="Extra arguments forwarded to idf.py")
    args = parser.parse_args()

    profile = PROFILES[args.profile]
    invoke = idf_env.find_idf_invoke()
    if not invoke:
        sys.exit("error: idf.py not found. Install ESP-IDF or set IDF_PATH, "
                 "or run the ESP-IDF export script (export.ps1/export.bat) first.")

    print("TheLink build profile: %s" % args.profile)
    print("  partition table : %s" % profile["partition"])
    print("  sdkconfig        : %s" % profile["sdkconfig_defaults"])
    print("  builds dir       : %s" % profile["build_dir"])
    print("  interpreter      : %s" % invoke[0])
    print("  idf.py           : %s" % invoke[-1])

    # A bare fullclean throws the build away and creates no binary, so there is
    # nothing for the broker settings to go into.
    build_dir = profile["build_dir"]
    defaults_spec = profile["sdkconfig_defaults"]
    if args.action != "fullclean":
        settings = secrets.resolve(os.path.join(build_dir, "sdkconfig"),
                                   allow_prompt=not args.no_prompt,
                                   force_prompt=args.reprompt)
        if settings:
            defaults_spec = "%s;%s" % (defaults_spec, secrets.SECRETS_BASENAME)
            print("  sdkconfig        : %s" % defaults_spec)

    if args.clean:
        print("Cleaning %s" % build_dir)
        cmd = invoke + ["-B", build_dir, "fullclean"]
        print("Running: %s" % " ".join(cmd))
        rc = subprocess.call(cmd, env=idf_env.build_env())
        if rc != 0:
            sys.exit(rc)

    sdkconfig = ensure_sdkconfig(build_dir, defaults_spec)
    print("  sdkconfig file   : %s" % sdkconfig)

    cmd = invoke + ["-B", build_dir,
                    "-DSDKCONFIG=%s" % sdkconfig,
                    "-DSDKCONFIG_DEFAULTS=%s" % defaults_spec]
    if args.port:
        cmd += ["-p", args.port]
    cmd += args.idf_args
    cmd += [args.action]

    print("Running: %s" % " ".join(cmd))
    sys.exit(subprocess.call(cmd, env=idf_env.build_env()))


if __name__ == "__main__":
    main()