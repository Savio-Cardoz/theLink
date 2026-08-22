#!/usr/bin/env python3
"""
Convert a PNG image to a 200x200 black-and-white .bin file
compatible with the TheLink e-paper display (LVGL I8 format).

Output format:
  - 12-byte LVGL image header
  - 1024-byte palette (256 BGRA entries, only index 0 and 1 used)
  - 40000 bytes of pixel indices (200 * 200)

Usage:
    python png_to_epaper.py input.png [output.bin] [--threshold 128] [--invert]
"""

import argparse
import struct
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("Error: Pillow is required. Install it with:")
    print("  pip install Pillow")
    sys.exit(1)

WIDTH = 200
HEIGHT = 200
PALETTE_SIZE = 256 * 4   # 256 entries, 4 bytes each (BGRA)
HEADER_SIZE = 12
PIXEL_COUNT = WIDTH * HEIGHT
EXPECTED_FILE_SIZE = HEADER_SIZE + PALETTE_SIZE + PIXEL_COUNT  # 41036 bytes

# LVGL 9.x I8 color format
LV_IMG_CF_I8 = 0x07
LV_IMAGE_HEADER_MAGIC = 0x0019


def build_header(width: int, height: int) -> bytes:
    """Build a 12-byte LVGL image header for I8 format."""
    return struct.pack(
        "<HHHHH",
        LV_IMAGE_HEADER_MAGIC,  # magic
        LV_IMG_CF_I8,           # cf (color format)
        0,                      # flags
        width,                  # w
        height,                 # h
    ) + struct.pack("<H", 0)   # reserved_2 (2 bytes to make 12 total)


def build_palette() -> bytes:
    """
    Build a 1024-byte BGRA palette.
    Index 0 = black (0,0,0,255), Index 1 = white (255,255,255,255).
    All other indices are zeroed (unused).
    """
    palette = bytearray(PALETTE_SIZE)
    # Index 0: black  (B=0, G=0, R=0, A=255)
    palette[0:4] = bytes([0x00, 0x00, 0x00, 0xFF])
    # Index 1: white  (B=255, G=255, R=255, A=255)
    palette[4:8] = bytes([0xFF, 0xFF, 0xFF, 0xFF])
    return bytes(palette)


def convert_image(input_path: str, threshold: int = 128, invert: bool = False) -> bytes:
    """Load an image, resize to 200x200, threshold to B&W, return I8 binary."""
    img = Image.open(input_path)

    # Resize to 200x200 using high-quality resampling
    img = img.resize((WIDTH, HEIGHT), Image.LANCZOS)

    # Convert to grayscale
    img = img.convert("L")

    # Threshold to binary (0 or 1 index)
    pixels = img.load()
    indices = bytearray(PIXEL_COUNT)
    for y in range(HEIGHT):
        for x in range(WIDTH):
            brightness = pixels[x, y]
            if invert:
                is_white = brightness < threshold
            else:
                is_white = brightness >= threshold
            indices[y * WIDTH + x] = 1 if is_white else 0

    # Assemble the binary file
    header = build_header(WIDTH, HEIGHT)
    palette = build_palette()
    return header + palette + bytes(indices)


def main():
    parser = argparse.ArgumentParser(
        description="Convert a PNG to a 200x200 B&W .bin for the TheLink e-paper display."
    )
    parser.add_argument("input", help="Input PNG image path")
    parser.add_argument("output", nargs="?", default=None,
                        help="Output .bin path (default: <input_stem>.bin)")
    parser.add_argument("--threshold", type=int, default=128,
                        help="Brightness threshold 0-255 (default: 128). "
                             "Pixels above this become white, below become black.")
    parser.add_argument("--invert", action="store_true",
                        help="Invert black and white")
    parser.add_argument("--preview", action="store_true",
                        help="Save a preview PNG showing the thresholded result")

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)

    output_path = Path(args.output) if args.output else input_path.with_suffix(".bin")

    print(f"Input:   {input_path}")
    print(f"Output:  {output_path}")
    print(f"Size:    {WIDTH}x{HEIGHT}")
    print(f"Threshold: {args.threshold}")
    print(f"Invert:  {args.invert}")

    binary = convert_image(str(input_path), args.threshold, args.invert)

    output_path.write_bytes(binary)
    print(f"Wrote {len(binary)} bytes (expected {EXPECTED_FILE_SIZE})")

    if args.preview:
        preview_path = input_path.with_name(input_path.stem + "_preview.png")
        # Re-read the indices from the binary and render as a preview
        indices = binary[HEADER_SIZE + PALETTE_SIZE:]
        preview = Image.new("L", (WIDTH, HEIGHT))
        px = preview.load()
        for i, idx in enumerate(indices):
            # Index 0 = black (0), Index 1 = white (255)
            px[i % WIDTH, i // WIDTH] = 0 if idx == 0 else 255
        preview.save(str(preview_path))
        print(f"Preview: {preview_path}")

    print("Done.")


if __name__ == "__main__":
    main()
