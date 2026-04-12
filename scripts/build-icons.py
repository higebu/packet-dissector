#!/usr/bin/env python3
"""Generate iOS / Android / Store app icons from a master SVG.

Usage:
    python3 build-icons.py [--renderer=cairosvg|rsvg]

Requires either ``cairosvg`` (pip) or ``rsvg-convert`` (librsvg2-bin).
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent.parent
MASTER_SVG = ROOT_DIR / "assets" / "pcap-icon.svg"
DERIVED_DIR = ROOT_DIR / "assets" / "derived"
IOS_DIR = ROOT_DIR / "ios" / "AppIcon.appiconset"
ANDROID_DIR = ROOT_DIR / "android" / "res"
STORE_DIR = ROOT_DIR / "store"

# ---------------------------------------------------------------------------
# Renderer abstraction
# ---------------------------------------------------------------------------

def render_svg_cairosvg(svg_path: Path, png_path: Path, width: int, height: int,
                        background_color: str | None = None) -> None:
    import cairosvg  # type: ignore[import-untyped]

    kwargs: dict = dict(
        url=str(svg_path),
        write_to=str(png_path),
        output_width=width,
        output_height=height,
    )
    if background_color:
        kwargs["background_color"] = background_color
    cairosvg.svg2png(**kwargs)


def render_svg_rsvg(svg_path: Path, png_path: Path, width: int, height: int,
                    background_color: str | None = None) -> None:
    cmd = ["rsvg-convert", "-w", str(width), "-h", str(height)]
    if background_color:
        cmd += ["--background-color", background_color]
    cmd += [str(svg_path), "-o", str(png_path)]
    subprocess.check_call(cmd)


RENDERERS = {
    "cairosvg": render_svg_cairosvg,
    "rsvg": render_svg_rsvg,
}

# ---------------------------------------------------------------------------
# Derived SVG content
# ---------------------------------------------------------------------------

BG_SVG_CONTENT = """\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%"  stop-color="#0E2036"/>
      <stop offset="100%" stop-color="#081424"/>
    </linearGradient>
  </defs>
  <rect width="1024" height="1024" fill="url(#bg)"/>
  <g stroke="#1A3556" stroke-width="1" opacity="0.45">
    <path d="M0 256 H1024 M0 512 H1024 M0 768 H1024"/>
    <path d="M256 0 V1024 M512 0 V1024 M768 0 V1024"/>
  </g>
</svg>
"""

# Foreground layer — all foreground elements wrapped in a transform that
# scales them into the Android adaptive-icon safe zone (center 66/108 dp).
#
# Foreground bounding box: x=91..872 (781 px), y=347..724 (377 px)
# Content centre: (481.5, 535.5)
# Safe-zone width in a 1024 px canvas: 1024 * 66/108 ≈ 626 px
# Required scale: 626 / 781 ≈ 0.80
# Transform: translate(512,512) scale(0.80) translate(-481.5,-535.5)
FG_SVG_CONTENT = """\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">
  <defs>
    <linearGradient id="accent" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%"  stop-color="#22D3EE"/>
      <stop offset="100%" stop-color="#38BDF8"/>
    </linearGradient>
  </defs>
  <g transform="translate(512,512) scale(0.80) translate(-481.5,-535.5)">
    <path d="M104 360 L184 440 L104 520"
          fill="none" stroke="url(#accent)" stroke-width="26"
          stroke-linecap="round" stroke-linejoin="round" opacity="0.85"/>
    <g fill="#E6F6FB">
      <g transform="translate(152.00 560.00) scale(0.3 -0.3)"><path d="M77 -180V550H199V449Q214 501 253.0 530.5Q292 560 350 560Q403 560 443.5 534.0Q484 508 506.5 460.5Q529 413 529 350V201Q529 106 480.0 48.0Q431 -10 350 -10Q292 -10 252.5 20.0Q213 50 198 104L202 -26V-180ZM303 98Q351 98 377.5 124.0Q404 150 404 204V346Q404 400 377.5 426.0Q351 452 303 452Q255 452 228.5 423.0Q202 394 202 341V209Q202 156 228.5 127.0Q255 98 303 98Z"/></g>
      <g transform="translate(332.00 560.00) scale(0.3 -0.3)"><path d="M309 -10Q238 -10 185.5 16.5Q133 43 104.0 91.5Q75 140 75 206V344Q75 410 104.0 458.5Q133 507 185.5 533.5Q238 560 309 560Q412 560 474.5 506.5Q537 453 540 361H417Q414 404 384.5 427.5Q355 451 309 451Q258 451 229.0 423.5Q200 396 200 345V206Q200 155 229.0 127.0Q258 99 309 99Q356 99 385.0 122.5Q414 146 417 189H540Q537 97 474.5 43.5Q412 -10 309 -10Z"/></g>
      <g transform="translate(512.00 560.00) scale(0.3 -0.3)"><path d="M239 -10Q155 -10 106.5 37.5Q58 85 58 162Q58 242 113.0 289.5Q168 337 264 337H398V376Q398 459 301 459Q257 459 231.0 442.0Q205 425 202 394H82Q86 468 144.5 514.0Q203 560 302 560Q407 560 465.0 511.0Q523 462 523 373V0H401V103Q394 50 351.0 20.0Q308 -10 239 -10ZM279 92Q334 92 366.0 119.0Q398 146 398 191V256H270Q229 256 205.0 233.0Q181 210 181 174Q181 137 206.5 114.5Q232 92 279 92Z"/></g>
      <g transform="translate(692.00 560.00) scale(0.3 -0.3)"><path d="M77 -180V550H199V449Q214 501 253.0 530.5Q292 560 350 560Q403 560 443.5 534.0Q484 508 506.5 460.5Q529 413 529 350V201Q529 106 480.0 48.0Q431 -10 350 -10Q292 -10 252.5 20.0Q213 50 198 104L202 -26V-180ZM303 98Q351 98 377.5 124.0Q404 150 404 204V346Q404 400 377.5 426.0Q351 452 303 452Q255 452 228.5 423.0Q202 394 202 341V209Q202 156 228.5 127.0Q255 98 303 98Z"/></g>
    </g>
    <rect x="152" y="712" width="720" height="12" rx="6" fill="#1E3A5F"/>
    <rect x="152" y="712" width="260" height="12" rx="6" fill="url(#accent)"/>
  </g>
</svg>
"""

ADAPTIVE_ICON_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@mipmap/ic_launcher_background"/>
    <foreground android:drawable="@mipmap/ic_launcher_foreground"/>
</adaptive-icon>
"""

# ---------------------------------------------------------------------------
# Contents.json for Xcode
# ---------------------------------------------------------------------------

CONTENTS_JSON: dict = {
    "images": [
        {"size": "20x20", "idiom": "iphone", "filename": "icon-20@2x.png", "scale": "2x"},
        {"size": "20x20", "idiom": "iphone", "filename": "icon-20@3x.png", "scale": "3x"},
        {"size": "29x29", "idiom": "iphone", "filename": "icon-29@2x.png", "scale": "2x"},
        {"size": "29x29", "idiom": "iphone", "filename": "icon-29@3x.png", "scale": "3x"},
        {"size": "40x40", "idiom": "iphone", "filename": "icon-40@2x.png", "scale": "2x"},
        {"size": "40x40", "idiom": "iphone", "filename": "icon-40@3x.png", "scale": "3x"},
        {"size": "60x60", "idiom": "iphone", "filename": "icon-60@2x.png", "scale": "2x"},
        {"size": "60x60", "idiom": "iphone", "filename": "icon-60@3x.png", "scale": "3x"},
        {"size": "20x20", "idiom": "ipad", "filename": "icon-20.png", "scale": "1x"},
        {"size": "20x20", "idiom": "ipad", "filename": "icon-20@2x.png", "scale": "2x"},
        {"size": "29x29", "idiom": "ipad", "filename": "icon-29.png", "scale": "1x"},
        {"size": "29x29", "idiom": "ipad", "filename": "icon-29@2x.png", "scale": "2x"},
        {"size": "40x40", "idiom": "ipad", "filename": "icon-40.png", "scale": "1x"},
        {"size": "40x40", "idiom": "ipad", "filename": "icon-40@2x.png", "scale": "2x"},
        {"size": "76x76", "idiom": "ipad", "filename": "icon-76.png", "scale": "1x"},
        {"size": "76x76", "idiom": "ipad", "filename": "icon-76@2x.png", "scale": "2x"},
        {"size": "83.5x83.5", "idiom": "ipad", "filename": "icon-83.5@2x.png", "scale": "2x"},
        {"size": "1024x1024", "idiom": "ios-marketing", "filename": "icon-1024.png", "scale": "1x"},
    ],
    "info": {"version": 1, "author": "build-icons.sh"},
}

# ---------------------------------------------------------------------------
# Icon size definitions
# ---------------------------------------------------------------------------

IOS_ICONS: list[tuple[int, str]] = [
    (20, "icon-20.png"),
    (40, "icon-20@2x.png"),
    (60, "icon-20@3x.png"),
    (29, "icon-29.png"),
    (58, "icon-29@2x.png"),
    (87, "icon-29@3x.png"),
    (40, "icon-40.png"),
    (80, "icon-40@2x.png"),
    (120, "icon-40@3x.png"),
    (120, "icon-60@2x.png"),
    (180, "icon-60@3x.png"),
    (76, "icon-76.png"),
    (152, "icon-76@2x.png"),
    (167, "icon-83.5@2x.png"),
    (1024, "icon-1024.png"),
]

# Android density → (adaptive_size, legacy_size)
ANDROID_DENSITIES: dict[str, tuple[int, int]] = {
    "mdpi": (108, 48),
    "hdpi": (162, 72),
    "xhdpi": (216, 96),
    "xxhdpi": (324, 144),
    "xxxhdpi": (432, 192),
}

# ---------------------------------------------------------------------------
# PNG verification helper
# ---------------------------------------------------------------------------

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def verify_png(path: Path, expected_size: int) -> bool:
    if not path.exists():
        print(f"  FAIL: Missing {path}")
        return False

    data = path.read_bytes()
    if len(data) < 24:
        print(f"  FAIL: Too small {path}")
        return False

    if data[:8] != PNG_MAGIC:
        print(f"  FAIL: Bad PNG magic {path}")
        return False

    # Read IHDR dimensions (bytes 16-23)
    width = struct.unpack(">I", data[16:20])[0]
    height = struct.unpack(">I", data[20:24])[0]

    if width != expected_size or height != expected_size:
        print(f"  FAIL: {path} expected {expected_size}x{expected_size}, got {width}x{height}")
        return False

    print(f"  OK: {path.relative_to(ROOT_DIR)} ({width}x{height}, {len(data)} bytes)")
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Build app icons from master SVG")
    parser.add_argument("--renderer", choices=["cairosvg", "rsvg"], default="cairosvg")
    args = parser.parse_args()

    render = RENDERERS[args.renderer]

    # Verify master SVG
    if not MASTER_SVG.exists():
        print(f"ERROR: Master SVG not found at {MASTER_SVG}", file=sys.stderr)
        sys.exit(1)
    print(f"==> Master SVG: {MASTER_SVG}")

    # Create directories
    for d in [DERIVED_DIR, IOS_DIR, STORE_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    for density in ANDROID_DENSITIES:
        (ANDROID_DIR / f"mipmap-{density}").mkdir(parents=True, exist_ok=True)
    (ANDROID_DIR / "mipmap-anydpi-v26").mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Derived SVGs
    # -----------------------------------------------------------------------
    print("==> Generating derived SVGs...")
    bg_svg = DERIVED_DIR / "pcap-icon-bg.svg"
    fg_svg = DERIVED_DIR / "pcap-icon-fg.svg"
    bg_svg.write_text(BG_SVG_CONTENT)
    fg_svg.write_text(FG_SVG_CONTENT)
    print("  Created: pcap-icon-bg.svg, pcap-icon-fg.svg")

    # -----------------------------------------------------------------------
    # iOS icons
    # -----------------------------------------------------------------------
    print("==> Generating iOS icons...")
    for size, filename in IOS_ICONS:
        out = IOS_DIR / filename
        print(f"  {filename} ({size}x{size})")
        render(MASTER_SVG, out, size, size, background_color="white")

    # Contents.json
    print("==> Generating Contents.json...")
    (IOS_DIR / "Contents.json").write_text(
        json.dumps(CONTENTS_JSON, indent=2, ensure_ascii=False) + "\n"
    )

    # -----------------------------------------------------------------------
    # Android icons
    # -----------------------------------------------------------------------
    print("==> Generating Android icons...")
    for density, (adaptive_sz, legacy_sz) in ANDROID_DENSITIES.items():
        mipmap = ANDROID_DIR / f"mipmap-{density}"

        # Background
        print(f"  mipmap-{density}/ic_launcher_background.png ({adaptive_sz}x{adaptive_sz})")
        render(bg_svg, mipmap / "ic_launcher_background.png", adaptive_sz, adaptive_sz)

        # Foreground
        print(f"  mipmap-{density}/ic_launcher_foreground.png ({adaptive_sz}x{adaptive_sz})")
        render(fg_svg, mipmap / "ic_launcher_foreground.png", adaptive_sz, adaptive_sz)

        # Legacy
        print(f"  mipmap-{density}/ic_launcher.png ({legacy_sz}x{legacy_sz})")
        render(MASTER_SVG, mipmap / "ic_launcher.png", legacy_sz, legacy_sz)

    # Adaptive icon XML
    print("==> Generating adaptive icon XML...")
    (ANDROID_DIR / "mipmap-anydpi-v26" / "ic_launcher.xml").write_text(ADAPTIVE_ICON_XML)

    # -----------------------------------------------------------------------
    # Store assets
    # -----------------------------------------------------------------------
    print("==> Generating store assets...")
    render(MASTER_SVG, STORE_DIR / "ios-1024.png", 1024, 1024, background_color="white")
    print("  store/ios-1024.png (1024x1024)")
    render(MASTER_SVG, STORE_DIR / "android-512.png", 512, 512)
    print("  store/android-512.png (512x512)")

    # -----------------------------------------------------------------------
    # Verification
    # -----------------------------------------------------------------------
    print()
    print("==> Verifying generated files...")
    errors = 0

    print("--- iOS ---")
    for size, filename in IOS_ICONS:
        if not verify_png(IOS_DIR / filename, size):
            errors += 1

    print("--- Android ---")
    for density, (adaptive_sz, legacy_sz) in ANDROID_DENSITIES.items():
        mipmap = ANDROID_DIR / f"mipmap-{density}"
        if not verify_png(mipmap / "ic_launcher_background.png", adaptive_sz):
            errors += 1
        if not verify_png(mipmap / "ic_launcher_foreground.png", adaptive_sz):
            errors += 1
        if not verify_png(mipmap / "ic_launcher.png", legacy_sz):
            errors += 1

    print("--- Store ---")
    if not verify_png(STORE_DIR / "ios-1024.png", 1024):
        errors += 1
    if not verify_png(STORE_DIR / "android-512.png", 512):
        errors += 1

    print("--- Meta files ---")
    contents_json_path = IOS_DIR / "Contents.json"
    if contents_json_path.exists():
        try:
            json.loads(contents_json_path.read_text())
            print("  OK: Contents.json (valid JSON)")
        except json.JSONDecodeError:
            print("  FAIL: Contents.json is not valid JSON")
            errors += 1
    else:
        print("  FAIL: Contents.json missing")
        errors += 1

    xml_path = ANDROID_DIR / "mipmap-anydpi-v26" / "ic_launcher.xml"
    if xml_path.exists():
        print("  OK: ic_launcher.xml")
    else:
        print("  FAIL: ic_launcher.xml missing")
        errors += 1

    print()
    if errors > 0:
        print(f"==> DONE with {errors} error(s)!")
        sys.exit(1)
    else:
        print("==> DONE. All files generated and verified successfully.")


if __name__ == "__main__":
    main()
