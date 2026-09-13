#!/usr/bin/env python3
"""Flatten and colour-normalise figures so the print PDF matches the source.

PDF engines used by this skill (WeasyPrint/Cairo, XeLaTeX/xepersian, Chromium
with --disable-gpu) paint PNG alpha onto black. `pdfimages -png` often dumps
Decode-inverted samples and leftover soft-masks. Either way the reader sees a
black rectangle instead of the source figure.

Usage:
    prepare-figures.py figures/            # flatten alpha in place (keeps .orig)
    prepare-figures.py figures/ --check    # report alpha / mostly-black dumps
    prepare-figures.py figures/ --invert-dark
        # negate mostly-black dumps. Only after comparing with a pdftoppm of
        # the source page — a real dark photograph must not be inverted.

Needs Pillow (`pip install pillow`) or ImageMagick.
Exit 1 on --check findings.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".tif", ".tiff"}

# Mean luminance below this (0–255) plus a high near-black fraction is the
# pdfimages-negative signature for a line diagram. Cream-on-black dumps
# (inverted colour figures) sit around mean 70–90, not 20.
DARK_MEAN = 120.0
DARK_BLACK_FRAC = 0.50


def have_pil() -> bool:
    try:
        import PIL.Image  # noqa: F401
        return True
    except ImportError:
        return False


def magick() -> list[str] | None:
    for cmd in (("magick",), ("convert",)):
        if shutil.which(cmd[0]):
            return list(cmd)
    return None


def iter_images(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            out.extend(sorted(
                q for q in p.iterdir()
                if q.is_file() and q.suffix.lower() in IMAGE_EXT
                and not q.name.endswith(".orig")
            ))
        elif p.is_file():
            out.append(p)
        else:
            print(f"prepare-figures: not a file: {p}", file=sys.stderr)
            sys.exit(2)
    return out


def flatten_to_rgb(im, invert: bool):
    from PIL import Image, ImageOps
    if im.mode in ("RGBA", "LA") or (im.mode == "P" and "transparency" in im.info):
        rgba = im.convert("RGBA")
        bg = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        im = Image.alpha_composite(bg, rgba).convert("RGB")
    elif im.mode != "RGB":
        im = im.convert("RGB")
    else:
        im = im.copy()
    if invert:
        im = ImageOps.invert(im)
    return im


def stats_pil(path: Path) -> tuple[float, float, str]:
    from PIL import Image
    im = Image.open(path)
    mode = im.mode
    rgb = flatten_to_rgb(im, invert=False)
    rgb.thumbnail((256, 256))
    data = rgb.tobytes()
    n = max(len(data) // 3, 1)
    mean = sum(data) / (3 * n)
    black = sum(
        1 for i in range(0, len(data), 3)
        if data[i] < 18 and data[i + 1] < 18 and data[i + 2] < 18
    ) / n
    return mean, black, mode


def flatten_pil(src: Path, dest: Path, invert: bool) -> None:
    from PIL import Image
    im = flatten_to_rgb(Image.open(src), invert)
    dest.parent.mkdir(parents=True, exist_ok=True)
    im.save(dest, format="PNG", optimize=True)


def flatten_magick(src: Path, dest: Path, invert: bool, cmd: list[str]) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    args = cmd + [
        str(src),
        "-background", "white",
        "-alpha", "remove",
        "-alpha", "off",
        "-colorspace", "sRGB",
        "-depth", "8",
    ]
    if invert:
        args.append("-negate")
    args.append(str(dest))
    subprocess.check_call(args)


def is_dark(mean: float, black: float) -> bool:
    return mean < DARK_MEAN and black >= DARK_BLACK_FRAC


def backup_once(src: Path) -> None:
    bak = src.with_name(src.name + ".orig")
    if not bak.exists():
        shutil.copy2(src, bak)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="prepare-figures.py")
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--check", action="store_true",
                    help="report problems; do not write")
    ap.add_argument("--invert-dark", action="store_true",
                    help="negate figures that look like pdfimages dumps")
    args = ap.parse_args(argv)

    files = iter_images(args.paths)
    if not files:
        print("prepare-figures: no images", file=sys.stderr)
        return 1

    pil = have_pil()
    mag = magick()
    if not pil and mag is None:
        print("prepare-figures: need Pillow (pip install pillow) or ImageMagick",
              file=sys.stderr)
        return 2

    findings = 0
    for src in files:
        mean = black = None
        mode = "?"
        has_alpha = False
        if pil:
            from PIL import Image
            mean, black, mode = stats_pil(src)
            im = Image.open(src)
            has_alpha = im.mode in ("RGBA", "LA") or (
                im.mode == "P" and "transparency" in im.info)
        dark = mean is not None and is_dark(mean, black or 0)

        if args.check:
            bits = []
            if has_alpha:
                bits.append(f"alpha mode={mode}")
            if dark:
                bits.append(
                    f"mostly black (mean={mean:.0f}, "
                    f"{100 * (black or 0):.0f}% near-black) — likely a "
                    "pdfimages Decode invert; compare with pdftoppm of the "
                    "source page, then --invert-dark"
                )
            if bits:
                findings += 1
                print(f"prepare-figures: {src}: {'; '.join(bits)}",
                      file=sys.stderr)
            else:
                extra = f" mean={mean:.0f}" if mean is not None else ""
                print(f"prepare-figures: ok {src} mode={mode}{extra}")
            continue

        invert = bool(args.invert_dark and dark)
        if not invert and not has_alpha and src.suffix.lower() == ".png" and mode == "RGB":
            print(f"prepare-figures: skip {src} (already RGB)")
            continue

        backup_once(src)
        dest = src.with_suffix(".png")
        # Flatten from the untouched original when present so --invert-dark
        # can be re-run without compounding.
        orig = src.with_name(src.name + ".orig")
        read_from = orig if orig.exists() else src
        if pil:
            flatten_pil(read_from, dest, invert)
        else:
            flatten_magick(read_from, dest, invert, mag)  # type: ignore[arg-type]
        if dest != src and src.suffix.lower() != ".png":
            src.unlink()
        note = " inverted" if invert else ""
        print(f"prepare-figures: wrote {dest}{note}")

    return 1 if args.check and findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
