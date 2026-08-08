"""Generate the extension's icon set.

Chrome requires a 128x128 icon to publish, and uses 16/32/48 for the toolbar,
the management page, and search results. Rendering them from one vector
description here keeps the sizes consistent and means the repo does not carry
four binary blobs nobody can edit.

    python deploy/make_extension_icons.py

Re-run after changing the shape or colours; commit the PNGs it writes.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parents[1] / "src" / "apps" / "extension" / "icons"
SIZES = (16, 32, 48, 128)

# Rendered at 8x and downsampled, which is cheaper than doing our own
# anti-aliasing and looks better at 16px than any hinting we would write.
SUPERSAMPLE = 8

BG = (31, 111, 235)  # the same blue as the injected scan button
SHIELD = (255, 255, 255)
CHECK = (31, 111, 235)


def _shield(size: int) -> list[tuple[float, float]]:
    """A shield outline on a `size` x `size` canvas."""
    w = size
    # Proportions chosen so the glyph still reads as a shield at 16px.
    left, right = w * 0.22, w * 0.78
    top, shoulder = w * 0.16, w * 0.54
    bottom = w * 0.86
    mid = w * 0.5
    return [
        (mid, top),
        (right, top + w * 0.08),
        (right, shoulder),
        (mid, bottom),
        (left, shoulder),
        (left, top + w * 0.08),
    ]


def _check(size: int) -> list[tuple[float, float]]:
    w = size
    return [(w * 0.38, w * 0.50), (w * 0.46, w * 0.59), (w * 0.63, w * 0.39)]


def render(size: int) -> Image.Image:
    big = size * SUPERSAMPLE
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Rounded square background: a bare glyph disappears on dark toolbars.
    draw.rounded_rectangle(
        [(0, 0), (big - 1, big - 1)], radius=big * 0.22, fill=BG
    )
    draw.polygon(_shield(big), fill=SHIELD)
    draw.line(
        _check(big),
        fill=CHECK,
        width=max(1, int(big * 0.07)),
        joint="curve",
    )
    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for size in SIZES:
        path = OUT / f"icon{size}.png"
        render(size).save(path, "PNG", optimize=True)
        print(f"wrote {path.relative_to(OUT.parents[4])} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
