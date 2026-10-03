"""Generate docs/images/05-attachments.png (house style, genuine output).

Runs the real CLI against docs/examples/invoice-scam-attachments.eml,
captures stdout, and renders it as a terminal screenshot: 760px wide,
#1e1e1e background, monospace. Kept out of the test suite; run by hand
when the example or rendering changes.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parent.parent
WIDTH = 760
BG = (30, 30, 30)
FG = (220, 220, 220)
ACCENT = (120, 200, 255)
MARGIN = 18
LINE_H = 20


def _font(size: int = 15):
    for candidate in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    ):
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size)
    return ImageFont.load_default()


def main() -> None:
    env = {"PYTHONPATH": str(REPO / "src"), "PATH": "/usr/bin:/bin"}
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "phishscope.cli.main",
            "attachments",
            str(REPO / "docs/examples/invoice-scam-attachments.eml"),
        ],
        capture_output=True,
        text=True,
        cwd=REPO,
        env=env,
        check=False,
    )
    text = (proc.stdout or "").strip().splitlines()
    # Drop the trailing observations block to keep the shot focused.
    cut = next(
        (
            i
            for i, line in enumerate(text)
            if line.startswith("Attachment observations")
        ),
        len(text),
    )
    text = text[:cut]
    text.insert(
        0,
        "$ phishscope attachments docs/examples/invoice-scam-attachments.eml",
    )

    font = _font()
    height = MARGIN * 2 + LINE_H * len(text) + 8
    img = Image.new("RGB", (WIDTH, height), BG)
    draw = ImageDraw.Draw(img)
    y = MARGIN
    for i, line in enumerate(text):
        color = ACCENT if i == 0 else FG
        draw.text((MARGIN, y), line[:110], font=font, fill=color)
        y += LINE_H
    out = REPO / "docs/images/05-attachments.png"
    img.save(out)
    print(f"wrote {out} ({WIDTH}x{height})")


if __name__ == "__main__":
    main()
