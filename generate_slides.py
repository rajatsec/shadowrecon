#!/usr/bin/env python3
"""
ShadowRecon 2.0 Instagram Slide Generator
Generates 9 portrait (1080x1920) PNG slides in red grunge horror cyberpunk style.
Output: output/slides/slide_01.png ... slide_09.png
"""

import math
import os
import random

from PIL import Image, ImageDraw, ImageFont

# ── Canvas ─────────────────────────────────────────────────────────────────
WIDTH, HEIGHT = 1080, 1920
OUT_DIR = os.path.join(os.path.dirname(__file__), "output", "slides")

# ── Colors ──────────────────────────────────────────────────────────────────
BLACK  = (0,   0,   0,   255)
WHITE  = (255, 255, 255, 255)
RED    = (220,  20,  20, 255)
LIME   = (170, 255,   0, 255)
PURPLE = (200,  68, 255, 255)
GRAY   = (180, 180, 180, 255)
DIM    = (140, 140, 140, 200)

# ── Font paths ───────────────────────────────────────────────────────────────
_LIB = "/usr/share/fonts/truetype/liberation/"
F_BOLD_ITALIC = _LIB + "LiberationSans-BoldItalic.ttf"
F_BOLD        = _LIB + "LiberationSans-Bold.ttf"
F_REGULAR     = _LIB + "LiberationSans-Regular.ttf"


def font(path: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size)


# ── Grunge edge effect ───────────────────────────────────────────────────────

def _splat(draw: ImageDraw.ImageDraw, rng: random.Random,
           cx: int, cy: int, size: int, alpha: int) -> None:
    r = rng.randint(140, 220)
    c = (r, 0, 0, alpha)
    draw.ellipse([cx - size, cy - size, cx + size, cy + size], fill=c)


def add_grunge_edges(img: Image.Image) -> None:
    rng = random.Random(7)
    draw = ImageDraw.Draw(img, "RGBA")
    margin = 220

    # Large blobs
    for _ in range(420):
        edge = rng.choice(("top", "bottom", "left", "right"))
        if edge == "top":
            cx, cy = rng.randint(-20, WIDTH + 20), rng.randint(-30, margin)
        elif edge == "bottom":
            cx, cy = rng.randint(-20, WIDTH + 20), rng.randint(HEIGHT - margin, HEIGHT + 30)
        elif edge == "left":
            cx, cy = rng.randint(-30, margin), rng.randint(-20, HEIGHT + 20)
        else:
            cx, cy = rng.randint(WIDTH - margin, WIDTH + 30), rng.randint(-20, HEIGHT + 20)

        size = rng.randint(8, 70)
        alpha = rng.randint(160, 255)
        _splat(draw, rng, cx, cy, size, alpha)

        # Occasional drip
        if rng.random() < 0.32:
            drip_len = rng.randint(30, 140)
            dw = rng.randint(4, 14)
            r = rng.randint(140, 200)
            dc = (r, 0, 0, rng.randint(140, 220))
            if edge == "top":
                draw.rectangle([cx - dw // 2, cy, cx + dw // 2, cy + drip_len], fill=dc)
            elif edge == "bottom":
                draw.rectangle([cx - dw // 2, cy - drip_len, cx + dw // 2, cy], fill=dc)
            elif edge == "left":
                draw.rectangle([cx, cy - dw // 2, cx + drip_len, cy + dw // 2], fill=dc)
            else:
                draw.rectangle([cx - drip_len, cy - dw // 2, cx, cy + dw // 2], fill=dc)

    # Fine specks
    for _ in range(700):
        edge = rng.choice(("top", "bottom", "left", "right", "corner"))
        if edge == "top":
            cx, cy = rng.randint(0, WIDTH), rng.randint(0, 160)
        elif edge == "bottom":
            cx, cy = rng.randint(0, WIDTH), rng.randint(HEIGHT - 160, HEIGHT)
        elif edge == "left":
            cx, cy = rng.randint(0, 160), rng.randint(0, HEIGHT)
        elif edge == "right":
            cx, cy = rng.randint(WIDTH - 160, WIDTH), rng.randint(0, HEIGHT)
        else:
            c = rng.randint(0, 3)
            corners = [(0, 200, 0, 200), (WIDTH - 200, WIDTH, 0, 200),
                       (0, 200, HEIGHT - 200, HEIGHT), (WIDTH - 200, WIDTH, HEIGHT - 200, HEIGHT)]
            x0, x1, y0, y1 = corners[c]
            cx, cy = rng.randint(x0, x1), rng.randint(y0, y1)

        size = rng.randint(2, 22)
        _splat(draw, rng, cx, cy, size, rng.randint(100, 200))


# ── Text helpers ─────────────────────────────────────────────────────────────

def text_w(draw: ImageDraw.ImageDraw, text: str, fnt: ImageFont.FreeTypeFont) -> int:
    bb = draw.textbbox((0, 0), text, font=fnt)
    return bb[2] - bb[0]


def centered_x(draw: ImageDraw.ImageDraw, text: str, fnt: ImageFont.FreeTypeFont) -> int:
    return (WIDTH - text_w(draw, text, fnt)) // 2


def wrap(draw: ImageDraw.ImageDraw, text: str, fnt: ImageFont.FreeTypeFont, max_w: int) -> list[str]:
    words = text.split()
    lines, cur = [], []
    for word in words:
        test = " ".join(cur + [word])
        if text_w(draw, test, fnt) <= max_w:
            cur.append(word)
        else:
            if cur:
                lines.append(" ".join(cur))
            cur = [word]
    if cur:
        lines.append(" ".join(cur))
    return lines


def watermark(draw: ImageDraw.ImageDraw) -> None:
    fnt = font(F_REGULAR, 38)
    txt = "@secure_with_rajat"
    x = centered_x(draw, txt, fnt)
    draw.text((x, HEIGHT - 75), txt, fill=(190, 190, 190, 170), font=fnt)


# ── Slide factories ───────────────────────────────────────────────────────────

def new_canvas() -> Image.Image:
    img = Image.new("RGBA", (WIDTH, HEIGHT), BLACK)
    add_grunge_edges(img)
    return img


def slide_cover() -> Image.Image:
    img = new_canvas()
    draw = ImageDraw.Draw(img)

    f_desc = font(F_REGULAR, 38)

    # Auto-fit "SHADOWRECON" to width with padding
    for size in range(145, 60, -4):
        f_main = font(F_BOLD_ITALIC, size)
        if text_w(draw, "SHADOWRECON", f_main) <= WIDTH - 80:
            break

    # Auto-fit "2.0"
    for size in range(220, 100, -4):
        f_num = font(F_BOLD_ITALIC, size)
        if text_w(draw, "2.0", f_num) <= WIDTH - 120:
            break

    f_sub = font(F_BOLD, 54)

    # SHADOWRECON — lime
    draw.text((centered_x(draw, "SHADOWRECON", f_main), 260),
              "SHADOWRECON", fill=LIME, font=f_main)

    # 2.0 — white
    title_h = draw.textbbox((0, 0), "SHADOWRECON", font=f_main)[3]
    draw.text((centered_x(draw, "2.0", f_num), 260 + title_h + 10),
              "2.0", fill=WHITE, font=f_num)

    # Subtitle lines — purple
    num_h = draw.textbbox((0, 0), "2.0", font=f_num)[3]
    y = 260 + title_h + num_h + 40
    for s in ["REBUILDING RECON", "FROM SCRATCH"]:
        draw.text((centered_x(draw, s, f_sub), y), s, fill=PURPLE, font=f_sub)
        y += 80

    # Descriptor
    desc = "Async  •  5 Providers  •  Takeover Detection  •  Persistence"
    draw.text((centered_x(draw, desc, f_desc), y + 60), desc, fill=GRAY, font=f_desc)

    watermark(draw)
    return img


def slide_hook() -> Image.Image:
    img = new_canvas()
    draw = ImageDraw.Draw(img)

    # Auto-fit hook font to slide width with safe padding
    title = "MOST RECON TOOLS ARE JUST SCRIPTS IN DISGUISE"
    for size in range(108, 60, -4):
        f_hook = font(F_BOLD_ITALIC, size)
        lines = wrap(draw, title, f_hook, WIDTH - 140)
        if len(lines) <= 5:
            break

    f_sub  = font(F_REGULAR, 46)
    f_cta  = font(F_BOLD,    42)

    line_h = int(size * 1.15)
    total_h = len(lines) * line_h
    y = HEIGHT // 2 - total_h // 2 - 140

    for line in lines:
        draw.text((centered_x(draw, line, f_hook), y), line, fill=RED, font=f_hook)
        y += line_h

    sub = "I rebuilt mine. Here's everything that changed."
    draw.text((centered_x(draw, sub, f_sub), y + 55), sub, fill=GRAY, font=f_sub)

    cta = "Save this & Share it  ↓"
    draw.text((centered_x(draw, cta, f_cta), HEIGHT - 200), cta, fill=RED, font=f_cta)

    watermark(draw)
    return img


def slide_content(num: int, title: str, bullets: list[str]) -> Image.Image:
    img = new_canvas()
    draw = ImageDraw.Draw(img)

    f_num   = font(F_BOLD_ITALIC, 120)
    f_title = font(F_BOLD_ITALIC,  78)
    f_body  = font(F_REGULAR,      48)

    # Slide number in red — large, top-left
    num_txt = f"{num}/"
    draw.text((70, 100), num_txt, fill=RED, font=f_num)
    num_h = draw.textbbox((0, 0), num_txt, font=f_num)[3]

    # Title below the number, full width
    title_lines = wrap(draw, title, f_title, WIDTH - 140)
    y = 100 + num_h + 10
    for line in title_lines:
        draw.text((70, y), line, fill=WHITE, font=f_title)
        y += 92

    # Red divider
    y += 18
    draw.rectangle([70, y, WIDTH - 70, y + 3], fill=(190, 0, 0, 220))
    y += 38

    # Bullets
    for bullet in bullets:
        lines = wrap(draw, f"• {bullet}", f_body, WIDTH - 150)
        for i, line in enumerate(lines):
            draw.text((70 if i == 0 else 100, y), line, fill=WHITE, font=f_body)
            y += 62
        y += 16

    watermark(draw)
    return img


def slide_cta() -> Image.Image:
    img = new_canvas()
    draw = ImageDraw.Draw(img)

    f_follow  = font(F_BOLD_ITALIC, 138)
    f_handle  = font(F_BOLD_ITALIC,  86)
    f_body    = font(F_REGULAR,      50)

    draw.text((centered_x(draw, "FOLLOW", f_follow), 260),
              "FOLLOW", fill=RED, font=f_follow)

    handle = "@secure_with_rajat"
    draw.text((centered_x(draw, handle, f_handle), 430),
              handle, fill=LIME, font=f_handle)

    # Divider
    draw.rectangle([140, 585, WIDTH - 140, 588], fill=(180, 0, 0, 200))

    ctas = [
        ("Like + Save if this helped", WHITE),
        ("Star the repo on GitHub ⭐", WHITE),
        ("github.com/rajatsec/shadowrecon", GRAY),
    ]
    y = 640
    for txt, col in ctas:
        draw.text((centered_x(draw, txt, f_body), y), txt, fill=col, font=f_body)
        y += 85

    # Auto-fit closing text
    closing = "RECON LIKE A PRO."
    for size in range(105, 60, -4):
        f_closing = font(F_BOLD_ITALIC, size)
        if text_w(draw, closing, f_closing) <= WIDTH - 100:
            break
    draw.text((centered_x(draw, closing, f_closing), 1080),
              closing, fill=RED, font=f_closing)

    watermark(draw)
    return img


# ── Slide data ───────────────────────────────────────────────────────────────

SLIDES = [
    ("cover",   None, None, None),
    ("hook",    None, None, None),
    ("content", 1, "WHAT WAS WRONG (v1.1)", [
        "Single-threaded — one port scanned at a time",
        "Only 2 subdomain sources (crt.sh + HackerTarget)",
        "Silent failures — bare except: pass everywhere",
        "No output formats — just terminal print",
        "No scan history or persistence",
    ]),
    ("content", 2, "THE ASYNC CORE (v2.0)", [
        "Full asyncio rewrite — zero blocking calls",
        "aiohttp replaces requests library",
        "asyncio.gather() runs DNS + subs + HTTP in parallel",
        "Semaphore-controlled port scanner (100 concurrent)",
        "10x faster on real targets",
    ]),
    ("content", 3, "PROVIDER SYSTEM — SUBFINDER INSPIRED", [
        "Abstract BaseProvider plugin class",
        "5 providers: crt.sh, HackerTarget, Certspotter, AlienVault OTX, urlscan.io",
        "Per-provider subdomain count shown in results",
        "API keys loaded from config.yaml",
        "Add new providers in under 20 lines",
    ]),
    ("content", 4, "SUBDOMAIN TAKEOVER DETECTION", [
        "25 service fingerprints (S3, GitHub Pages, Heroku, Fastly, Azure...)",
        "Resolves CNAME chain for each subdomain",
        "Fetches HTTP response and matches fingerprint string",
        "Flags vulnerable subdomains with service name",
        "Enable with --takeover flag",
    ]),
    ("content", 5, "DATA PIPELINE + PERSISTENCE", [
        "collect → normalize → deduplicate → enrich → store",
        "aiosqlite stores every scan to shadowrecon.db",
        "shadowrecon history -d domain.com shows past scans",
        "compare_scans() diffs two scans for monitoring",
        "JSON + TXT + HTML reports auto-generated",
    ]),
    ("content", 6, "NEW ARCHITECTURE", [
        "providers/ — 5 async subdomain plugins",
        "modules/ — dns, ports, http, fingerprint, takeover",
        "core/ — engine.py orchestrates all scan phases",
        "db/ — aiosqlite persistence layer",
        "utils/ — rate limiter, retry, output, logger",
    ]),
    ("cta",     None, None, None),
]


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)

    for i, (stype, num, title, bullets) in enumerate(SLIDES, 1):
        if stype == "cover":
            img = slide_cover()
        elif stype == "hook":
            img = slide_hook()
        elif stype == "content":
            img = slide_content(num, title, bullets)
        else:
            img = slide_cta()

        out = os.path.join(OUT_DIR, f"slide_{i:02d}.png")
        img.convert("RGB").save(out, "PNG")
        print(f"  ✓ slide_{i:02d}.png  [{stype}]")

    print(f"\nDone — {len(SLIDES)} slides saved to {OUT_DIR}")


if __name__ == "__main__":
    main()
