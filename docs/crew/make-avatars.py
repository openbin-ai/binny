import sys
import numpy as np
from PIL import Image, ImageDraw, ImageFilter

SRC, DST = "docs/crew", "internal/serve/web/crew"
SIZE = 128

def cut_checkerboard(im):
    """The checkerboard is baked into an RGB image: near-white and light-grey
    squares. Flood from the border through those, make them transparent, then
    put back the white sticker outline the flood ate."""
    rgb = np.asarray(im.convert("RGB")).astype(np.int16)
    light = (rgb.min(axis=2) >= 222) & ((rgb.max(axis=2) - rgb.min(axis=2)) <= 30)
    mask = Image.fromarray((light * 255).astype(np.uint8), "L").copy()
    w, h = mask.size
    mask.load(); px = mask.load()
    seeds = [(x, y) for x in range(0, w, 16) for y in (0, h - 1)] + [(x, y) for y in range(0, h, 16) for x in (0, w - 1)]
    for s in seeds:
        if px[s] == 255:
            ImageDraw.floodfill(mask, s, 128)
    bg = np.asarray(mask) == 128
    alpha = Image.fromarray((~bg * 255).astype(np.uint8), "L")
    # soften the cut edge a touch, then rebuild the outline
    # drop speckle left by a soft glow: open the mask, keep what survives
    opened = alpha.filter(ImageFilter.MinFilter(13)).filter(ImageFilter.MaxFilter(15))
    alpha = Image.fromarray(np.minimum(np.asarray(alpha), np.asarray(opened)), "L").copy()
    alpha = alpha.filter(ImageFilter.MinFilter(3))
    fig = im.convert("RGBA")
    fig.putalpha(alpha)
    ring = alpha.filter(ImageFilter.MaxFilter(27)).filter(ImageFilter.GaussianBlur(1.2))
    out = Image.new("RGBA", fig.size, (255, 255, 255, 0))
    white = Image.new("RGBA", fig.size, (255, 255, 255, 255))
    out.paste(white, (0, 0), ring)
    out.alpha_composite(fig)
    return out

def fit(im):
    """Trim to the figure, pad to a square, downscale."""
    bbox = im.getchannel("A").point(lambda a: 255 if a > 8 else 0).getbbox()
    im = im.crop(bbox)
    side = max(im.size)
    pad = int(side * 0.04)
    sq = Image.new("RGBA", (side + 2 * pad, side + 2 * pad), (0, 0, 0, 0))
    sq.paste(im, ((sq.width - im.width) // 2, (sq.height - im.height) // 2))
    return sq.resize((SIZE, SIZE), Image.LANCZOS)

for name in ["dex", "hex", "parity", "parity-dark", "siggy", "trace", "twine"]:
    im = Image.open(f"{SRC}/{name}.png")
    if im.mode != "RGBA":
        im = cut_checkerboard(im)
    out = fit(im)
    out.save(f"{DST}/{name}.png", optimize=True)
    print(name, out.size)
