"""Local image metadata extraction and perceptual comparison.

Local files are never uploaded by this module. Web reverse-image providers are
presented as analyst-operated workflows; the user decides whether to upload.
"""
from __future__ import annotations

import hashlib
from pathlib import Path


def inspect_image(path: str | Path) -> dict:
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(source)
    if source.stat().st_size > 100 * 1024 * 1024:
        raise ValueError("Image is larger than the 100 MiB analysis limit.")
    try:
        from PIL import Image, ExifTags
    except ImportError as exc:
        raise RuntimeError("Image analysis requires Pillow. Install Pillow and restart Smart Intel.") from exc
    with Image.open(source) as image:
        image.verify()
    with Image.open(source) as image:
        exif = image.getexif()
        reverse_tags = {v: k for k, v in ExifTags.TAGS.items()}
        selected = {}
        for tag in ("Make", "Model", "DateTime", "DateTimeOriginal", "Software", "Artist",
                    "ImageDescription", "Orientation", "FocalLength", "ExposureTime", "ISOSpeedRatings"):
            key = reverse_tags.get(tag)
            if key is not None and key in exif:
                selected[tag] = str(exif.get(key))[:500]
        gps = {}
        try:
            gps_raw = exif.get_ifd(ExifTags.IFD.GPSInfo)
            gps_names = {v: k for k, v in ExifTags.GPSTAGS.items()}
            for key, value in gps_raw.items():
                name = gps_names.get(key, str(key))
                gps[name] = str(value)
        except Exception:
            pass
        rgb = image.convert("L").resize((9, 8))
        pixels = list(rgb.getdata())
        bits = 0
        for y in range(8):
            for x in range(8):
                bits = (bits << 1) | int(pixels[y * 9 + x] > pixels[y * 9 + x + 1])
        phash = f"{bits:016x}"
        width, height = image.size
        fmt = image.format
    data = source.read_bytes()
    return {
        "filename": source.name, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "width": width, "height": height, "format": fmt, "exif": selected, "gps": gps,
        "dhash64": phash,
        "privacy_note": "GPS metadata may reveal a precise location. Review and redact before sharing.",
        "reverse_search_options": [
            {"provider": "Google Lens", "url": "https://lens.google.com/"},
            {"provider": "Bing Visual Search", "url": "https://www.bing.com/visualsearch"},
            {"provider": "TinEye", "url": "https://tineye.com/"},
        ],
    }


def hamming_distance(left: str, right: str) -> int:
    if len(left) != 16 or len(right) != 16:
        raise ValueError("Image hashes must be 64-bit hexadecimal values.")
    return (int(left, 16) ^ int(right, 16)).bit_count()


def compare_images(left: str | Path, right: str | Path) -> dict:
    a = inspect_image(left)
    b = inspect_image(right)
    distance = hamming_distance(a["dhash64"], b["dhash64"])
    return {"left": a["filename"], "right": b["filename"], "hamming_distance": distance,
            "similarity_percent": round((64 - distance) / 64 * 100, 1),
            "interpretation": "Perceptual resemblance candidate only; not proof of same image, origin or subject."}
