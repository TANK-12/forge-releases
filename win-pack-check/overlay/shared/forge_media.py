"""Bit-exact opt-in media stage for Forge Pack / Vault (FVLT0001 v1.1).

Implements four strictly bit-exact, reversible media transforms that shrink
already-compressed media where general lossless packers stall, while
verifying every pack-time transform by decoding and comparing SHA-256:

1. `jxl_jpeg`: JPEG -> lossless JPEG XL transcode (`cjxl --lossless_jpeg=1 -e 7`;
   restore with `djxl`).
2. `png_recipe_jxl`: PNG re-deflate recipe + lossless JPEG XL pixels via PAM
   (`FPR1` binary envelope preserving chunk order, CRCs, IDAT split sizes,
   per-row filter bytes, and any trailing bytes after `IEND`). Falls back to
   plain storage when the IDAT deflate stream was not written by classic zlib.
   Recipes always re-deflate with classic zlib (`forge_deflate`: Python's own
   zlib where it is classic, else a fetched classic zlib1.dll on Windows, whose
   Python 3.14 is built with zlib-ng), so a pack restores on every system.
3. `mp4_packet_dedup`: Optional cross-file render-version packet deduplication
   (`FMP1` skeleton + zlib-compressed packet reference table pointing to a base
   file in the same pack).
4. `mkv_font_dedup`: Optional pure-Python EBML Matroska attachment deduplication
   storing each unique embedded `FileData` blob once in `manifest["media_assets"]`
   and splicing exact byte spans back into MKV skeletons on unpack.

Zero third-party Python dependencies (stdlib only; uses optional native C
`fv_png_unfilter` / `fv_png_filter` helpers when `libforge_vault` is loaded).
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import lzma
import os
import shutil
import struct
import subprocess
import tempfile
import zlib
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

import forge_deflate

HERE = Path(__file__).resolve().parent
VAULT_DIR = HERE / "vault"
STANDALONE_DIR = HERE.parent / "apps" / "pack" / "standalone"

JPEG_EXTS = frozenset({".jpg", ".jpeg"})
PNG_EXTS = frozenset({".png"})
MP4_DEDUP_EXTS = frozenset({".mp4", ".mov", ".m4v"})
MKV_FONT_EXTS = frozenset({".mkv"})

PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_RECIPE_MAGIC = b"FPR1"
MP4_DEDUP_MAGIC = b"FMP1"

PNG_CHANNELS: dict[int, int] = {0: 1, 2: 3, 4: 2, 6: 4}
PAM_TUPLTYPES: dict[int, str] = {
    1: "GRAYSCALE",
    2: "GRAYSCALE_ALPHA",
    3: "RGB",
    4: "RGB_ALPHA",
}

MAX_PNG_PIXEL_BYTES = 256 * 1024 * 1024
MAX_PNG_RECIPE_HEADER_BYTES = 64 * 1024 * 1024
MAX_MP4_TABLE_BYTES = 64 * 1024 * 1024
DEFAULT_JXL_EFFORT = 7
SUBPROCESS_TIMEOUT_SEC = 300


def _make_fsize_limiter(max_bytes: int) -> Callable[[], None] | None:
    """Return a POSIX preexec_fn capping output file size via RLIMIT_FSIZE."""
    if os.name != "posix" or max_bytes <= 0:
        return None
    import resource  # noqa: PLC0415

    limit = max(max_bytes, 65536)

    def _limit() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

    return _limit


class MediaStageError(Exception):
    """Raised when decoding a media-stage payload fails or is corrupted."""


class MediaToolMissingError(MediaStageError):
    """Raised when an external decoder required by a media stage (e.g. djxl) is missing."""


# ----------------------------- Tool Discovery -----------------------------


def _forge_tools_module():
    try:
        import forge_tools  # noqa: PLC0415

        return forge_tools
    except Exception:  # noqa: BLE001 — optional helper when run standalone
        return None


def find_tool(
    name: str,
    extra_dirs: tuple[Path, ...] = (),
    *,
    auto_fetch: bool = False,
) -> str | None:
    """Locate an external binary (env override -> bundled folders -> PATH -> forge_tools)."""
    env_override = os.environ.get(f"FORGE_{name.upper()}")
    if env_override:
        p = Path(env_override)
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
        return None
    exe_names = (f"{name}.exe", name) if os.name == "nt" else (name,)
    for folder in (*extra_dirs, STANDALONE_DIR, VAULT_DIR):
        for exe in exe_names:
            cand = folder / exe
            if cand.is_file() and os.access(cand, os.X_OK):
                return str(cand)
    found = shutil.which(name)
    if found:
        return found
    ft = _forge_tools_module()
    if ft is not None:
        cached = ft.find(name)
        if cached:
            return cached
        if auto_fetch and ft.can_fetch(name):
            try:
                return ft.ensure(name)
            except Exception:  # noqa: BLE001 — fall back cleanly when offline
                return None
    return None


def media_tools_status() -> dict[str, Any]:
    """Report availability of optional media-stage tools (`cjxl`, `djxl`, `ffprobe`)."""
    cjxl = find_tool("cjxl")
    djxl = find_tool("djxl")
    ffprobe = find_tool("ffprobe")
    ft = _forge_tools_module()
    can_fetch_jxl = bool(
        ft is not None and ft.can_fetch("cjxl") and ft.can_fetch("djxl")
    )
    jxl_hint = (
        ft.install_hint("cjxl") if ft is not None else "install libjxl (cjxl & djxl)"
    )
    deflate = forge_deflate.status()
    deflate_ok = bool(deflate["ready"] or deflate["can_fetch"])
    return {
        "cjxl": cjxl,
        "djxl": djxl,
        "ffprobe": ffprobe,
        "can_fetch_jxl": can_fetch_jxl,
        "jxl_hint": jxl_hint,
        "jpeg_ready": bool((cjxl and djxl) or can_fetch_jxl),
        "png_ready": bool(((cjxl and djxl) or can_fetch_jxl) and deflate_ok),
        "png_deflate": deflate,
        "decode_jxl_ready": bool(djxl or can_fetch_jxl),
        "video_dedup_ready": bool(ffprobe),
        "mkv_fonts_ready": True,
        "decode_note": (
            "Unpacking JPEG/PNG media-stage files requires djxl (libjxl, BSD). "
            "MP4 packet dedup and MKV font dedup unpack in pure Python with no external tools."
        ),
    }


def normalize_media_options(
    media_stage: bool = False,
    media_options: dict[str, Any] | None = None,
) -> dict[str, bool]:
    """Normalize opt-in media-stage flags into explicit per-transform booleans."""
    if not media_stage:
        return {
            "enabled": False,
            "jpeg": False,
            "png": False,
            "video_dedup": False,
            "mkv_fonts": False,
        }
    opts = media_options or {}
    return {
        "enabled": True,
        "jpeg": bool(opts.get("jpeg", True)),
        "png": bool(opts.get("png", True)),
        "video_dedup": bool(opts.get("video_dedup", True)),
        "mkv_fonts": bool(opts.get("mkv_fonts", True)),
    }


# ----------------------------- Stage 1: JPEG -> JXL -----------------------------


def encode_jpeg_jxl(
    raw_bytes: bytes,
    *,
    effort: int = DEFAULT_JXL_EFFORT,
) -> tuple[bytes, dict[str, Any]] | None:
    """Losslessly transcode a JPEG to JPEG XL, decode-verifying SHA-256 at pack time.

    Returns `(jxl_bytes, media_meta)` only if the result is strictly smaller and
    decodes back to `raw_bytes` byte for byte; otherwise returns `None`.
    """
    if len(raw_bytes) < 128 or raw_bytes[:2] != b"\xff\xd8":
        return None
    cjxl = find_tool("cjxl", auto_fetch=True)
    djxl = find_tool("djxl", auto_fetch=True)
    if not cjxl or not djxl:
        return None

    orig_sha = hashlib.sha256(raw_bytes).digest()
    with tempfile.TemporaryDirectory(prefix="fv_jxl_jpg_") as td:
        d = Path(td)
        in_jpg = d / "in.jpg"
        out_jxl = d / "out.jxl"
        chk_jpg = d / "chk.jpg"
        in_jpg.write_bytes(raw_bytes)

        try:
            enc = subprocess.run(
                [
                    cjxl,
                    "--lossless_jpeg=1",
                    "-e",
                    str(effort),
                    "--quiet",
                    str(in_jpg),
                    str(out_jxl),
                ],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT_SEC,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if enc.returncode != 0 or not out_jxl.is_file():
            return None
        jxl_bytes = out_jxl.read_bytes()
        if not jxl_bytes or len(jxl_bytes) >= len(raw_bytes):
            return None

        try:
            dec = subprocess.run(
                [djxl, "--quiet", str(out_jxl), str(chk_jpg)],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT_SEC,
                preexec_fn=_make_fsize_limiter(len(raw_bytes) + 65536),
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if dec.returncode != 0 or not chk_jpg.is_file():
            return None
        if chk_jpg.stat().st_size != len(raw_bytes):
            return None
        restored = chk_jpg.read_bytes()
        if hashlib.sha256(restored).digest() != orig_sha:
            return None

    return jxl_bytes, {
        "stage": "jxl_jpeg",
        "stored_size": len(jxl_bytes),
        "jxl_sha256": hashlib.sha256(jxl_bytes).hexdigest(),
        "effort": int(effort),
    }


def decode_jpeg_jxl(
    jxl_bytes: bytes,
    meta: dict[str, Any] | None = None,
    *,
    djxl_path: str | None = None,
    max_output_bytes: int | None = None,
) -> bytes:
    """Restore the bit-exact original JPEG bytes from a lossless JPEG XL transcode."""
    if meta is not None:
        exp_size = meta.get("stored_size")
        if isinstance(exp_size, int) and len(jxl_bytes) != exp_size:
            raise MediaStageError(
                f"JXL stored size mismatch (got {len(jxl_bytes)}, expected {exp_size})"
            )
        exp_sha = meta.get("jxl_sha256")
        if (
            isinstance(exp_sha, str)
            and hashlib.sha256(jxl_bytes).hexdigest() != exp_sha
        ):
            raise MediaStageError("damaged JXL payload (jxl_sha256 mismatch)")

    djxl = djxl_path or find_tool("djxl", auto_fetch=True)
    if not djxl:
        raise MediaToolMissingError(
            "Unpacking JPEG XL media-stage files requires 'djxl' (libjxl, BSD) "
            "on PATH or placed beside forge_unpack.py."
        )

    out_cap = (
        max_output_bytes + 65536
        if isinstance(max_output_bytes, int) and max_output_bytes > 0
        else MAX_PNG_PIXEL_BYTES
    )
    with tempfile.TemporaryDirectory(prefix="fv_jxl_dec_") as td:
        d = Path(td)
        in_jxl = d / "in.jxl"
        out_jpg = d / "out.jpg"
        in_jxl.write_bytes(jxl_bytes)
        try:
            dec = subprocess.run(
                [djxl, "--quiet", str(in_jxl), str(out_jpg)],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT_SEC,
                preexec_fn=_make_fsize_limiter(out_cap),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise MediaStageError(
                f"djxl failed to decode JPEG XL stream: {exc}"
            ) from exc
        if dec.returncode != 0 or not out_jpg.is_file():
            detail = (dec.stderr or dec.stdout or "unknown error").strip()
            raise MediaStageError(f"djxl failed to decode JPEG XL stream: {detail}")
        out_sz = out_jpg.stat().st_size
        if out_sz == 0 or out_sz > out_cap:
            raise MediaStageError(f"djxl output size out of bounds: {out_sz}")
        return out_jpg.read_bytes()


# ----------------------------- Stage 2: PNG Recipe + JXL -----------------------------


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def png_unfilter(
    filtered: bytes,
    height: int,
    stride: int,
    bpp: int,
    *,
    native_lib: Any = None,
) -> tuple[bytes, bytes]:
    """Undo per-row PNG scanline filters, returning `(raw_pixels, row_types)`."""
    row_in = stride + 1
    if height <= 0 or stride <= 0 or bpp < 1 or bpp > 8 or bpp > stride:
        raise MediaStageError("invalid PNG dimensions or bpp")
    if len(filtered) != height * row_in:
        raise MediaStageError("PNG filtered scanline size mismatch")

    if native_lib is not None and hasattr(native_lib, "fv_png_unfilter"):
        raw_buf = ctypes.create_string_buffer(height * stride)
        types_buf = ctypes.create_string_buffer(height)
        rc = int(
            native_lib.fv_png_unfilter(
                filtered,
                len(filtered),
                height,
                stride,
                bpp,
                raw_buf,
                types_buf,
            )
        )
        if rc != 0:
            raise MediaStageError("invalid PNG scanline filter type")
        return raw_buf.raw, types_buf.raw

    raw_out = bytearray(height * stride)
    types_out = bytearray(height)
    mv = memoryview(filtered)
    for y in range(height):
        src_off = y * row_in
        ftype = mv[src_off]
        if ftype > 4:
            raise MediaStageError(f"invalid PNG filter type: {ftype}")
        types_out[y] = ftype
        dst_off = y * stride
        prev_off = dst_off - stride
        if ftype == 0:
            raw_out[dst_off : dst_off + stride] = mv[src_off + 1 : src_off + row_in]
        elif ftype == 1:
            for x in range(bpp):
                raw_out[dst_off + x] = mv[src_off + 1 + x]
            for x in range(bpp, stride):
                raw_out[dst_off + x] = (
                    mv[src_off + 1 + x] + raw_out[dst_off + x - bpp]
                ) & 0xFF
        elif ftype == 2:
            if y == 0:
                raw_out[dst_off : dst_off + stride] = mv[src_off + 1 : src_off + row_in]
            else:
                for x in range(stride):
                    raw_out[dst_off + x] = (
                        mv[src_off + 1 + x] + raw_out[prev_off + x]
                    ) & 0xFF
        elif ftype == 3:
            for x in range(stride):
                a = raw_out[dst_off + x - bpp] if x >= bpp else 0
                b = raw_out[prev_off + x] if y > 0 else 0
                raw_out[dst_off + x] = (mv[src_off + 1 + x] + ((a + b) >> 1)) & 0xFF
        else:
            for x in range(stride):
                a = raw_out[dst_off + x - bpp] if x >= bpp else 0
                b = raw_out[prev_off + x] if y > 0 else 0
                c = raw_out[prev_off + x - bpp] if (y > 0 and x >= bpp) else 0
                raw_out[dst_off + x] = (mv[src_off + 1 + x] + _paeth(a, b, c)) & 0xFF
    return bytes(raw_out), bytes(types_out)


def png_filter(
    raw_pixels: bytes,
    row_types: bytes,
    height: int,
    stride: int,
    bpp: int,
    *,
    native_lib: Any = None,
) -> bytes:
    """Re-apply per-row PNG scanline filters to raw pixel bytes."""
    if height <= 0 or stride <= 0 or bpp < 1 or bpp > 8 or bpp > stride:
        raise MediaStageError("invalid PNG dimensions or bpp")
    if len(raw_pixels) != height * stride or len(row_types) != height:
        raise MediaStageError("PNG pixel/filter-type buffer size mismatch")

    row_out = stride + 1
    if native_lib is not None and hasattr(native_lib, "fv_png_filter"):
        out_buf = ctypes.create_string_buffer(height * row_out)
        rc = int(
            native_lib.fv_png_filter(
                raw_pixels,
                len(raw_pixels),
                row_types,
                height,
                stride,
                bpp,
                out_buf,
            )
        )
        if rc != 0:
            raise MediaStageError("invalid PNG scanline filter type")
        return out_buf.raw

    out = bytearray(height * row_out)
    mv = memoryview(raw_pixels)
    for y in range(height):
        ftype = row_types[y]
        if ftype > 4:
            raise MediaStageError(f"invalid PNG filter type: {ftype}")
        src_off = y * stride
        prev_off = src_off - stride
        dst_off = y * row_out
        out[dst_off] = ftype
        if ftype == 0:
            out[dst_off + 1 : dst_off + row_out] = mv[src_off : src_off + stride]
        elif ftype == 1:
            for x in range(bpp):
                out[dst_off + 1 + x] = mv[src_off + x]
            for x in range(bpp, stride):
                out[dst_off + 1 + x] = (mv[src_off + x] - mv[src_off + x - bpp]) & 0xFF
        elif ftype == 2:
            if y == 0:
                out[dst_off + 1 : dst_off + row_out] = mv[src_off : src_off + stride]
            else:
                for x in range(stride):
                    out[dst_off + 1 + x] = (mv[src_off + x] - mv[prev_off + x]) & 0xFF
        elif ftype == 3:
            for x in range(stride):
                a = mv[src_off + x - bpp] if x >= bpp else 0
                b = mv[prev_off + x] if y > 0 else 0
                out[dst_off + 1 + x] = (mv[src_off + x] - ((a + b) >> 1)) & 0xFF
        else:
            for x in range(stride):
                a = mv[src_off + x - bpp] if x >= bpp else 0
                b = mv[prev_off + x] if y > 0 else 0
                c = mv[prev_off + x - bpp] if (y > 0 and x >= bpp) else 0
                out[dst_off + 1 + x] = (mv[src_off + x] - _paeth(a, b, c)) & 0xFF
    return bytes(out)


def parse_png(data: bytes) -> tuple[list[tuple[bytes, bytes, bytes]], bytes] | None:
    """Parse a PNG file into `(chunks, trailing_bytes)` or return `None` if malformed."""
    if len(data) < 33 or data[:8] != PNG_SIG:
        return None
    pos = 8
    chunks: list[tuple[bytes, bytes, bytes]] = []
    saw_iend = False
    while pos + 12 <= len(data):
        (length,) = struct.unpack_from(">I", data, pos)
        end = pos + 12 + length
        if end > len(data):
            return None
        ctype = data[pos + 4 : pos + 8]
        body = data[pos + 8 : pos + 8 + length]
        crc = data[pos + 8 + length : end]
        chunks.append((ctype, body, crc))
        pos = end
        if ctype == b"IEND":
            saw_iend = True
            break
    if not saw_iend or not chunks or chunks[0][0] != b"IHDR" or len(chunks[0][1]) != 13:
        return None
    return chunks, data[pos:]


def classic_zlib_missing_words(why: str) -> str:
    """The message for restoring PNG recipes without classic zlib (forge_deflate's why)."""
    return (
        "Restoring PNG files packed with Pack's exact PNG recipe needs classic zlib, "
        f"and there is none here: {why}. On Windows, connect to the internet once "
        "so Forge can fetch it, or point FORGE_ZLIB_CLASSIC at a classic zlib library."
    )


def png_recipes_restorable(auto_fetch: bool = True) -> str | None:
    """None when PNG recipes can be restored here, else the words saying why not."""
    try:
        forge_deflate.classic(auto_fetch=auto_fetch)
    except forge_deflate.ClassicZlibMissing as exc:
        return classic_zlib_missing_words(str(exc))
    return None


def find_zlib_recipe(
    filtered: bytes,
    compressed: bytes,
    classic: forge_deflate.Classic | None = None,
) -> tuple[int, int, int, int] | None:
    """Search `(level, memLevel, strategy, wbits)` reproducing `compressed` byte for byte.

    Runs classic zlib (`classic`, else forge_deflate's, fetched on first use
    where Forge has a build); None when there is no classic deflate here.
    """
    if len(compressed) < 6:
        return None
    if classic is None:
        classic = forge_deflate.try_classic(auto_fetch=True)
        if classic is None:
            return None
    cmf, flg = compressed[0], compressed[1]
    if (cmf & 0x0F) != 8 or (cmf * 256 + flg) % 31 != 0 or (flg & 0x20) != 0:
        return None
    wbits = (cmf >> 4) + 8
    if not (8 <= wbits <= 15):
        return None
    flevel = flg >> 6
    by_flag = {0: [1], 1: [2, 3, 4, 5], 2: [6], 3: [7, 8, 9]}[flevel]
    levels = by_flag + [lv for lv in range(0, 10) if lv not in by_flag]
    prefix = filtered[: 1 << 18]
    is_short = len(prefix) == len(filtered)
    for strategy in (0, 1, 3, 2):
        for mem in (8, 9, 7, 6, 5, 4, 3, 2, 1):
            for lv in levels:
                co = classic.compressobj(lv, zlib.DEFLATED, wbits, mem, strategy)
                out = co.compress(prefix)
                if is_short:
                    out += co.flush()
                    if out == compressed:
                        return lv, mem, strategy, wbits
                    continue
                if out and compressed[: len(out)] != out:
                    continue
                full = classic.compressobj(lv, zlib.DEFLATED, wbits, mem, strategy)
                if full.compress(filtered) + full.flush() == compressed:
                    return lv, mem, strategy, wbits
    return None


def _encode_pam(width: int, height: int, channels: int, pixels: bytes) -> bytes:
    tupl = PAM_TUPLTYPES[channels]
    hdr = (
        f"P7\nWIDTH {width}\nHEIGHT {height}\nDEPTH {channels}\n"
        f"MAXVAL 255\nTUPLTYPE {tupl}\nENDHDR\n"
    ).encode("ascii")
    return hdr + pixels


def _decode_pam(pam_bytes: bytes) -> tuple[int, int, int, bytes]:
    marker = b"ENDHDR\n"
    idx = pam_bytes.find(marker)
    if idx < 0 or not pam_bytes.startswith(b"P7\n"):
        raise MediaStageError("invalid PAM header from djxl")
    hdr_lines = pam_bytes[:idx].decode("ascii", errors="strict").splitlines()
    vals: dict[str, str] = {}
    for line in hdr_lines[1:]:
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            vals[parts[0]] = parts[1]
    try:
        w = int(vals["WIDTH"])
        h = int(vals["HEIGHT"])
        ch = int(vals["DEPTH"])
        maxval = int(vals["MAXVAL"])
    except (KeyError, ValueError) as exc:
        raise MediaStageError("incomplete PAM header from djxl") from exc
    if maxval != 255:
        raise MediaStageError(f"unexpected PAM MAXVAL {maxval}")
    pixels = pam_bytes[idx + len(marker) :]
    if len(pixels) != w * h * ch:
        raise MediaStageError(
            f"PAM pixel length mismatch (got {len(pixels)}, expected {w * h * ch})"
        )
    return w, h, ch, pixels


def encode_png_recipe(
    raw_bytes: bytes,
    *,
    effort: int = DEFAULT_JXL_EFFORT,
    native_lib: Any = None,
) -> tuple[bytes, dict[str, Any]] | None:
    """Bit-exact PNG re-deflate recipe + lossless JPEG XL pixels (`FPR1`).

    Preserves every PNG chunk, CRC, IDAT split size, per-row filter byte, and any
    trailing bytes after `IEND`. Verifies exact SHA-256 round trip at pack time;
    returns `None` on recipe miss, unsupported mode, or if not strictly smaller.
    """
    cjxl = find_tool("cjxl", auto_fetch=True)
    djxl = find_tool("djxl", auto_fetch=True)
    if not cjxl or not djxl:
        return None
    # recipes need classic zlib's exact bytes (Windows: a fetched zlib1.dll)
    classic = forge_deflate.try_classic(auto_fetch=True)
    if classic is None:
        return None
    parsed = parse_png(raw_bytes)
    if parsed is None:
        return None
    chunks, trailing = parsed
    w, h, bd, ct, cm, fm, il = struct.unpack(">IIBBBBB", chunks[0][1])
    if bd != 8 or ct not in PNG_CHANNELS or cm != 0 or fm != 0 or il != 0:
        return None
    ch = PNG_CHANNELS[ct]
    if w == 0 or h == 0 or w * h * ch > MAX_PNG_PIXEL_BYTES:
        return None

    idat_parts = [body for typ, body, _crc in chunks if typ == b"IDAT"]
    if not idat_parts:
        return None
    z_stream = b"".join(idat_parts)
    expected_filtered = h * (w * ch + 1)
    decomp = zlib.decompressobj()
    try:
        filtered = decomp.decompress(z_stream, expected_filtered + 1)
    except zlib.error:
        return None
    if not decomp.eof or decomp.unused_data or len(filtered) != expected_filtered:
        return None

    recipe = find_zlib_recipe(filtered, z_stream, classic)
    if recipe is None:
        return None

    try:
        pixels, row_types = png_unfilter(filtered, h, w * ch, ch, native_lib=native_lib)
    except MediaStageError:
        return None

    with tempfile.TemporaryDirectory(prefix="fv_jxl_png_") as td:
        d = Path(td)
        pam_in = d / "in.pam"
        jxl_out = d / "pix.jxl"
        pam_in.write_bytes(_encode_pam(w, h, ch, pixels))
        try:
            enc = subprocess.run(
                [
                    cjxl,
                    str(pam_in),
                    str(jxl_out),
                    "-d",
                    "0",
                    "-e",
                    str(effort),
                    "--quiet",
                ],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT_SEC,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if enc.returncode != 0 or not jxl_out.is_file():
            return None
        jxl_bytes = jxl_out.read_bytes()

    if not jxl_bytes:
        return None

    chunk_meta: list[dict[str, Any]] = []
    non_idat_blobs: list[bytes] = []
    for typ, body, crc in chunks:
        entry: dict[str, Any] = {"t": typ.decode("latin1"), "crc": crc.hex()}
        if typ == b"IDAT":
            entry["n"] = len(body)
        else:
            entry["blen"] = len(body)
            non_idat_blobs.append(body)
        chunk_meta.append(entry)

    hdr_json = json.dumps(
        {
            "v": 1,
            "recipe": list(recipe),
            "shape": [h, w, ch],
            "chunks": chunk_meta,
            "trailing_len": len(trailing),
        },
        separators=(",", ":"),
    ).encode("utf-8")

    hdr_plain = (
        struct.pack("<I", len(hdr_json))
        + hdr_json
        + row_types
        + b"".join(non_idat_blobs)
        + trailing
    )
    if len(hdr_plain) > MAX_PNG_RECIPE_HEADER_BYTES:
        return None
    hdr_comp = lzma.compress(hdr_plain, preset=6)

    envelope = (
        PNG_RECIPE_MAGIC
        + struct.pack("<I", len(hdr_comp))
        + hdr_comp
        + struct.pack("<I", len(jxl_bytes))
        + jxl_bytes
    )
    if len(envelope) >= len(raw_bytes):
        return None

    # Mandatory pack-time verification: decode and check exact SHA-256 match.
    try:
        restored = decode_png_recipe(
            envelope, native_lib=native_lib, djxl_path=djxl, classic=classic
        )
    except MediaStageError:
        return None
    if (
        len(restored) != len(raw_bytes)
        or hashlib.sha256(restored).digest() != hashlib.sha256(raw_bytes).digest()
    ):
        return None

    return envelope, {
        "stage": "png_recipe_jxl",
        "stored_size": len(envelope),
        "jxl_size": len(jxl_bytes),
        "recipe": list(recipe),
        "shape": [h, w, ch],
        "trailing_bytes": len(trailing),
    }


def decode_png_recipe(
    envelope: bytes,
    meta: dict[str, Any] | None = None,
    *,
    native_lib: Any = None,
    djxl_path: str | None = None,
    classic: forge_deflate.Classic | None = None,
) -> bytes:
    """Restore a bit-exact PNG from an `FPR1` recipe + lossless JPEG XL envelope.

    Re-deflates with classic zlib (`classic`, else forge_deflate's, fetched on
    first use where Forge has a build); MediaToolMissingError naming the cause
    when there is none here.
    """
    if meta is not None:
        exp_size = meta.get("stored_size")
        if isinstance(exp_size, int) and len(envelope) != exp_size:
            raise MediaStageError(
                f"PNG recipe size mismatch (got {len(envelope)}, expected {exp_size})"
            )
    if len(envelope) < 12 or envelope[:4] != PNG_RECIPE_MAGIC:
        raise MediaStageError("invalid PNG recipe envelope magic")
    hdr_comp_len = struct.unpack_from("<I", envelope, 4)[0]
    jxl_len_off = 8 + hdr_comp_len
    if jxl_len_off + 4 > len(envelope):
        raise MediaStageError("truncated PNG recipe header")
    hdr_comp = envelope[8:jxl_len_off]
    jxl_len = struct.unpack_from("<I", envelope, jxl_len_off)[0]
    jxl_start = jxl_len_off + 4
    if jxl_start + jxl_len != len(envelope) or jxl_len == 0:
        raise MediaStageError("truncated or trailing bytes in PNG recipe JXL payload")
    jxl_bytes = envelope[jxl_start:]

    try:
        dec_lzma = lzma.LZMADecompressor()
        hdr_plain = dec_lzma.decompress(
            hdr_comp, max_length=MAX_PNG_RECIPE_HEADER_BYTES + 1
        )
        if not dec_lzma.eof or len(hdr_plain) > MAX_PNG_RECIPE_HEADER_BYTES:
            raise MediaStageError("PNG recipe header exceeds safe bounds")
    except lzma.LZMAError as exc:
        raise MediaStageError(f"corrupted PNG recipe header: {exc}") from exc

    if len(hdr_plain) < 4:
        raise MediaStageError("truncated PNG recipe metadata")
    json_len = struct.unpack_from("<I", hdr_plain, 0)[0]
    if 4 + json_len > len(hdr_plain):
        raise MediaStageError("malformed PNG recipe JSON length")
    try:
        hdr_meta = json.loads(hdr_plain[4 : 4 + json_len].decode("utf-8"))
        h, w, ch = (int(x) for x in hdr_meta["shape"])
        lv, mem, strategy, wbits = (int(x) for x in hdr_meta["recipe"])
        chunks_spec = hdr_meta["chunks"]
        trailing_len = int(hdr_meta.get("trailing_len", 0))
    except (ValueError, KeyError, TypeError) as exc:
        raise MediaStageError(f"malformed PNG recipe JSON: {exc}") from exc

    if (
        w <= 0
        or h <= 0
        or ch not in (1, 2, 3, 4)
        or w * h * ch > MAX_PNG_PIXEL_BYTES
        or trailing_len < 0
    ):
        raise MediaStageError("PNG recipe dimensions out of safe bounds")

    pos = 4 + json_len
    if pos + h > len(hdr_plain):
        raise MediaStageError("truncated PNG row filter types")
    row_types = hdr_plain[pos : pos + h]
    pos += h

    non_idat_bodies: list[bytes] = []
    if not isinstance(chunks_spec, list):
        raise MediaStageError("malformed PNG recipe chunks list")
    for entry in chunks_spec:
        if not isinstance(entry, dict):
            raise MediaStageError("malformed PNG recipe chunk entry")
        if entry.get("t") != "IDAT":
            try:
                blen = int(entry.get("blen", -1))
            except (ValueError, TypeError) as exc:
                raise MediaStageError("invalid PNG chunk body length") from exc
            if blen < 0 or pos + blen > len(hdr_plain):
                raise MediaStageError("truncated PNG non-IDAT chunk body")
            non_idat_bodies.append(hdr_plain[pos : pos + blen])
            pos += blen
    if pos + trailing_len != len(hdr_plain):
        raise MediaStageError("PNG recipe trailing bytes length mismatch")
    trailing = hdr_plain[pos : pos + trailing_len]

    if classic is None:
        try:
            classic = forge_deflate.classic(auto_fetch=True)
        except forge_deflate.ClassicZlibMissing as exc:
            raise MediaToolMissingError(classic_zlib_missing_words(str(exc))) from None

    djxl = djxl_path or find_tool("djxl", auto_fetch=True)
    if not djxl:
        raise MediaToolMissingError(
            "Unpacking PNG recipe media-stage files requires 'djxl' (libjxl, BSD) "
            "on PATH or placed beside forge_unpack.py."
        )

    max_pam_bytes = w * h * ch + 4096
    with tempfile.TemporaryDirectory(prefix="fv_jxl_png_dec_") as td:
        d = Path(td)
        in_jxl = d / "pix.jxl"
        out_pam = d / "out.pam"
        in_jxl.write_bytes(jxl_bytes)
        try:
            dec = subprocess.run(
                [djxl, "--quiet", str(in_jxl), str(out_pam)],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT_SEC,
                preexec_fn=_make_fsize_limiter(w * h * ch + 65536),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise MediaStageError(f"djxl failed to decode PNG pixels: {exc}") from exc
        if dec.returncode != 0 or not out_pam.is_file():
            detail = (dec.stderr or dec.stdout or "unknown error").strip()
            raise MediaStageError(f"djxl failed to decode PNG pixels: {detail}")
        if out_pam.stat().st_size > max_pam_bytes:
            raise MediaStageError("decoded PAM exceeds declared recipe pixel bounds")
        dw, dh, dch, pixels = _decode_pam(out_pam.read_bytes())

    if (dw, dh, dch) != (w, h, ch):
        raise MediaStageError(
            f"decoded JXL dimensions ({dw}x{dh}x{dch}) != recipe ({w}x{h}x{ch})"
        )

    filtered = png_filter(pixels, row_types, h, w * ch, ch, native_lib=native_lib)
    try:
        co = classic.compressobj(lv, zlib.DEFLATED, wbits, mem, strategy)
        z_stream = co.compress(filtered) + co.flush()
    except (ValueError, zlib.error) as exc:
        raise MediaStageError(f"PNG recipe zlib deflate failed: {exc}") from exc

    parts: list[bytes] = [PNG_SIG]
    z_pos = 0
    non_idx = 0
    for entry in chunks_spec:
        try:
            typ = str(entry["t"]).encode("latin1")
            crc = bytes.fromhex(str(entry["crc"]))
        except (KeyError, UnicodeEncodeError, ValueError) as exc:
            raise MediaStageError(f"malformed PNG chunk metadata: {exc}") from exc
        if len(typ) != 4:
            raise MediaStageError("invalid PNG chunk type length")
        if len(crc) != 4:
            raise MediaStageError("invalid PNG chunk CRC length")
        if typ == b"IDAT":
            try:
                n = int(entry["n"])
            except (KeyError, ValueError, TypeError) as exc:
                raise MediaStageError("invalid PNG IDAT chunk length") from exc
            if n < 0 or z_pos + n > len(z_stream):
                raise MediaStageError("PNG recipe IDAT split out of bounds")
            body = z_stream[z_pos : z_pos + n]
            z_pos += n
        else:
            body = non_idat_bodies[non_idx]
            non_idx += 1
        parts.append(struct.pack(">I", len(body)))
        parts.append(typ)
        parts.append(body)
        parts.append(crc)
    if z_pos != len(z_stream):
        raise MediaStageError("PNG recipe did not consume entire deflated IDAT stream")
    if trailing:
        parts.append(trailing)
    return b"".join(parts)


# ---------------------- Stage 3: MP4 Render-Version Packet Dedup ----------------------


def ffprobe_packet_spans(path: Path) -> list[tuple[int, int]]:
    """Return sorted non-overlapping `(pos, size)` byte spans for packets via `ffprobe`."""
    ffprobe = find_tool("ffprobe")
    if not ffprobe:
        return []
    try:
        res = subprocess.run(
            [
                ffprobe,
                "-v",
                "error",
                "-show_entries",
                "packet=pos,size",
                "-of",
                "compact=p=0",
                str(path),
            ],
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SEC,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if res.returncode != 0:
        return []

    file_size = path.stat().st_size
    spans: list[tuple[int, int]] = []
    for line in res.stdout.splitlines():
        pos: int | None = None
        size: int | None = None
        for part in line.split("|"):
            if part.startswith("pos="):
                raw_v = part[4:].strip()
                if raw_v and raw_v != "N/A":
                    pos = int(raw_v)
            elif part.startswith("size="):
                raw_v = part[5:].strip()
                if raw_v and raw_v != "N/A":
                    size = int(raw_v)
        if (
            pos is not None
            and size is not None
            and pos >= 0
            and size > 0
            and pos + size <= file_size
        ):
            spans.append((pos, size))
    spans.sort()
    clean: list[tuple[int, int]] = []
    cursor = 0
    for pos, size in spans:
        if pos >= cursor:
            clean.append((pos, size))
            cursor = pos + size
    return clean


def _index_mp4_packets(path: Path) -> dict[bytes, tuple[int, int]]:
    """Index packet SHA-256 -> `(pos, size)` by reading packet spans from `path`."""
    spans = ffprobe_packet_spans(path)
    if not spans:
        return {}
    index: dict[bytes, tuple[int, int]] = {}
    with path.open("rb") as fh:
        for pos, size in spans:
            fh.seek(pos)
            pkt = fh.read(size)
            if len(pkt) != size:
                continue
            digest = hashlib.sha256(pkt).digest()
            index.setdefault(digest, (pos, size))
    return index


def plan_mp4_packet_dedup(
    mp4_files: list[tuple[str, Path]],
) -> dict[str, tuple[bytes, dict[str, Any]]]:
    """Plan cross-file render-version packet dedup across MP4/MOV/M4V files.

    Returns `{rel_path: (fmp1_payload, media_meta)}` for every file that saves
    bytes by referencing an earlier base file in the same pack and passes
    pack-time SHA-256 rebuild verification. Base files are left untouched v1.
    """
    if len(mp4_files) < 2 or not find_tool("ffprobe"):
        return {}

    bases: list[tuple[str, Path, dict[bytes, tuple[int, int]]]] = []
    base_file_hashes: set[bytes] = set()
    plans: dict[str, tuple[bytes, dict[str, Any]]] = {}

    for rel, fpath in mp4_files:
        spans = ffprobe_packet_spans(fpath)
        if not spans:
            continue
        f_size = fpath.stat().st_size
        # Skip byte-identical duplicate MP4s so plain FastCDC dedup stores 0 extra bytes.
        f_hash = hashlib.sha256()
        with fpath.open("rb") as fh_all:
            while True:
                blk = fh_all.read(1024 * 1024)
                if not blk:
                    break
                f_hash.update(blk)
        full_digest = f_hash.digest()
        if full_digest in base_file_hashes:
            continue
        # Compute packet hashes for candidate file B once.
        b_pkts: list[tuple[int, int, bytes]] = []
        with fpath.open("rb") as fh:
            for pos, size in spans:
                fh.seek(pos)
                pkt = fh.read(size)
                if len(pkt) == size:
                    b_pkts.append((pos, size, hashlib.sha256(pkt).digest()))

        best_base: tuple[str, Path, list[tuple[int, int, int]], int] | None = None
        for base_rel, base_path, base_idx in bases:
            matches: list[tuple[int, int, int]] = []
            matched_bytes = 0
            for b_pos, size, digest in b_pkts:
                hit = base_idx.get(digest)
                if hit is not None and hit[1] == size:
                    matches.append((b_pos, hit[0], size))
                    matched_bytes += size
            if matched_bytes > 4096 and (
                best_base is None or matched_bytes > best_base[3]
            ):
                best_base = (base_rel, base_path, matches, matched_bytes)

        if best_base is not None:
            base_rel, base_path, raw_matches, _ = best_base
            # Build skeleton and confirm exact byte equality against base_path.
            verified_table: list[tuple[int, int, int]] = []
            skel = bytearray()
            cur = 0
            shared_bytes = 0
            orig_hasher = hashlib.sha256()
            with fpath.open("rb") as fb, base_path.open("rb") as fa:
                for b_pos, a_pos, size in raw_matches:
                    if b_pos < cur:
                        continue
                    fa.seek(a_pos)
                    a_pkt = fa.read(size)
                    fb.seek(b_pos)
                    b_pkt = fb.read(size)
                    if len(a_pkt) == size and a_pkt == b_pkt:
                        if b_pos > cur:
                            fb.seek(cur)
                            gap = fb.read(b_pos - cur)
                            skel.extend(gap)
                            orig_hasher.update(gap)
                        orig_hasher.update(b_pkt)
                        verified_table.append((b_pos, a_pos, size))
                        shared_bytes += size
                        cur = b_pos + size
                if cur < f_size:
                    fb.seek(cur)
                    tail = fb.read(f_size - cur)
                    skel.extend(tail)
                    orig_hasher.update(tail)

            if verified_table:
                table_raw = b"".join(
                    struct.pack("<QQI", bp, ap, sz) for bp, ap, sz in verified_table
                )
                table_comp = zlib.compress(table_raw, 6)
                payload = (
                    MP4_DEDUP_MAGIC
                    + struct.pack("<I", len(table_comp))
                    + table_comp
                    + bytes(skel)
                )
                if len(payload) + 1024 < f_size:
                    # Mandatory pack-time rebuild verification.
                    with base_path.open("rb") as fa_chk:

                        def _read_base(
                            off: int, length: int, fh: Any = fa_chk
                        ) -> bytes:
                            fh.seek(off)
                            return fh.read(length)

                        chk_hasher = hashlib.sha256()
                        chk_len = 0
                        for piece in iter_decode_mp4_packet_dedup(payload, _read_base):
                            chk_hasher.update(piece)
                            chk_len += len(piece)
                    if (
                        chk_len == f_size
                        and chk_hasher.digest() == orig_hasher.digest()
                    ):
                        plans[rel] = (
                            payload,
                            {
                                "stage": "mp4_packet_dedup",
                                "ref_path": base_rel,
                                "stored_size": len(payload),
                                "shared_packets": len(verified_table),
                                "shared_bytes": shared_bytes,
                            },
                        )
                        continue

        # Not deduped -> register as a base file for later MP4s.
        idx: dict[bytes, tuple[int, int]] = {}
        for pos, size, digest in b_pkts:
            idx.setdefault(digest, (pos, size))
        bases.append((rel, fpath, idx))
        base_file_hashes.add(full_digest)

    return plans


def iter_decode_mp4_packet_dedup(
    payload: bytes,
    read_ref_range: Callable[[int, int], bytes],
    meta: dict[str, Any] | None = None,
) -> Iterator[bytes]:
    """Stream-rebuild an `FMP1` packet-deduplicated MP4 yielding ordered byte pieces."""
    if meta is not None:
        exp_size = meta.get("stored_size")
        if isinstance(exp_size, int) and len(payload) != exp_size:
            raise MediaStageError("MP4 dedup payload stored_size mismatch")
    if len(payload) < 8 or payload[:4] != MP4_DEDUP_MAGIC:
        raise MediaStageError("invalid MP4 packet-dedup magic")
    table_comp_len = struct.unpack_from("<I", payload, 4)[0]
    skel_start = 8 + table_comp_len
    if skel_start > len(payload):
        raise MediaStageError("truncated MP4 packet-dedup table")
    table_comp = payload[8:skel_start]
    skel = memoryview(payload)[skel_start:]

    try:
        dec = zlib.decompressobj()
        table_raw = dec.decompress(table_comp, MAX_MP4_TABLE_BYTES + 1)
        if not dec.eof or len(table_raw) > MAX_MP4_TABLE_BYTES:
            raise MediaStageError("MP4 packet-dedup table exceeds safe bounds")
    except zlib.error as exc:
        raise MediaStageError(f"corrupted MP4 packet-dedup table: {exc}") from exc
    if len(table_raw) % 20 != 0:
        raise MediaStageError("malformed MP4 packet-dedup entry alignment")

    s_pos = 0
    prev_end = 0
    for off in range(0, len(table_raw), 20):
        b_pos, a_pos, size = struct.unpack_from("<QQI", table_raw, off)
        if b_pos < prev_end or size == 0:
            raise MediaStageError("invalid or overlapping MP4 packet-dedup span")
        gap = b_pos - prev_end
        if s_pos + gap > len(skel):
            raise MediaStageError("MP4 packet-dedup skeleton truncated")
        if gap:
            yield bytes(skel[s_pos : s_pos + gap])
            s_pos += gap
        ref_bytes = read_ref_range(a_pos, size)
        if len(ref_bytes) != size:
            raise MediaStageError("MP4 packet-dedup reference read out of bounds")
        yield ref_bytes
        prev_end = b_pos + size
    if s_pos < len(skel):
        yield bytes(skel[s_pos:])


# ---------------------- Stage 4: MKV Embedded Attachment / Font Dedup ----------------------


_EBML_SEGMENT_ID = 0x18538067
_EBML_ATTACHMENTS_ID = 0x1941A469
_EBML_ATTACHED_FILE_ID = 0x61A7
_EBML_FILE_DATA_ID = 0x465C


def _read_ebml_id(fh: Any) -> tuple[int, int] | None:
    b0 = fh.read(1)
    if not b0:
        return None
    first = b0[0]
    if first == 0:
        return None
    mask = 0x80
    length = 1
    while length <= 4 and not (first & mask):
        mask >>= 1
        length += 1
    if length > 4:
        return None
    rest = fh.read(length - 1)
    if len(rest) != length - 1:
        return None
    val = first
    for b in rest:
        val = (val << 8) | b
    return val, length


def _read_ebml_size(fh: Any) -> tuple[int | None, int] | None:
    b0 = fh.read(1)
    if not b0:
        return None
    first = b0[0]
    if first == 0:
        return None
    mask = 0x80
    length = 1
    while length <= 8 and not (first & mask):
        mask >>= 1
        length += 1
    if length > 8:
        return None
    rest = fh.read(length - 1)
    if len(rest) != length - 1:
        return None
    val = first & (mask - 1)
    all_ones = (1 << (7 * length)) - 1
    for b in rest:
        val = (val << 8) | b
    if val == all_ones:
        return None, length  # Unknown / streaming size
    return val, length


def scan_mkv_attachment_spans(path: Path) -> list[tuple[int, int, str]]:
    """Locate exact `(offset, length, sha256_hex)` of every Matroska `FileData` payload.

    Pure-Python EBML walk over top-level Segment children (seeks past Cluster
    elements in O(1) without reading video frames or spawning ffmpeg).
    """
    file_size = path.stat().st_size
    spans: list[tuple[int, int, str]] = []
    with path.open("rb") as fh:
        if fh.read(4) != b"\x1a\x45\xdf\xa3":
            return []
        fh.seek(0)
        # Walk root elements until Segment
        seg_end = file_size
        found_seg = False
        while fh.tell() < file_size:
            eid = _read_ebml_id(fh)
            if eid is None:
                return []
            esize = _read_ebml_size(fh)
            if esize is None:
                return []
            elem_id, _ = eid
            size, _ = esize
            payload_start = fh.tell()
            if elem_id == _EBML_SEGMENT_ID:
                seg_end = (
                    min(file_size, payload_start + size)
                    if size is not None
                    else file_size
                )
                found_seg = True
                break
            if size is None or payload_start + size > file_size:
                return []
            fh.seek(payload_start + size)
        if not found_seg:
            return []

        # Walk top-level children of Segment
        while fh.tell() < seg_end:
            eid = _read_ebml_id(fh)
            if eid is None:
                break
            esize = _read_ebml_size(fh)
            if esize is None:
                break
            elem_id, _ = eid
            size, _ = esize
            child_start = fh.tell()
            if elem_id == _EBML_ATTACHMENTS_ID:
                att_end = (
                    min(seg_end, child_start + size) if size is not None else seg_end
                )
                while fh.tell() < att_end:
                    aid = _read_ebml_id(fh)
                    if aid is None:
                        break
                    asize = _read_ebml_size(fh)
                    if asize is None:
                        break
                    a_elem_id, _ = aid
                    a_len, _ = asize
                    af_start = fh.tell()
                    if a_len is None or af_start + a_len > att_end:
                        break
                    af_end = af_start + a_len
                    if a_elem_id == _EBML_ATTACHED_FILE_ID:
                        while fh.tell() < af_end:
                            fid = _read_ebml_id(fh)
                            if fid is None:
                                break
                            fsize = _read_ebml_size(fh)
                            if fsize is None:
                                break
                            f_elem_id, _ = fid
                            f_len, _ = fsize
                            fd_start = fh.tell()
                            if f_len is None or fd_start + f_len > af_end:
                                break
                            if f_elem_id == _EBML_FILE_DATA_ID and f_len >= 64:
                                data = fh.read(f_len)
                                if len(data) == f_len:
                                    spans.append(
                                        (
                                            fd_start,
                                            f_len,
                                            hashlib.sha256(data).hexdigest(),
                                        )
                                    )
                            else:
                                fh.seek(fd_start + f_len)
                    fh.seek(af_end)
                fh.seek(att_end)
                continue
            if size is None or child_start + size > seg_end:
                break
            fh.seek(child_start + size)

    spans.sort()
    # Ensure strict non-overlapping spans.
    clean: list[tuple[int, int, str]] = []
    cur = 0
    for off, length, digest in spans:
        if off >= cur and off + length <= file_size:
            clean.append((off, length, digest))
            cur = off + length
    return clean


def plan_mkv_font_dedup(
    mkv_files: list[tuple[str, Path]],
) -> tuple[dict[str, bytes], dict[str, list[tuple[int, int, str]]]]:
    """Identify shared MKV attachments across 2+ MKV files in a pack.

    Returns `(unique_assets_by_sha, per_file_spans)` only when deduplicating
    attachments across the MKV set actually shares at least one attachment and
    strictly saves bytes.
    """
    if len(mkv_files) < 2:
        return {}, {}

    scanned: dict[str, tuple[Path, list[tuple[int, int, str]]]] = {}
    asset_counts: dict[str, int] = {}
    asset_sizes: dict[str, int] = {}
    asset_loc: dict[str, tuple[Path, int, int]] = {}

    for rel, fpath in mkv_files:
        spans = scan_mkv_attachment_spans(fpath)
        if not spans:
            continue
        scanned[rel] = (fpath, spans)
        for off, length, sha in spans:
            asset_counts[sha] = asset_counts.get(sha, 0) + 1
            asset_sizes[sha] = length
            asset_loc.setdefault(sha, (fpath, off, length))

    shared_shas = {sha for sha, cnt in asset_counts.items() if cnt >= 2}
    if not shared_shas:
        return {}, {}

    # Replace only spans whose attachment is shared across >= 2 occurrences.
    total_replaced = sum(asset_sizes[sha] * asset_counts[sha] for sha in shared_shas)
    unique_total = sum(asset_sizes[sha] for sha in shared_shas)
    overhead_est = sum(len(s) * 90 for _, s in scanned.values()) + 256
    if total_replaced <= unique_total + overhead_est:
        return {}, {}

    unique_assets: dict[str, bytes] = {}
    for sha in sorted(shared_shas):
        src_path, off, length = asset_loc[sha]
        with src_path.open("rb") as fh:
            fh.seek(off)
            blob = fh.read(length)
        if len(blob) != length or hashlib.sha256(blob).hexdigest() != sha:
            return {}, {}
        unique_assets[sha] = blob

    per_file_spans: dict[str, list[tuple[int, int, str]]] = {}
    for rel, (_fpath, spans) in scanned.items():
        kept = [(off, length, sha) for off, length, sha in spans if sha in shared_shas]
        if kept:
            per_file_spans[rel] = kept

    return unique_assets, per_file_spans


def stream_mkv_skeleton_chunks(
    fpath: Path,
    spans: list[tuple[int, int, str]],
    cut_fn: Callable[[bytes], int],
    min_chunk: int,
    max_chunk: int,
    chunk_size: int = 1024 * 1024,
) -> tuple[list[bytes], int, str, int]:
    """Stream an MKV into FastCDC skeleton chunks without buffering 2-3x the whole file.

    Returns `(skeleton_chunks, skeleton_total_bytes, orig_sha256_hex, orig_size)`
    while verifying every attachment span's SHA-256 inline in one sequential pass.
    """
    orig_size = fpath.stat().st_size
    hasher = hashlib.sha256()
    chunks: list[bytes] = []
    skel_total = 0
    buf = bytearray()

    def _push_skel(data: bytes) -> None:
        nonlocal skel_total
        if not data:
            return
        skel_total += len(data)
        buf.extend(data)
        while len(buf) >= max_chunk:
            window = bytes(buf[:max_chunk])
            cut = cut_fn(window)
            if cut <= 0:
                cut = max_chunk
            chunks.append(window[:cut])
            del buf[:cut]

    cur = 0
    with fpath.open("rb") as fh:
        for off, length, sha in spans:
            if off < cur or off + length > orig_size:
                raise MediaStageError("invalid MKV attachment span bounds")
            rem = off - cur
            while rem > 0:
                piece = fh.read(min(rem, chunk_size))
                if not piece:
                    raise MediaStageError("unexpected EOF reading MKV skeleton")
                hasher.update(piece)
                _push_skel(piece)
                rem -= len(piece)
            att = fh.read(length)
            if len(att) != length or hashlib.sha256(att).hexdigest() != sha:
                raise MediaStageError("MKV attachment SHA-256 changed during pack")
            hasher.update(att)
            cur = off + length
        while True:
            piece = fh.read(chunk_size)
            if not piece:
                break
            hasher.update(piece)
            _push_skel(piece)

    while buf:
        if len(buf) <= min_chunk:
            chunks.append(bytes(buf))
            buf.clear()
        else:
            window = bytes(buf)
            cut = cut_fn(window)
            if cut <= 0:
                cut = len(window)
            chunks.append(window[:cut])
            del buf[:cut]

    return chunks, skel_total, hasher.hexdigest(), orig_size


def rebuild_mkv_stream(
    skeleton_chunks: Iterable[bytes],
    spans: list[list[Any]],
    get_asset: Callable[[str], bytes],
    emit: Callable[[bytes], None],
) -> int:
    """Stream-rebuild an MKV from skeleton chunks + `media_assets` spans.

    Calls `emit(chunk)` in exact file order and returns total written byte count.
    """
    if not isinstance(spans, list):
        raise MediaStageError("malformed MKV attachment spans list")
    # Validate sorted non-overlapping spans up front.
    parsed_spans: list[tuple[int, int, str]] = []
    prev_end = 0
    for item in spans:
        if not isinstance(item, (list, tuple)) or len(item) != 3:
            raise MediaStageError("malformed MKV attachment span entry")
        try:
            off, length, sha = int(item[0]), int(item[1]), str(item[2])
        except (ValueError, TypeError) as exc:
            raise MediaStageError("invalid MKV attachment span values") from exc
        if off < prev_end or length <= 0:
            raise MediaStageError("overlapping or empty MKV attachment span")
        parsed_spans.append((off, length, sha))
        prev_end = off + length

    chunk_iter = iter(skeleton_chunks)
    cur_buf = b""
    cur_pos = 0

    def take_skel(n: int) -> None:
        nonlocal cur_buf, cur_pos
        need = n
        while need > 0:
            if cur_pos >= len(cur_buf):
                try:
                    cur_buf = next(chunk_iter)
                except StopIteration as exc:
                    raise MediaStageError("MKV skeleton truncated before span") from exc
                cur_pos = 0
                if not cur_buf:
                    continue
            avail = len(cur_buf) - cur_pos
            step = min(need, avail)
            emit(cur_buf[cur_pos : cur_pos + step])
            cur_pos += step
            need -= step

    written = 0
    out_pos = 0
    for off, length, sha in parsed_spans:
        gap = off - out_pos
        if gap:
            take_skel(gap)
            written += gap
            out_pos += gap
        blob = get_asset(sha)
        if len(blob) != length:
            raise MediaStageError(
                f"MKV asset {sha[:12]} length mismatch (got {len(blob)}, expected {length})"
            )
        emit(blob)
        written += length
        out_pos += length

    # Emit remaining skeleton tail.
    if cur_pos < len(cur_buf):
        tail = cur_buf[cur_pos:]
        emit(tail)
        written += len(tail)
    for rem_chunk in chunk_iter:
        if rem_chunk:
            emit(rem_chunk)
            written += len(rem_chunk)
    return written
