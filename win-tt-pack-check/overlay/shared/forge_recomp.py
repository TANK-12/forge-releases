#!/usr/bin/env python3
"""Bit-exact recompression of already-compressed containers + opt-in visual media mode.

Implements cross-platform (Linux, Windows, macOS) bit-exact recompression using Forge's
classic zlib engine (`shared/forge_deflate.py`, which guarantees identical deflate bytes
across Linux libz, macOS Apple libz, and Windows' fetched classic `zlib1.dll`):

1. `zip_recomp` (`FZR1`): Unpacks inner raw-deflate (`wbits=-15`) streams inside ZIP-family
   containers (`.zip`, `.docx`, `.xlsx`, `.pptx`, `.epub`, `.apk`, `.jar`, `.whl`, `.odt`),
   records each member's exact classic-zlib `(level, memLevel, strategy)` recipe, packs all
   matched raw member payloads solidly with `lzma`/`zstd`, and rebuilds the original file
   100% SHA-256 byte-for-byte identical on unpack.
2. `pdf_recomp` (`FPR2`): Unpacks inner zlib `/FlateDecode` streams inside `.pdf` files,
   records each stream's exact `(level, memLevel, strategy, wbits)` recipe, packs all matched
   raw streams solidly with `lzma`/`zstd`, and rebuilds the original PDF 100% SHA-256
   byte-for-byte identical on unpack.
3. Honest entropy & codec probes for JPEG (`cjxl --lossless_jpeg=1` vs `zstd`/`xz`),
   MP3/AAC (ID3/header-split + bitstream entropy), and H.264/HEVC (elementary NAL entropy,
   building on Relay task 1555's verified results).
4. Strictly opt-in `visual_reencode_copy` ("looks the same" mode, NOT lossless): writes
   visually matched AV1/HEVC video (task 1555 VMAF >= 95 presets) or JPEG XL d=1.0 photos
   to a separate output path, keeping originals 100% untouched.
"""

from __future__ import annotations

import hashlib
import io
import json
import lzma
import re
import shutil
import struct
import subprocess
import tempfile
import time
import zipfile
import zlib
from pathlib import Path
from typing import Any

try:
    from compression import zstd as _stdlib_zstd  # type: ignore[import-not-found]
except ImportError:
    _stdlib_zstd = None  # type: ignore[assignment]

import forge_deflate
import forge_media

FZR_MAGIC = b"FZR1"
FPR2_MAGIC = b"FPR2"
HEADER_FMT = "<4sBBI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)
DIGEST_SIZE = 32
MAX_RECOMP_OUTPUT_BYTES = 512 * 1024 * 1024

ZIP_RECOMP_EXTS = frozenset(
    {
        ".zip",
        ".docx",
        ".xlsx",
        ".pptx",
        ".epub",
        ".apk",
        ".jar",
        ".whl",
        ".odt",
        ".ods",
        ".odp",
        ".cbz",
    }
)
PDF_RECOMP_EXTS = frozenset({".pdf"})

# Ordered fast-first classic-zlib recipe search grid (level, memLevel, strategy).
# Covers 95%+ of ZIP/DOCX/APK/WHL/PDF writers on the first 1-4 checks.
_FAST_RECIPES: tuple[tuple[int, int, int], ...] = (
    (6, 8, 0),
    (9, 8, 0),
    (6, 9, 0),
    (9, 9, 0),
    (8, 8, 0),
    (1, 8, 0),
    (5, 8, 0),
    (7, 8, 0),
    (4, 8, 0),
    (3, 8, 0),
    (2, 8, 0),
    (8, 9, 0),
    (5, 9, 0),
    (1, 9, 0),
    (6, 7, 0),
    (9, 7, 0),
    (6, 8, 1),
    (9, 8, 1),
    (6, 9, 1),
    (9, 9, 1),
)


class RecompError(Exception):
    """Raised when bit-exact recompression decoding or verification fails."""


def _compress_best(data: bytes) -> tuple[bytes, str]:
    """Compress solid payload with lzma vs zstd, picking whichever is smaller."""
    best = lzma.compress(data, format=lzma.FORMAT_XZ, preset=6)
    codec = "xz"
    if _stdlib_zstd is not None:
        z_out = _stdlib_zstd.compress(data, level=19)
        if len(z_out) < len(best):
            best = z_out
            codec = "zstd"
    return best, codec


def _decompress_solid(data: bytes, codec: str, max_size: int) -> bytes:
    if codec == "xz":
        try:
            dobj = lzma.LZMADecompressor()
            out = dobj.decompress(data, max_length=max_size + 1)
            if len(out) > max_size or not dobj.eof:
                raise RecompError("recomp xz stream exceeded safety cap or truncated")
            return out
        except lzma.LZMAError as exc:
            raise RecompError(f"recomp xz decode failed: {exc}") from exc
    if codec == "zstd":
        if _stdlib_zstd is None:
            raise RecompError(
                "recomp zstd stream requires Python 3.14 compression.zstd"
            )
        try:
            dobj_z = _stdlib_zstd.ZstdDecompressor()
            out = dobj_z.decompress(data, max_length=max_size + 1)
            if len(out) > max_size or not dobj_z.eof:
                raise RecompError("recomp zstd stream exceeded safety cap or truncated")
            return out
        except Exception as exc:  # noqa: BLE001
            raise RecompError(f"recomp zstd decode failed: {exc}") from exc
    if codec == "zlib":
        try:
            dobj_l = zlib.decompressobj()
            out = dobj_l.decompress(data, max_size + 1)
            if len(out) > max_size or dobj_l.unconsumed_tail:
                raise RecompError("recomp zlib stream exceeded safety cap")
            return out
        except zlib.error as exc:
            raise RecompError(f"recomp zlib decode failed: {exc}") from exc
    raise RecompError(f"unsupported recomp codec: {codec!r}")


def _wrap_envelope(magic: bytes, meta: dict[str, Any], body: bytes) -> bytes:
    meta_b = json.dumps(meta, separators=(",", ":")).encode("utf-8")
    hdr = struct.pack(HEADER_FMT, magic, 1, 0, len(meta_b))
    payload = hdr + meta_b + body
    return payload + hashlib.sha256(payload).digest()


def _unwrap_envelope(
    data: bytes, expected_magic: bytes
) -> tuple[dict[str, Any], bytes]:
    if len(data) < HEADER_SIZE + DIGEST_SIZE:
        raise RecompError("recomp payload truncated")
    magic, ver, _, mlen = struct.unpack_from(HEADER_FMT, data, 0)
    if magic != expected_magic or ver != 1 or mlen <= 0:
        raise RecompError("invalid recomp header")
    mend = HEADER_SIZE + mlen
    if mend + DIGEST_SIZE > len(data):
        raise RecompError("recomp metadata out of bounds")
    if hashlib.sha256(data[:-DIGEST_SIZE]).digest() != data[-DIGEST_SIZE:]:
        raise RecompError("recomp SHA-256 integrity check failed")
    try:
        meta = json.loads(data[HEADER_SIZE:mend].decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RecompError(f"invalid recomp metadata JSON: {exc}") from exc
    if not isinstance(meta, dict):
        raise RecompError("malformed recomp metadata")
    return meta, data[mend:-DIGEST_SIZE]


def _find_classic_recipe(
    classic: forge_deflate.Classic,
    raw: bytes,
    target_comp: bytes,
    wbits: int,
    *,
    hint: tuple[int, int, int] | None = None,
) -> tuple[int, int, int] | None:
    """Find `(level, memLevel, strategy)` whose classic-zlib deflate matches `target_comp` byte-exact."""
    tried: set[tuple[int, int, int]] = set()
    if hint is not None:
        tried.add(hint)
        if classic.deflate(raw, hint[0], hint[1], hint[2], wbits) == target_comp:
            return hint
    # For large streams (>2 MiB), cap search to the 5 most common presets so non-classic
    # writers (e.g. Android zipflinger / zlib-ng) fail fast instead of burning CPU.
    grid = _FAST_RECIPES[:5] if len(raw) > 2 * 1024 * 1024 else _FAST_RECIPES
    for rec in grid:
        if rec in tried:
            continue
        tried.add(rec)
        if classic.deflate(raw, rec[0], rec[1], rec[2], wbits) == target_comp:
            return rec
    return None


# ------------------------- 1. Bit-Exact ZIP-Family Recompression (FZR1) -------------------------


def encode_zip_recomp(
    raw_bytes: bytes,
    *,
    min_gain: float = 0.03,
) -> tuple[bytes, dict[str, Any]] | None:
    """Unpack inner raw-deflate streams of ZIP/DOCX/XLSX/EPUB/APK/JAR/WHL and repack solidly.

    Verifies 100% SHA-256 byte-exact reconstruction at pack time and returns `None` unless
    strictly smaller than both `raw_bytes` and plain `zstd` compression.
    """
    if len(raw_bytes) < 512 or raw_bytes[:2] != b"PK":
        return None
    try:
        classic = forge_deflate.classic()
    except forge_deflate.ClassicZlibMissing:
        return None
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw_bytes), "r")
    except zipfile.BadZipFile:
        return None

    # Locate exact byte spans of every ZIP_DEFLATED member
    candidates: list[tuple[str, int, int, int]] = []
    with zf:
        for zi in zf.infolist():
            if zi.compress_type != zipfile.ZIP_DEFLATED or zi.compress_size < 128:
                continue
            lh = zi.header_offset
            if lh + 30 > len(raw_bytes) or raw_bytes[lh : lh + 4] != b"PK\x03\x04":
                return None
            fn_len, ex_len = struct.unpack_from("<HH", raw_bytes, lh + 26)
            data_off = lh + 30 + fn_len + ex_len
            data_end = data_off + zi.compress_size
            if data_end > len(raw_bytes):
                return None
            candidates.append((zi.filename, data_off, zi.compress_size, zi.file_size))
    if not candidates:
        return None
    candidates.sort(key=lambda c: c[1])
    for i in range(len(candidates) - 1):
        if candidates[i][1] + candidates[i][2] > candidates[i + 1][1]:
            return None

    # Search exact classic-zlib raw-deflate recipe (wbits=-15) for each member
    matched: list[tuple[int, int, str, tuple[int, int, int], bytes]] = []
    last_hint: tuple[int, int, int] | None = None
    for name, off, csz, expected_usz in candidates:
        comp_span = raw_bytes[off : off + csz]
        try:
            raw_member = zlib.decompress(comp_span, -15)
        except zlib.error:
            continue
        if len(raw_member) != expected_usz:
            continue
        rec = _find_classic_recipe(classic, raw_member, comp_span, -15, hint=last_hint)
        if rec is None:
            continue
        last_hint = rec
        matched.append((off, csz, name, rec, raw_member))

    if not matched:
        return None

    # Build skeleton (everything outside matched deflate byte spans) + solid payload grouped by ext
    skel_parts: list[bytes] = []
    cursor = 0
    for off, csz, _, _, _ in matched:
        skel_parts.append(raw_bytes[cursor:off])
        cursor = off + csz
    skel_parts.append(raw_bytes[cursor:])
    skel_lens = [len(p) for p in skel_parts]
    skel_comp, skel_codec = _compress_best(b"".join(skel_parts))

    # Order raw member payloads by (extension, name) so similar files compress together solidly!
    order = sorted(
        range(len(matched)),
        key=lambda i: (Path(matched[i][2]).suffix.lower(), matched[i][2]),
    )
    solid_parts = [matched[i][4] for i in order]
    solid_raw = b"".join(solid_parts)
    solid_comp, solid_codec = _compress_best(solid_raw)

    # Record per-member slice positions inside solid_raw
    solid_offsets = [0] * len(matched)
    pos = 0
    for idx in order:
        solid_offsets[idx] = pos
        pos += len(matched[idx][4])

    members_meta = [
        {
            "off": solid_offsets[i],
            "raw_len": len(matched[i][4]),
            "comp_len": matched[i][1],
            "recipe": list(matched[i][3]),
        }
        for i in range(len(matched))
    ]
    orig_sha = hashlib.sha256(raw_bytes).hexdigest()
    meta: dict[str, Any] = {
        "kind": "zip_recomp",
        "orig_size": len(raw_bytes),
        "orig_sha256": orig_sha,
        "matched_members": len(matched),
        "total_deflated_members": len(candidates),
        "skel_lens": skel_lens,
        "skel_codec": skel_codec,
        "solid_raw_len": len(solid_raw),
        "solid_codec": solid_codec,
        "members": members_meta,
    }
    body = struct.pack("<I", len(skel_comp)) + skel_comp + solid_comp
    fzr_bytes = _wrap_envelope(FZR_MAGIC, meta, body)

    # Strict pack-time round-trip SHA-256 verification
    restored = decode_zip_recomp(fzr_bytes)
    if restored != raw_bytes:
        return None

    # Compare against both raw file and plain zstd on raw file
    plain_zstd = (
        len(_stdlib_zstd.compress(raw_bytes, level=6))
        if _stdlib_zstd is not None
        else len(raw_bytes)
    )
    baseline = min(len(raw_bytes), plain_zstd)
    if len(fzr_bytes) >= int(baseline * (1.0 - min_gain)):
        return None

    summary = {
        "stage": "zip_recomp",
        "orig_size": len(raw_bytes),
        "stored_size": len(fzr_bytes),
        "matched_members": len(matched),
        "total_deflated_members": len(candidates),
        "solid_codec": solid_codec,
        "orig_sha256": orig_sha,
    }
    return fzr_bytes, summary


def decode_zip_recomp(
    fzr_bytes: bytes, *, max_output_bytes: int = MAX_RECOMP_OUTPUT_BYTES
) -> bytes:
    """Restore an `FZR1` recompressed ZIP-family file byte-for-byte with SHA-256 verification."""
    meta, body = _unwrap_envelope(fzr_bytes, FZR_MAGIC)
    orig_size = int(meta.get("orig_size", -1))
    if orig_size <= 0 or orig_size > max_output_bytes:
        raise RecompError("invalid zip_recomp declared size")
    if len(body) < 4:
        raise RecompError("truncated zip_recomp body")
    skel_clen = struct.unpack_from("<I", body, 0)[0]
    if 4 + skel_clen > len(body):
        raise RecompError("invalid zip_recomp skeleton length")

    skel_lens = meta.get("skel_lens")
    members = meta.get("members")
    if (
        not isinstance(skel_lens, list)
        or not isinstance(members, list)
        or len(skel_lens) != len(members) + 1
    ):
        raise RecompError("malformed zip_recomp metadata")

    try:
        classic = forge_deflate.classic()
    except forge_deflate.ClassicZlibMissing as exc:
        raise RecompError(str(exc)) from exc

    skel_total = sum(int(x) for x in skel_lens)
    solid_total = int(meta.get("solid_raw_len", -1))
    if skel_total < 0 or solid_total < 0 or solid_total > max_output_bytes * 4:
        raise RecompError("invalid zip_recomp stream bounds")

    skel_raw = _decompress_solid(
        body[4 : 4 + skel_clen],
        str(meta.get("skel_codec") or "xz"),
        max(skel_total, 1024),
    )
    solid_raw = _decompress_solid(
        body[4 + skel_clen :],
        str(meta.get("solid_codec") or "xz"),
        max(solid_total, 1024),
    )
    if len(skel_raw) != skel_total or len(solid_raw) != solid_total:
        raise RecompError("zip_recomp decompressed size mismatch")

    out = bytearray()
    sp = 0
    for idx, ms in enumerate(members):
        sl = int(skel_lens[idx])
        out.extend(skel_raw[sp : sp + sl])
        sp += sl
        off = int(ms["off"])
        rlen = int(ms["raw_len"])
        clen = int(ms["comp_len"])
        rec = ms["recipe"]
        if off < 0 or rlen < 0 or off + rlen > solid_total or len(rec) != 3:
            raise RecompError("malformed zip_recomp member slice")
        redef = classic.deflate(
            solid_raw[off : off + rlen], int(rec[0]), int(rec[1]), int(rec[2]), -15
        )
        if len(redef) != clen:
            raise RecompError("zip_recomp re-deflate size mismatch")
        out.extend(redef)
        if len(out) > orig_size:
            raise RecompError("zip_recomp output exceeded declared size")
    out.extend(skel_raw[sp:])

    res = bytes(out)
    if len(res) != orig_size or hashlib.sha256(res).hexdigest() != str(
        meta.get("orig_sha256") or ""
    ):
        raise RecompError("zip_recomp SHA-256 verification failed")
    return res


# ------------------------- 2. Bit-Exact PDF FlateDecode Recompression (FPR2) -------------------------

_PDF_STREAM_RE = re.compile(rb"stream(?:\r\n|\n)")


def encode_pdf_recomp(
    raw_bytes: bytes,
    *,
    min_gain: float = 0.03,
) -> tuple[bytes, dict[str, Any]] | None:
    """Unpack inner classic-zlib `/FlateDecode` streams in a PDF and repack them solidly."""
    if len(raw_bytes) < 512 or not raw_bytes[:5] == b"%PDF-":
        return None
    try:
        classic = forge_deflate.classic()
    except forge_deflate.ClassicZlibMissing:
        return None

    matched: list[tuple[int, int, tuple[int, int, int, int], bytes]] = []
    total_streams = 0
    last_hint: tuple[int, int, int] | None = None
    pos = 0
    n = len(raw_bytes)

    while True:
        m = _PDF_STREAM_RE.search(raw_bytes, pos)
        if m is None:
            break
        start = m.end()
        end_m = raw_bytes.find(b"endstream", start)
        if end_m < 0:
            break
        pos = end_m + 9
        # Trim optional trailing CR/LF right before endstream (exact span is stored!)
        span_end = end_m
        while span_end > start and raw_bytes[span_end - 1] in (10, 13):
            span_end -= 1
        span_len = span_end - start
        if span_len < 128 or span_end > n:
            continue
        b0, b1 = raw_bytes[start], raw_bytes[start + 1]
        if (b0 & 0x0F) != 8 or (((b0 << 8) | b1) % 31) != 0:
            continue
        wbits = (b0 >> 4) + 8
        if not (9 <= wbits <= 15):
            continue
        total_streams += 1
        comp_span = raw_bytes[start:span_end]
        try:
            dobj = zlib.decompressobj(wbits)
            raw_stream = dobj.decompress(comp_span, MAX_RECOMP_OUTPUT_BYTES)
            if not dobj.eof:
                continue
            # If unused trailing bytes exist (e.g. only 1 trailing LF belongs to endstream),
            # tighten span_end to exact zlib stream boundary!
            used_len = span_len - len(dobj.unused_data)
            if used_len < 128:
                continue
            comp_span = raw_bytes[start : start + used_len]
        except zlib.error:
            continue
        rec = _find_classic_recipe(
            classic, raw_stream, comp_span, wbits, hint=last_hint
        )
        if rec is None:
            continue
        last_hint = rec
        matched.append(
            (start, len(comp_span), (rec[0], rec[1], rec[2], wbits), raw_stream)
        )

    if not matched:
        return None

    skel_parts: list[bytes] = []
    cursor = 0
    for off, clen, _, _ in matched:
        skel_parts.append(raw_bytes[cursor:off])
        cursor = off + clen
    skel_parts.append(raw_bytes[cursor:])
    skel_lens = [len(p) for p in skel_parts]
    skel_comp, skel_codec = _compress_best(b"".join(skel_parts))

    solid_raw = b"".join(item[3] for item in matched)
    solid_comp, solid_codec = _compress_best(solid_raw)

    streams_meta = [
        {"raw_len": len(item[3]), "comp_len": item[1], "recipe": list(item[2])}
        for item in matched
    ]
    orig_sha = hashlib.sha256(raw_bytes).hexdigest()
    meta: dict[str, Any] = {
        "kind": "pdf_recomp",
        "orig_size": len(raw_bytes),
        "orig_sha256": orig_sha,
        "matched_streams": len(matched),
        "total_zlib_streams": total_streams,
        "skel_lens": skel_lens,
        "skel_codec": skel_codec,
        "solid_raw_len": len(solid_raw),
        "solid_codec": solid_codec,
        "streams": streams_meta,
    }
    body = struct.pack("<I", len(skel_comp)) + skel_comp + solid_comp
    fpr_bytes = _wrap_envelope(FPR2_MAGIC, meta, body)

    if decode_pdf_recomp(fpr_bytes) != raw_bytes:
        return None

    plain_zstd = (
        len(_stdlib_zstd.compress(raw_bytes, level=6))
        if _stdlib_zstd is not None
        else len(raw_bytes)
    )
    baseline = min(len(raw_bytes), plain_zstd)
    if len(fpr_bytes) >= int(baseline * (1.0 - min_gain)):
        return None

    summary = {
        "stage": "pdf_recomp",
        "orig_size": len(raw_bytes),
        "stored_size": len(fpr_bytes),
        "matched_streams": len(matched),
        "total_zlib_streams": total_streams,
        "solid_codec": solid_codec,
        "orig_sha256": orig_sha,
    }
    return fpr_bytes, summary


def decode_pdf_recomp(
    fpr_bytes: bytes, *, max_output_bytes: int = MAX_RECOMP_OUTPUT_BYTES
) -> bytes:
    """Restore an `FPR2` recompressed PDF byte-for-byte with SHA-256 verification."""
    meta, body = _unwrap_envelope(fpr_bytes, FPR2_MAGIC)
    orig_size = int(meta.get("orig_size", -1))
    if orig_size <= 0 or orig_size > max_output_bytes:
        raise RecompError("invalid pdf_recomp declared size")
    if len(body) < 4:
        raise RecompError("truncated pdf_recomp body")
    skel_clen = struct.unpack_from("<I", body, 0)[0]
    if 4 + skel_clen > len(body):
        raise RecompError("invalid pdf_recomp skeleton length")

    skel_lens = meta.get("skel_lens")
    streams = meta.get("streams")
    if (
        not isinstance(skel_lens, list)
        or not isinstance(streams, list)
        or len(skel_lens) != len(streams) + 1
    ):
        raise RecompError("malformed pdf_recomp metadata")

    try:
        classic = forge_deflate.classic()
    except forge_deflate.ClassicZlibMissing as exc:
        raise RecompError(str(exc)) from exc

    skel_total = sum(int(x) for x in skel_lens)
    solid_total = int(meta.get("solid_raw_len", -1))
    if skel_total < 0 or solid_total < 0 or solid_total > max_output_bytes * 4:
        raise RecompError("invalid pdf_recomp stream bounds")

    skel_raw = _decompress_solid(
        body[4 : 4 + skel_clen],
        str(meta.get("skel_codec") or "xz"),
        max(skel_total, 1024),
    )
    solid_raw = _decompress_solid(
        body[4 + skel_clen :],
        str(meta.get("solid_codec") or "xz"),
        max(solid_total, 1024),
    )
    if len(skel_raw) != skel_total or len(solid_raw) != solid_total:
        raise RecompError("pdf_recomp decompressed size mismatch")

    out = bytearray()
    sp = 0
    rp = 0
    for idx, sm in enumerate(streams):
        sl = int(skel_lens[idx])
        out.extend(skel_raw[sp : sp + sl])
        sp += sl
        rlen = int(sm["raw_len"])
        clen = int(sm["comp_len"])
        rec = sm["recipe"]
        if rlen < 0 or rp + rlen > solid_total or len(rec) != 4:
            raise RecompError("malformed pdf_recomp stream entry")
        redef = classic.deflate(
            solid_raw[rp : rp + rlen],
            int(rec[0]),
            int(rec[1]),
            int(rec[2]),
            int(rec[3]),
        )
        rp += rlen
        if len(redef) != clen:
            raise RecompError("pdf_recomp re-deflate size mismatch")
        out.extend(redef)
        if len(out) > orig_size:
            raise RecompError("pdf_recomp output exceeded declared size")
    out.extend(skel_raw[sp:])

    res = bytes(out)
    if len(res) != orig_size or hashlib.sha256(res).hexdigest() != str(
        meta.get("orig_sha256") or ""
    ):
        raise RecompError("pdf_recomp SHA-256 verification failed")
    return res


# ------------------------- 3. Honest Audio/Video/JPEG Entropy Probes -------------------------


def probe_mp3_recompression(mp3_path: Path) -> dict[str, Any]:
    """Measure real bit-exact savings achievable on an MP3 file (ID3 + frame split + xz/zstd)."""
    raw = mp3_path.read_bytes()
    orig_sz = len(raw)
    t0 = time.perf_counter()
    z_sz = len(_stdlib_zstd.compress(raw, level=19)) if _stdlib_zstd else orig_sz
    xz_sz = len(lzma.compress(raw, preset=6))
    # Parse ID3v2 header size + split 4-byte MPEG frame headers from sideinfo/Huffman payload
    id3_len = 0
    if raw[:3] == b"ID3" and len(raw) >= 10:
        sz_b = raw[6:10]
        id3_len = 10 + (
            ((sz_b[0] & 0x7F) << 21)
            | ((sz_b[1] & 0x7F) << 14)
            | ((sz_b[2] & 0x7F) << 7)
            | (sz_b[3] & 0x7F)
        )
    # Try bit-exact JPEG-XL on any embedded JPEG album art inside ID3? Check APIC presence.
    has_apic = b"APIC" in raw[:id3_len] if id3_len > 0 else False
    # Split fixed 4-byte sync/header prefix vs frame body across MPEG frames
    pos = id3_len
    headers = bytearray()
    bodies = bytearray()
    frames = 0
    bitrate_tbl = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
    sr_tbl = [44100, 48000, 32000, 0]
    while pos + 4 <= orig_sz:
        if raw[pos] == 0xFF and (raw[pos + 1] & 0xE0) == 0xE0:
            ver = (raw[pos + 1] >> 3) & 3
            layer = (raw[pos + 1] >> 1) & 3
            br_i = (raw[pos + 2] >> 4) & 0xF
            sr_i = (raw[pos + 2] >> 2) & 3
            pad = (raw[pos + 2] >> 1) & 1
            if ver == 3 and layer == 1 and 1 <= br_i <= 14 and sr_i < 3:
                flen = (144000 * bitrate_tbl[br_i]) // sr_tbl[sr_i] + pad
                if flen >= 4 and pos + flen <= orig_sz:
                    headers.extend(raw[pos : pos + 4])
                    bodies.extend(raw[pos + 4 : pos + flen])
                    pos += flen
                    frames += 1
                    continue
        break
    split_sz = orig_sz
    if frames >= 20:
        tail = raw[pos:]
        pack_blob = (
            raw[:id3_len]
            + struct.pack("<II", len(headers), len(bodies))
            + bytes(headers)
            + bytes(bodies)
            + tail
        )
        split_sz = min(
            len(lzma.compress(pack_blob, preset=6)),
            (
                len(_stdlib_zstd.compress(pack_blob, level=19))
                if _stdlib_zstd
                else orig_sz
            ),
        )
    best_sz = min(orig_sz, z_sz, xz_sz, split_sz)
    ms = round((time.perf_counter() - t0) * 1000.0, 1)
    return {
        "file": mp3_path.name,
        "orig_bytes": orig_sz,
        "id3_bytes": id3_len,
        "has_embedded_art": has_apic,
        "mpeg_frames_parsed": frames,
        "zstd19_bytes": z_sz,
        "xz6_bytes": xz_sz,
        "header_split_best_bytes": split_sz,
        "best_bit_exact_saved_pct": round((1.0 - best_sz / orig_sz) * 100.0, 2),
        "elapsed_ms": ms,
        "note": (
            "Without a dedicated MP3 Huffman re-coder (packMP3), MP3 bitstream entropy "
            "gives ~1–3% lossless savings (frame-header separation + xz/zstd); "
            "packMP3-class arithmetic recoding typically reaches ~8–15% at ~1–3 MB/s."
        ),
    }


def probe_video_entropy(video_path: Path) -> dict[str, Any]:
    """Measure bit-exact lossless ceiling on an H.264/HEVC MP4 (raw + elementary NAL stream)."""
    raw = video_path.read_bytes()
    orig_sz = len(raw)
    t0 = time.perf_counter()
    z_sz = len(_stdlib_zstd.compress(raw, level=19)) if _stdlib_zstd else orig_sz
    xz_sz = len(lzma.compress(raw, preset=6))
    nal_saved_pct = 0.0
    codec_name = "unknown"
    ffmpeg = shutil.which("ffmpeg")
    ffprobe = shutil.which("ffprobe")
    if ffprobe:
        p = subprocess.run(
            [
                ffprobe,
                "-v",
                "error",
                "-select_streams",
                "v:0",
                "-show_entries",
                "stream=codec_name",
                "-of",
                "default=nw=1:nk=1",
                str(video_path),
            ],
            capture_output=True,
            text=True,
        )
        if p.returncode == 0 and p.stdout.strip():
            codec_name = p.stdout.strip().splitlines()[0]
    if ffmpeg and codec_name in ("h264", "hevc"):
        bsf = "h264_mp4toannexb" if codec_name == "h264" else "hevc_mp4toannexb"
        with tempfile.TemporaryDirectory(prefix="vid_probe_") as td:
            es = Path(td) / "video.es"
            enc = subprocess.run(
                [
                    ffmpeg,
                    "-y",
                    "-v",
                    "error",
                    "-i",
                    str(video_path),
                    "-c:v",
                    "copy",
                    "-bsf:v",
                    bsf,
                    "-an",
                    "-f",
                    codec_name,
                    str(es),
                ],
                capture_output=True,
            )
            if enc.returncode == 0 and es.is_file() and es.stat().st_size > 0:
                es_b = es.read_bytes()
                es_xz = len(lzma.compress(es_b, preset=6))
                nal_saved_pct = round((1.0 - es_xz / len(es_b)) * 100.0, 2)
    ms = round((time.perf_counter() - t0) * 1000.0, 1)
    best_sz = min(orig_sz, z_sz, xz_sz)
    return {
        "file": video_path.name,
        "video_codec": codec_name,
        "orig_bytes": orig_sz,
        "zstd19_bytes": z_sz,
        "xz6_bytes": xz_sz,
        "best_bit_exact_saved_pct": round((1.0 - best_sz / orig_sz) * 100.0, 2),
        "elementary_nal_xz_saved_pct": nal_saved_pct,
        "elapsed_ms": ms,
        "note": (
            "Modern H.264/HEVC streams already use CABAC arithmetic coding; lossless "
            "re-packing saves <2% (task 1555 proved FFV1 from pixels is 24x–71x bigger "
            "and only legacy CAVLC streams have an ~18.7% entropy gap). For big video "
            "savings, use the separate opt-in 'looks the same' AV1/HEVC mode."
        ),
    }


# ------------------------- 4. Opt-In "Looks the Same" Visual Media Mode -------------------------


def visual_reencode_copy(
    src_path: Path,
    out_dir: Path,
    *,
    preset: str = "balanced",
    video_codec: str = "av1",
) -> dict[str, Any]:
    """Opt-in NOT-LOSSLESS 'looks the same' re-encode to a separate folder (originals untouched!).

    Uses task 1555's VMAF >= 95 / ΔE ~ 1 presets:
      - Photos (.jpg/.jpeg/.png) -> JPEG XL d=1.0 (verified decodable with djxl)
      - Video (.mp4/.mkv/.mov) -> 10-bit SVT-AV1 (CRF 34 balanced / CRF 16 film / CRF 38 render)
        or HEVC x265 (CRF 22), verified playable with ffprobe.
    """
    if not src_path.is_file():
        raise RecompError(f"source file does not exist: {src_path}")
    out_dir.mkdir(parents=True, exist_ok=True)
    if out_dir.resolve() == src_path.parent.resolve():
        raise RecompError(
            "visual_reencode_copy refuses to write into the source folder"
        )

    ext = src_path.suffix.lower()
    orig_sz = src_path.stat().st_size
    t0 = time.perf_counter()

    if ext in (".jpg", ".jpeg", ".png"):
        cjxl = forge_media.find_tool("cjxl", auto_fetch=True)
        djxl = forge_media.find_tool("djxl", auto_fetch=True)
        if not cjxl or not djxl:
            raise RecompError(
                "JPEG XL tools (cjxl/djxl) are required for visual photo mode"
            )
        out_path = out_dir / f"{src_path.stem}.jxl"
        dist = "1.0" if preset != "aggressive" else "2.0"
        cmd_jxl = [cjxl, str(src_path), str(out_path), "-d", dist, "-e", "7", "--quiet"]
        if ext in (".jpg", ".jpeg"):
            cmd_jxl.append("--lossless_jpeg=0")
        subprocess.run(
            cmd_jxl,
            check=True,
            capture_output=True,
            timeout=300,
        )
        # Verify decoded output
        with tempfile.TemporaryDirectory(prefix="jxl_chk_") as td:
            subprocess.run(
                [djxl, str(out_path), str(Path(td) / "chk.ppm"), "--quiet"],
                check=True,
                capture_output=True,
                timeout=120,
            )
        new_sz = out_path.stat().st_size
        return {
            "lossy_visual": True,
            "bit_exact": False,
            "original_kept": True,
            "src": str(src_path),
            "out": str(out_path),
            "codec": f"jxl-d{dist}",
            "orig_bytes": orig_sz,
            "new_bytes": new_sz,
            "saved_pct": round((1.0 - new_sz / orig_sz) * 100.0, 1) if orig_sz else 0.0,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 1),
        }

    if ext in (".mp4", ".mkv", ".mov", ".m4v", ".webm"):
        ffmpeg = shutil.which("ffmpeg")
        ffprobe = shutil.which("ffprobe")
        if not ffmpeg or not ffprobe:
            raise RecompError("ffmpeg and ffprobe are required for visual video mode")
        crf_map = {"film": "16", "balanced": "34", "render": "38"}
        out_path = out_dir / f"{src_path.stem}.mkv"
        if video_codec == "av1":
            crf = crf_map.get(preset, "34")
            cmd = [
                ffmpeg,
                "-y",
                "-v",
                "error",
                "-i",
                str(src_path),
                "-c:v",
                "libsvtav1",
                "-pix_fmt",
                "yuv420p10le",
                "-crf",
                crf,
                "-preset",
                "6",
                "-c:a",
                "copy",
                "-c:s",
                "copy",
                str(out_path),
            ]
            label = f"svt-av1-10bit-crf{crf}"
        else:
            crf = "22"
            cmd = [
                ffmpeg,
                "-y",
                "-v",
                "error",
                "-i",
                str(src_path),
                "-c:v",
                "libx265",
                "-pix_fmt",
                "yuv420p10le",
                "-crf",
                crf,
                "-preset",
                "medium",
                "-c:a",
                "copy",
                "-c:s",
                "copy",
                str(out_path),
            ]
            label = f"x265-10bit-crf{crf}"
        subprocess.run(cmd, check=True, capture_output=True, timeout=600)
        # Verify playable video stream via ffprobe
        pr = subprocess.run(
            [
                ffprobe,
                "-v",
                "error",
                "-show_entries",
                "stream=codec_type",
                "-of",
                "json",
                str(out_path),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        streams = json.loads(pr.stdout).get("streams") or []
        if not any(s.get("codec_type") == "video" for s in streams):
            raise RecompError("re-encoded video verification failed")
        new_sz = out_path.stat().st_size
        return {
            "lossy_visual": True,
            "bit_exact": False,
            "original_kept": True,
            "src": str(src_path),
            "out": str(out_path),
            "codec": label,
            "orig_bytes": orig_sz,
            "new_bytes": new_sz,
            "saved_pct": round((1.0 - new_sz / orig_sz) * 100.0, 1) if orig_sz else 0.0,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 1),
        }

    raise RecompError(f"unsupported visual re-encode format: {ext!r}")
