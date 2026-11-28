#!/usr/bin/env python3
"""Forge Pack Standalone Unpacker (Windows & Linux, zero Forge installation required).

Anyone can inspect, verify, or unpack `.fpack` and `.fvlt` archives using only
standard Python 3 — no Forge install, no C compiler, and no third-party packages
required for unencrypted `.fpack` packs created with Fast / Ultra-fast profiles.

Acceleration:
  - If `libforge_vault.so` (Linux) or `forge_vault.dll` (Windows) is present
    beside this script or in `../../../shared/vault/`, native C codecs & crypto
    run automatically at 500-7,000+ MB/s.
  - Otherwise, the built-in pure-Python reference implementation of the
    `FVLT0001` v1 specification (`Raw`, `Selkie-SIMD`, `Phrase-Selkie`,
    `Kraken-Huff4`, `Kraken-tANS4`, `Plane-AVX2`, and `BLAKE3`) runs directly
    on Windows, Linux, and macOS with zero dependencies.

Usage:
    python forge_unpack.py info archive.fpack
    python forge_unpack.py verify archive.fpack
    python forge_unpack.py unpack archive.fpack ./restored
    python forge_unpack.py unpack archive.fpack ./restored --pure-python
"""

from __future__ import annotations

import argparse
import bisect
import ctypes
import getpass
import hashlib
import json
import lzma
import math
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

MAGIC = b"FVLT0001"
FOOTER_MAGIC = b"FVTE"
HEADER_FMT = "<8sBBBBIII16sQ"
HEADER_SIZE = struct.calcsize(HEADER_FMT)
CHUNK_HDR_FMT = "<32sBBIBI"
CHUNK_HDR_SIZE = struct.calcsize(CHUNK_HDR_FMT)
MANIFEST_PREFIX_FMT = "<BI"
MANIFEST_PREFIX_SIZE = struct.calcsize(MANIFEST_PREFIX_FMT)
FOOTER_FMT = "<Q4s"
FOOTER_SIZE = struct.calcsize(FOOTER_FMT)

HEADER_FLAG_MANIFEST_KRAKEN = 0x02
HEADER_FLAG_HAS_MEDIA = 0x04
HEADER_FLAG_HAS_TENSOR = 0x08
CHUNK_FLAG_USED_DICT = 0x01
MAX_CHUNK_RAW_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_PLAIN_BYTES = 128 * 1024 * 1024
MAX_PNG_PIXEL_BYTES = 256 * 1024 * 1024
MAX_PNG_RECIPE_HEADER_BYTES = 64 * 1024 * 1024
MAX_MP4_TABLE_BYTES = 64 * 1024 * 1024
PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_RECIPE_MAGIC = b"FPR1"
MP4_DEDUP_MAGIC = b"FMP1"
FV_HIST_SIZE = 65536
FV_BLOCK_SIZE = 262144
FV_PLANE_BLOCK_SIZE = 524288

CODEC_RAW = 0
CODEC_SIMD_SELKIE = 1
CODEC_PHRASE_SELKIE = 2
CODEC_KRAKEN_HUFF8 = 3
CODEC_KRAKEN_TANS8 = 4
CODEC_AVX2_PLANE = 5
CODEC_ZSTD_FAST = 6
CODEC_ZSTD_MAX = 7
CODEC_AVX2_PLANE_ZSTD = 8

CIPHER_NONE = 0
CIPHER_AES256GCM = 1
CIPHER_XCHACHA20 = 2
CIPHER_NAMES = {0: "none", 1: "aes256gcm", 2: "xchacha20"}
PROFILE_NAMES = {0: "ultra_fast", 1: "fast", 2: "balanced", 3: "max"}


class UnpackError(Exception):
    """Raised on corrupt, tampered, or unsupported pack files."""


# -------------------------- Pure-Python Reference BLAKE3 --------------------------

_B3_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
_B3_MSG_PERM = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
_B3_CHUNK_START = 1 << 0
_B3_CHUNK_END = 1 << 1
_B3_PARENT = 1 << 2
_B3_ROOT = 1 << 3
_B3_KEYED_HASH = 1 << 4


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)) & 0xFFFFFFFF


def _b3_g(s: list[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    s[a] = (s[a] + s[b] + mx) & 0xFFFFFFFF
    s[d] = _rotr32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotr32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & 0xFFFFFFFF
    s[d] = _rotr32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotr32(s[b] ^ s[c], 7)


def _b3_compress(
    cv: list[int], block_words: list[int], counter: int, block_len: int, flags: int
) -> list[int]:
    s = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        _B3_IV[0],
        _B3_IV[1],
        _B3_IV[2],
        _B3_IV[3],
        counter & 0xFFFFFFFF,
        (counter >> 32) & 0xFFFFFFFF,
        block_len,
        flags,
    ]
    m = list(block_words)
    for r in range(7):
        _b3_g(s, 0, 4, 8, 12, m[0], m[1])
        _b3_g(s, 1, 5, 9, 13, m[2], m[3])
        _b3_g(s, 2, 6, 10, 14, m[4], m[5])
        _b3_g(s, 3, 7, 11, 15, m[6], m[7])
        _b3_g(s, 0, 5, 10, 15, m[8], m[9])
        _b3_g(s, 1, 6, 11, 12, m[10], m[11])
        _b3_g(s, 2, 7, 8, 13, m[12], m[13])
        _b3_g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in _B3_MSG_PERM]
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def _b3_words(data: bytes) -> list[int]:
    padded = data + b"\x00" * (64 - len(data)) if len(data) < 64 else data
    return list(struct.unpack("<16I", padded[:64]))


def blake3_pure(data: bytes, key: bytes | None = None) -> bytes:
    """Reference pure-Python BLAKE3-256 (standard and keyed modes)."""
    if key is not None:
        if len(key) != 32:
            raise UnpackError("BLAKE3 key must be 32 bytes")
        key_words = list(struct.unpack("<8I", key))
        base_flags = _B3_KEYED_HASH
    else:
        key_words = list(_B3_IV)
        base_flags = 0

    def chunk_output(
        chunk: bytes, counter: int
    ) -> tuple[list[int], list[int], int, int, int]:
        cv = list(key_words)
        if not chunk:
            return (
                cv,
                _b3_words(b""),
                counter,
                0,
                base_flags | _B3_CHUNK_START | _B3_CHUNK_END,
            )
        n_blocks = (len(chunk) + 63) // 64
        for bi in range(n_blocks):
            blk = chunk[bi * 64 : (bi + 1) * 64]
            fl = base_flags
            if bi == 0:
                fl |= _B3_CHUNK_START
            if bi == n_blocks - 1:
                fl |= _B3_CHUNK_END
                return cv, _b3_words(blk), counter, len(blk), fl
            cv = _b3_compress(cv, _b3_words(blk), counter, len(blk), fl)[:8]
        raise AssertionError("unreachable")

    def parent_output(
        left_cv: list[int], right_cv: list[int]
    ) -> tuple[list[int], list[int], int, int, int]:
        return (
            list(key_words),
            left_cv + right_cv,
            0,
            64,
            base_flags | _B3_PARENT,
        )

    cv_stack: list[list[int]] = []
    pos = 0
    total_len = len(data)
    chunk_counter = 0
    while True:
        chunk = data[pos : pos + 1024]
        pos += len(chunk)
        is_last = pos >= total_len
        out = chunk_output(chunk, chunk_counter)
        if is_last:
            while cv_stack:
                cur_cv = _b3_compress(*out)[:8]
                left = cv_stack.pop()
                out = parent_output(left, cur_cv)
            root_words = _b3_compress(out[0], out[1], out[2], out[3], out[4] | _B3_ROOT)
            return struct.pack("<8I", *root_words[:8])
        cur_cv = _b3_compress(*out)[:8]
        chunk_counter += 1
        total_chunks = chunk_counter
        while (total_chunks & 1) == 0:
            left = cv_stack.pop()
            cur_cv = _b3_compress(*parent_output(left, cur_cv))[:8]
            total_chunks >>= 1
        cv_stack.append(cur_cv)


# -------------------------- Pure-Python Codec Decoders --------------------------


def _bitrev(v: int, bits: int) -> int:
    r = 0
    for _ in range(bits):
        r = (r << 1) | (v & 1)
        v >>= 1
    return r


def _huff4_decompress(src: bytes, dst_len: int) -> bytes:
    if not src:
        raise UnpackError("empty Huffman stream")
    flag = src[0]
    if flag == 0:
        if len(src) != dst_len + 1:
            raise UnpackError("raw Huffman length mismatch")
        return src[1:]
    if flag == 1:
        if len(src) != 2:
            raise UnpackError("RLE Huffman length mismatch")
        return bytes([src[1]]) * dst_len
    if flag != 2 or len(src) < 145:
        raise UnpackError(f"invalid Huffman flag {flag}")

    lengths = [0] * 256
    bl_count = [0] * 12
    kraft = 0
    for i in range(128):
        b = src[1 + i]
        l0, l1 = b & 0x0F, b >> 4
        if l0 > 11 or l1 > 11:
            raise UnpackError("Huffman code length > 11")
        lengths[2 * i] = l0
        lengths[2 * i + 1] = l1
        if l0:
            bl_count[l0] += 1
            kraft += 1 << (11 - l0)
        if l1:
            bl_count[l1] += 1
            kraft += 1 << (11 - l1)
    if kraft != 2048:
        raise UnpackError("invalid Huffman Kraft sum")

    next_code = [0] * 12
    code = 0
    for b in range(1, 12):
        code = (code + bl_count[b - 1]) << 1
        next_code[b] = code

    lut_sym = [0] * 2048
    lut_len = [0] * 2048
    for s in range(256):
        ln = lengths[s]
        if ln == 0:
            continue
        lsb = _bitrev(next_code[ln], ln)
        next_code[ln] += 1
        step = 1 << ln
        for idx in range(lsb, 2048, step):
            lut_sym[idx] = s
            lut_len[idx] = ln

    slens = struct.unpack("<4I", src[129:145])
    pos = 145
    base, rem = divmod(dst_len, 4)
    out = bytearray(dst_len)
    d_off = 0
    for k in range(4):
        slen = slens[k]
        if pos + slen > len(src):
            raise UnpackError("truncated Huffman lane")
        lane = src[pos : pos + slen]
        pos += slen
        nk = base + (1 if k < rem else 0)
        lp = 0
        bits = 0
        cnt = 0
        for i in range(nk):
            while cnt < 11 and lp < slen:
                bits |= lane[lp] << cnt
                lp += 1
                cnt += 8
            idx = bits & 2047
            ln = lut_len[idx]
            if ln == 0 or ln > cnt:
                raise UnpackError("corrupted Huffman bitstream")
            out[d_off + i] = lut_sym[idx]
            bits >>= ln
            cnt -= ln
        d_off += nk
    if pos != len(src):
        raise UnpackError("trailing bytes in Huffman stream")
    return bytes(out)


def _tans4_decompress(src: bytes, dst_len: int) -> bytes:
    if not src:
        raise UnpackError("empty tANS stream")
    flag = src[0]
    if flag == 0:
        if len(src) != dst_len + 1:
            raise UnpackError("raw tANS length mismatch")
        return src[1:]
    if flag == 1:
        if len(src) != 2:
            raise UnpackError("RLE tANS length mismatch")
        return bytes([src[1]]) * dst_len

    norm = [0] * 256
    pos = 1
    if flag == 2:
        if len(src) < 2:
            raise UnpackError("truncated sparse tANS header")
        active = src[pos]
        pos += 1
        if active < 2 or len(src) < pos + active * 3 + 24:
            raise UnpackError("invalid sparse tANS header")
        for _ in range(active):
            sym = src[pos]
            val = struct.unpack_from("<H", src, pos + 1)[0]
            pos += 3
            if norm[sym] != 0 or val == 0 or val >= 2048:
                raise UnpackError("invalid sparse tANS table")
            norm[sym] = val
    elif flag == 3:
        if len(src) < 1 + 384 + 24:
            raise UnpackError("truncated dense tANS header")
        for s in range(0, 256, 2):
            b0, b1, b2 = src[pos], src[pos + 1], src[pos + 2]
            pos += 3
            norm[s] = b0 | ((b1 & 0x0F) << 8)
            norm[s + 1] = (b1 >> 4) | (b2 << 4)
            if norm[s] >= 2048 or norm[s + 1] >= 2048:
                raise UnpackError("invalid dense tANS entry")
    else:
        raise UnpackError(f"invalid tANS flag {flag}")

    if sum(norm) != 2048:
        raise UnpackError("tANS frequencies do not sum to 2048")

    state_sym = [0] * 2048
    sp = 0
    for s in range(256):
        ns = norm[s]
        for _ in range(ns):
            state_sym[sp] = s
            sp = (sp + 1283) & 2047

    next_occ = list(norm)
    d_sym = [0] * 2048
    d_nb = [0] * 2048
    d_base = [0] * 2048
    for st in range(2048):
        s = state_sym[st]
        x = next_occ[s]
        next_occ[s] = x + 1
        nb = 11 - (x.bit_length() - 1)
        d_sym[st] = s
        d_nb[st] = nb
        d_base[st] = (x << nb) - 2048

    st_init = struct.unpack_from("<4H", src, pos)
    pos += 8
    slens = struct.unpack_from("<4I", src, pos)
    pos += 16

    base, rem = divmod(dst_len, 4)
    out = bytearray(dst_len)
    d_off = 0
    for k in range(4):
        state = st_init[k]
        if state >= 2048:
            raise UnpackError("invalid tANS initial state")
        slen = slens[k]
        if pos + slen > len(src):
            raise UnpackError("truncated tANS lane")
        lane = src[pos : pos + slen]
        pos += slen
        nk = base + (1 if k < rem else 0)
        lp = 0
        bits = 0
        cnt = 0
        for i in range(nk):
            out[d_off + i] = d_sym[state]
            nb = d_nb[state]
            while cnt < nb and lp < slen:
                bits |= lane[lp] << cnt
                lp += 1
                cnt += 8
            if cnt < nb:
                raise UnpackError("truncated tANS bits")
            bval = bits & ((1 << nb) - 1) if nb else 0
            bits >>= nb
            cnt -= nb
            state = d_base[state] + bval
        d_off += nk
    if pos != len(src):
        raise UnpackError("trailing bytes in tANS stream")
    return bytes(out)


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    val = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, pos
        shift += 7
        if shift > 28:
            raise UnpackError("varint overflow")
    raise UnpackError("truncated varint")


def _split_lz_decompress(src: bytes, dictionary: bytes = b"") -> bytes:
    if len(src) < 8:
        raise UnpackError("truncated Split-LZ header")
    orig_len = struct.unpack_from("<I", src, 0)[0]
    ent_mode = src[4]
    needs_dict = src[5]
    if orig_len == 0:
        return b""
    out = bytearray(orig_len)
    sp = 8
    dp = 0
    while dp < orig_len:
        if sp + 9 > len(src):
            raise UnpackError("truncated Split-LZ block header")
        btype = src[sp]
        blk_len, clen = struct.unpack_from("<II", src, sp + 1)
        sp += 9
        if blk_len == 0 or blk_len > FV_BLOCK_SIZE or blk_len > orig_len - dp:
            raise UnpackError("invalid Split-LZ block length")
        if sp + clen > len(src):
            raise UnpackError("truncated Split-LZ block payload")
        bp = src[sp : sp + clen]
        sp += clen
        if btype == 0:
            if clen != blk_len:
                raise UnpackError("raw block length mismatch")
            out[dp : dp + blk_len] = bp
            dp += blk_len
            continue
        if btype != 1:
            raise UnpackError(f"unsupported Split-LZ block type {btype}")

        use_dict_blk = bool(needs_dict and dp == 0)
        if use_dict_blk:
            prefix = dictionary[: 128 * 1024]
        else:
            start = max(0, dp - FV_HIST_SIZE)
            prefix = bytes(out[start:dp])
        prefix_len = len(prefix)

        if ent_mode == 0:
            if clen < 36:
                raise UnpackError("truncated Selkie sub-header")
            (
                _fl,
                n_toks,
                n_lits,
                n_off24,
                n_extra,
                trailing,
                c_toks,
                c_lits,
                c_offs,
            ) = struct.unpack_from("<9I", bp, 0)
            if 36 + c_toks + c_lits + c_offs + n_off24 + n_extra != clen:
                raise UnpackError("Selkie stream sizes mismatch")
            r = 36
            toks = bp[r : r + c_toks]
            r += c_toks
            lits = bp[r : r + c_lits]
            r += c_lits
            offs16_bytes = bp[r : r + c_offs]
            r += c_offs
            off24 = bp[r : r + n_off24]
            r += n_off24
            extra = bp[r : r + n_extra]
            sub_mode = False
            ohi = b""
            olo = b""
        else:
            if clen < 40:
                raise UnpackError("truncated Kraken sub-header")
            flags = bp[0]
            (
                n_toks,
                n_lits,
                n_off24,
                n_extra,
                trailing,
                c_toks,
                c_lits,
                c_ohi,
                c_olo,
            ) = struct.unpack_from("<9I", bp, 4)
            if 40 + c_toks + c_lits + c_ohi + c_olo + n_off24 + n_extra != clen:
                raise UnpackError("Kraken stream sizes mismatch")
            r = 40
            dec_fn = _huff4_decompress if ent_mode == 1 else _tans4_decompress
            toks = dec_fn(bp[r : r + c_toks], n_toks)
            r += c_toks
            lits = dec_fn(bp[r : r + c_lits], n_lits)
            r += c_lits
            ohi = dec_fn(bp[r : r + c_ohi], n_toks)
            r += c_ohi
            if flags & 2:
                olo = dec_fn(bp[r : r + c_olo], n_toks)
            else:
                if c_olo != n_toks:
                    raise UnpackError("raw olo size mismatch")
                olo = bp[r : r + c_olo]
            r += c_olo
            off24 = bp[r : r + n_off24]
            r += n_off24
            extra = bp[r : r + n_extra]
            sub_mode = bool(flags & 1)
            offs16_bytes = b""

        buf = bytearray(prefix_len + blk_len)
        if prefix_len:
            buf[:prefix_len] = prefix
        cur_pos = prefix_len
        end_pos = prefix_len + blk_len
        lp = 0
        ep = 0
        o24p = 0
        rep0 = 1

        for ti in range(n_toks):
            t = toks[ti]
            ll = t >> 4
            ml_c = t & 0x0F
            if ll == 15:
                add_ll, ep = _read_varint(extra, ep)
                ll += add_ll
            ml = ml_c + 3
            if ml_c == 15:
                add_ml, ep = _read_varint(extra, ep)
                ml += add_ml
            if lp + ll > n_lits or cur_pos + ll > end_pos:
                raise UnpackError("literal bounds exceeded")
            if ll:
                if sub_mode:
                    for i in range(ll):
                        pred = buf[cur_pos + i - rep0] if cur_pos + i >= rep0 else 0
                        buf[cur_pos + i] = (lits[lp + i] + pred) & 0xFF
                else:
                    buf[cur_pos : cur_pos + ll] = lits[lp : lp + ll]
                lp += ll
                cur_pos += ll
            if ent_mode == 0:
                o16 = struct.unpack_from("<H", offs16_bytes, ti * 2)[0]
            else:
                o16 = olo[ti] | (ohi[ti] << 8)
            if o16 == 0:
                off = rep0
            elif o16 == 65535:
                if o24p + 3 > n_off24:
                    raise UnpackError("off24 truncated")
                off = off24[o24p] | (off24[o24p + 1] << 8) | (off24[o24p + 2] << 16)
                o24p += 3
                rep0 = off
            else:
                off = o16
                rep0 = off
            if off == 0 or off > cur_pos or cur_pos + ml > end_pos:
                raise UnpackError("match bounds exceeded")
            for i in range(ml):
                buf[cur_pos + i] = buf[cur_pos + i - off]
            cur_pos += ml

        if trailing:
            if lp + trailing != n_lits or cur_pos + trailing != end_pos:
                raise UnpackError("trailing literal mismatch")
            if sub_mode:
                for i in range(trailing):
                    pred = buf[cur_pos + i - rep0] if cur_pos + i >= rep0 else 0
                    buf[cur_pos + i] = (lits[lp + i] + pred) & 0xFF
            else:
                buf[cur_pos : cur_pos + trailing] = lits[lp : lp + trailing]
            cur_pos += trailing
        if cur_pos != end_pos:
            raise UnpackError("Split-LZ block size mismatch")
        out[dp : dp + blk_len] = buf[prefix_len:]
        dp += blk_len
    if sp != len(src):
        raise UnpackError("trailing bytes in Split-LZ stream")
    return bytes(out)


def _zstd_decompress_pure(data: bytes, raw_len: int, dictionary: bytes = b"") -> bytes:
    """Decompress a Zstd frame via Python 3.14 stdlib compression.zstd or pip zstandard."""
    try:
        from compression import zstd as std_zstd  # type: ignore[import-not-found]

        if dictionary:
            zd = std_zstd.ZstdDict(dictionary, is_raw=True)
            res = std_zstd.decompress(data, zstd_dict=zd)
        else:
            res = std_zstd.decompress(data)
        if len(res) != raw_len:
            raise UnpackError("zstd output length mismatch")
        return res
    except ImportError:
        pass
    try:
        import zstandard  # type: ignore[import-not-found]

        if dictionary:
            dd = zstandard.ZstdCompressionDict(dictionary)
            dctx = zstandard.ZstdDecompressor(dict_data=dd)
        else:
            dctx = zstandard.ZstdDecompressor()
        res = dctx.decompress(data, max_output_size=raw_len)
        if len(res) != raw_len:
            raise UnpackError("zstd output length mismatch")
        return res
    except ImportError as exc:
        raise UnpackError(
            "this pack uses Zstd chunks (Max/Balanced profile) and requires Python 3.14+ "
            "or `pip install zstandard` (or the native libforge_vault library)"
        ) from exc


def _plane_decompress(src: bytes) -> bytes:
    if len(src) < 8:
        raise UnpackError("truncated Plane-AVX2 header")
    orig_len = struct.unpack_from("<I", src, 0)[0]
    if orig_len == 0:
        return b""
    out = bytearray(orig_len)
    sp = 8
    dp = 0
    while dp < orig_len:
        if sp + 9 > len(src):
            raise UnpackError("truncated Plane block header")
        btype = src[sp]
        blk_len, clen = struct.unpack_from("<II", src, sp + 1)
        sp += 9
        if blk_len == 0 or blk_len > FV_PLANE_BLOCK_SIZE or sp + clen > len(src):
            raise UnpackError("invalid Plane block bounds")
        bp = src[sp : sp + clen]
        sp += clen
        if btype == 0:
            if clen != blk_len:
                raise UnpackError("raw plane block mismatch")
            out[dp : dp + blk_len] = bp
        elif btype == 10:
            out[dp : dp + blk_len] = _split_lz_decompress(bp)
        elif btype == 11:
            out[dp : dp + blk_len] = _zstd_decompress_pure(bp, blk_len)
        elif btype in (2, 4):
            stride = btype
            phdr = 1 + stride * 5
            if clen < phdr:
                raise UnpackError("truncated plane sub-header")
            tail = bp[0]
            n_elems = blk_len // stride
            if tail != blk_len % stride:
                raise UnpackError("plane tail mismatch")
            rp = phdr
            planes: list[bytes] = []
            for s in range(stride):
                pm = bp[1 + s * 5]
                pcl = struct.unpack_from("<I", bp, 2 + s * 5)[0]
                if rp + pcl > clen:
                    raise UnpackError("truncated plane payload")
                chunk = bp[rp : rp + pcl]
                rp += pcl
                if pm == 0:
                    if pcl != n_elems:
                        raise UnpackError("raw plane length mismatch")
                    pl = chunk
                elif pm == 1:
                    pl = _huff4_decompress(chunk, n_elems)
                elif pm == 2:
                    pl = _tans4_decompress(chunk, n_elems)
                elif pm == 3:
                    raw_d = bytearray(_tans4_decompress(chunk, n_elems))
                    acc = 0
                    for i in range(n_elems):
                        acc = (acc + raw_d[i]) & 0xFF
                        raw_d[i] = acc
                    pl = bytes(raw_d)
                elif pm == 4:
                    pl = _zstd_decompress_pure(chunk, n_elems)
                elif pm == 6:
                    pl = _split_lz_decompress(chunk)
                else:
                    raise UnpackError(f"unknown plane mode {pm}")
                planes.append(pl)
            if clen - rp != tail:
                raise UnpackError("plane trailing bytes mismatch")
            for s in range(stride):
                out[dp + s : dp + n_elems * stride : stride] = planes[s]
            if tail:
                out[dp + n_elems * stride : dp + blk_len] = bp[rp : rp + tail]
        else:
            raise UnpackError(f"unsupported Plane block type {btype}")
        dp += blk_len
    return bytes(out)


def _phrase_selkie_decompress(src: bytes, dictionary: bytes = b"") -> bytes:
    if len(src) < 5:
        raise UnpackError("truncated Phrase-Selkie header")
    orig_len = struct.unpack_from("<I", src, 0)[0]
    n_phrases = src[4]
    if n_phrases == 0:
        return _split_lz_decompress(src[5:], dictionary)
    pos = 5
    phrases: list[bytes] = []
    for _ in range(n_phrases):
        plen = src[pos]
        pos += 1
        phrases.append(src[pos : pos + plen])
        pos += plen
    folded = _split_lz_decompress(src[pos:], dictionary)
    out = bytearray()
    i = 0
    n = len(folded)
    while i < n:
        b = folded[i]
        i += 1
        if b == 0xFF:
            if i >= n:
                raise UnpackError("truncated Phrase-Selkie escape")
            out.append(folded[i])
            i += 1
        elif 0x80 <= b < 0x80 + n_phrases:
            out.extend(phrases[b - 0x80])
        else:
            out.append(b)
    if len(out) != orig_len:
        raise UnpackError("Phrase-Selkie output size mismatch")
    return bytes(out)


def decompress_pure(
    codec_id: int, comp: bytes, raw_len: int, dictionary: bytes = b""
) -> bytes:
    """Reference pure-Python codec dispatcher for FVLT0001 v1."""
    if codec_id == CODEC_RAW:
        if len(comp) != raw_len + 4 or struct.unpack_from("<I", comp, 0)[0] != raw_len:
            raise UnpackError("raw chunk size mismatch")
        return comp[4:]
    if codec_id in (CODEC_SIMD_SELKIE, CODEC_KRAKEN_HUFF8, CODEC_KRAKEN_TANS8):
        out = _split_lz_decompress(comp, dictionary)
    elif codec_id == CODEC_PHRASE_SELKIE:
        out = _phrase_selkie_decompress(comp, dictionary)
    elif codec_id in (CODEC_AVX2_PLANE, CODEC_AVX2_PLANE_ZSTD):
        out = _plane_decompress(comp)
    elif codec_id in (CODEC_ZSTD_FAST, CODEC_ZSTD_MAX):
        if len(comp) < 8:
            raise UnpackError("truncated Zstd wrapper")
        out = _zstd_decompress_pure(comp[8:], raw_len, dictionary)
    else:
        raise UnpackError(f"unsupported codec_id {codec_id}")
    if len(out) != raw_len:
        raise UnpackError(
            f"decompressed length mismatch (codec={codec_id}, got={len(out)}, expected={raw_len})"
        )
    return out


# -------------------------- Native Accelerator (Optional) --------------------------


def _try_load_native() -> ctypes.CDLL | None:
    here = Path(__file__).resolve().parent
    lib_name = "forge_vault.dll" if os.name == "nt" else "libforge_vault.so"
    candidates = [
        here / lib_name,
        here.parents[2] / "shared" / "vault" / lib_name,
    ]
    env_lib = os.environ.get("FORGE_VAULT_LIB")
    if env_lib:
        candidates.insert(0, Path(env_lib))
    for cand in candidates:
        if cand.is_file():
            try:
                lib = ctypes.CDLL(str(cand))
                lib.fv_crypto_init.argtypes = []
                lib.fv_crypto_init.restype = ctypes.c_int
                if lib.fv_crypto_init() != 0:
                    continue
                lib.fv_blake3.argtypes = [
                    ctypes.c_char_p,
                    ctypes.c_size_t,
                    ctypes.c_char_p,
                ]
                lib.fv_blake3.restype = None
                lib.fv_keyed_blake3.argtypes = [
                    ctypes.c_char_p,
                    ctypes.c_char_p,
                    ctypes.c_size_t,
                    ctypes.c_char_p,
                ]
                lib.fv_keyed_blake3.restype = None
                lib.fv_decompress.argtypes = [
                    ctypes.c_int,
                    ctypes.c_char_p,
                    ctypes.c_size_t,
                    ctypes.c_char_p,
                    ctypes.c_size_t,
                    ctypes.c_char_p,
                    ctypes.c_size_t,
                ]
                lib.fv_decompress.restype = ctypes.c_int64
                if hasattr(lib, "fv_png_filter"):
                    lib.fv_png_filter.argtypes = [
                        ctypes.c_char_p,
                        ctypes.c_size_t,
                        ctypes.c_char_p,
                        ctypes.c_uint32,
                        ctypes.c_uint32,
                        ctypes.c_uint32,
                        ctypes.c_char_p,
                    ]
                    lib.fv_png_filter.restype = ctypes.c_int
                return lib
            except OSError:
                continue
    return None


# ------------------ Classic zlib deflate (PNG recipe stage) ------------------
# PNG recipes re-deflate pixels with classic zlib, whose bytes Python's zlib
# matches only where it is classic: Python 3.14 for Windows uses zlib-ng. This
# is a copy of the ctypes part of Forge's shared/forge_deflate.py (Relay task
# 1578; shared/tests/test_forge_deflate.py keeps the two in step).

_Z_STREAM_END = 1
_Z_STREAM_ERROR = -2
_Z_BUF_ERROR = -5
_Z_FINISH = 4
_ZK = 1024
_ZM = 1024 * _ZK
ZLIB_OUTPUT_BLOCKS = (
    32 * _ZK, 64 * _ZK, 256 * _ZK, 1 * _ZM, 4 * _ZM, 8 * _ZM, 16 * _ZM, 16 * _ZM,
    32 * _ZM, 32 * _ZM, 32 * _ZM, 32 * _ZM, 64 * _ZM, 64 * _ZM, 128 * _ZM, 128 * _ZM,
)  # fmt: skip
ZLIB_OUTPUT_MAX_BLOCK = 256 * _ZM
ZLIB_FINGERPRINT_SETTINGS = (
    (0, 8, 0, 15), (0, 1, 0, 9), (0, 5, 0, 11), (1, 8, 0, 15), (2, 1, 0, 9),
    (3, 9, 0, 15), (4, 8, 0, 15), (5, 3, 1, 12), (6, 8, 0, 15), (6, 8, 1, 15),
    (7, 9, 0, 14), (8, 8, 0, 15), (9, 9, 0, 15), (9, 2, 1, 10), (6, 8, 2, 15),
    (6, 8, 3, 15), (1, 1, 3, 9),
)  # fmt: skip
ZLIB_GOLDEN_SHA256 = (
    "e125b66bbad097f6c1625ad5ab69298c4e992a39621bf68b3ed6b4b9ac71674a"  # levels 1-9
)
ZLIB_GOLDEN_STORED_SHA256 = (
    "dbbd5bcc756422a45a1527256eb060212a1f43d4a97eec2a3f07eace719182c5"  # level 0
)
# where an installed Forge keeps its fetched classic zlib, under its tools folder
ZLIB_TOOL_PATH = ("zlib-classic", "ucrt64", "bin", "zlib1.dll")


class _ZStream(ctypes.Structure):
    _fields_ = [
        ("next_in", ctypes.c_void_p),
        ("avail_in", ctypes.c_uint),
        ("total_in", ctypes.c_ulong),
        ("next_out", ctypes.c_void_p),
        ("avail_out", ctypes.c_uint),
        ("total_out", ctypes.c_ulong),
        ("msg", ctypes.c_char_p),
        ("state", ctypes.c_void_p),
        ("zalloc", ctypes.c_void_p),
        ("zfree", ctypes.c_void_p),
        ("opaque", ctypes.c_void_p),
        ("data_type", ctypes.c_int),
        ("adler", ctypes.c_ulong),
        ("reserved", ctypes.c_ulong),
    ]


def _zlib_deflate_ctypes(
    lib: Any, data: bytes, level: int, mem: int, strategy: int, wbits: int
) -> bytes:
    """One finished zlib stream from a ctypes zlib, given output room as CPython's zlib does."""
    z = _ZStream()
    zp = ctypes.byref(z)
    rc = lib.deflateInit2_(
        zp, level, 8, wbits, mem, strategy, lib.zlibVersion(), ctypes.sizeof(_ZStream)
    )
    if rc != 0:
        raise zlib.error(f"Error {rc} while creating compression object")
    out: list[bytes] = []
    try:
        for chunk, mode in ((data, 0), (b"", _Z_FINISH)):
            base = ctypes.cast(ctypes.c_char_p(chunk), ctypes.c_void_p).value or 0
            left, offset = len(chunk), 0
            sizes = iter(ZLIB_OUTPUT_BLOCKS)
            blocks: list[Any] = []

            def grow(_blocks: list[Any] = blocks, _sizes: Any = sizes) -> None:
                size = next(_sizes, ZLIB_OUTPUT_MAX_BLOCK)
                buf = ctypes.create_string_buffer(size)
                _blocks.append(buf)
                z.next_out = ctypes.addressof(buf)
                z.avail_out = size

            grow()
            while True:
                take = min(left, 0xFFFFFFFF)
                z.next_in = base + offset if take else None
                z.avail_in = take
                offset += take
                left -= take
                while True:
                    if z.avail_out == 0:
                        grow()
                    rc = lib.deflate(zp, mode)
                    if rc == _Z_STREAM_ERROR:
                        raise zlib.error(f"Error {rc} while compressing data")
                    if z.avail_out != 0:
                        break
                if left == 0:
                    break
            if mode == _Z_FINISH and rc != _Z_STREAM_END:
                raise zlib.error(f"Error {rc} while flushing")
            if mode != _Z_FINISH and rc not in (0, _Z_BUF_ERROR):
                raise zlib.error(f"Error {rc} while compressing data")
            used = len(blocks[-1]) - z.avail_out
            out.append(b"".join(b.raw for b in blocks[:-1]) + blocks[-1].raw[:used])
    finally:
        lib.deflateEnd(zp)
    return b"".join(out)


def _zlib_bind(lib: Any) -> Any:
    """Declare the zlib calls used here on a loaded library."""
    zp = ctypes.POINTER(_ZStream)
    lib.zlibVersion.restype = ctypes.c_char_p
    lib.zlibVersion.argtypes = []
    lib.deflateInit2_.restype = ctypes.c_int
    lib.deflateInit2_.argtypes = (
        [zp] + [ctypes.c_int] * 5 + [ctypes.c_char_p, ctypes.c_int]
    )
    lib.deflate.restype = ctypes.c_int
    lib.deflate.argtypes = [zp, ctypes.c_int]
    lib.deflateEnd.restype = ctypes.c_int
    lib.deflateEnd.argtypes = [zp]
    return lib


def _zlib_python_deflate(
    data: bytes, level: int, mem: int, strategy: int, wbits: int
) -> bytes:
    co = zlib.compressobj(level, zlib.DEFLATED, wbits, mem, strategy)
    return co.compress(data) + co.flush()


def _zlib_fingerprint_sample() -> bytes:
    x = 0x1578
    out = bytearray()

    def rnd() -> int:
        nonlocal x
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        return x >> 16

    for row in range(96):
        out.append(row % 5)
        for col in range(255):
            out.append((row + col * 3 + (rnd() & 7)) & 0xFF)
    words = (b"forge ", b"pack ", b"recipe ", b"deflate ", b"classic ", b"zlib\n")
    for _ in range(3000):
        out += words[rnd() % len(words)]
    for i in range(64):
        out += bytes([i]) * (i * 7 % 300 + 1)
    for _ in range(8192):
        out.append(rnd() & 0xFF)
    return bytes(out)


def _zlib_fingerprint(
    deflate: Callable[[bytes, int, int, int, int], bytes], stored: bool = False
) -> str:
    data = _zlib_fingerprint_sample()
    h = hashlib.sha256()
    for level, mem, strategy, wbits in ZLIB_FINGERPRINT_SETTINGS:
        if (level == 0) != stored:
            continue
        stream = deflate(data, level, mem, strategy, wbits)
        h.update(len(stream).to_bytes(4, "little"))
        h.update(stream)
    return h.hexdigest()


def _zlib_judge(deflate: Callable[[bytes, int, int, int, int], bytes]) -> bool | None:
    """None: not classic; True: classic at every level; False: levels 1-9 only
    (zlib 1.2.11, whose level-0 stored blocks differ)."""
    try:
        if _zlib_fingerprint(deflate) != ZLIB_GOLDEN_SHA256:
            return None
        return _zlib_fingerprint(deflate, stored=True) == ZLIB_GOLDEN_STORED_SHA256
    except (ValueError, zlib.error):
        return None


def _zlib_library_candidates() -> list[str]:
    """Classic zlib libraries to try, best first: FORGE_ZLIB_CLASSIC, beside
    this script, Forge's fetched copy (an installed Forge's tools folder), and
    (not on Windows) the system's libz."""
    out: list[str] = []
    env_lib = os.environ.get("FORGE_ZLIB_CLASSIC")
    if env_lib:
        out.append(env_lib)
    here = Path(__file__).resolve().parent
    names = (
        ("zlib1.dll",) if os.name == "nt" else ("libz.so.1", "libz.so", "libz.dylib")
    )
    out += [str(here / n) for n in names if (here / n).is_file()]
    tools: list[Path] = []
    if os.environ.get("FORGE_TOOLS_DIR"):
        tools.append(Path(os.environ["FORGE_TOOLS_DIR"]))
    if os.environ.get("FORGE_CACHE"):
        tools.append(Path(os.environ["FORGE_CACHE"]) / "tools")
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        tools.append(Path(local) / "Forge" / "Cache" / "tools")
    for t in tools:
        cand = t.joinpath(*ZLIB_TOOL_PATH)
        if cand.is_file():
            out.append(str(cand))
    if os.name != "nt":
        import ctypes.util  # noqa: PLC0415

        found = ctypes.util.find_library("z")
        if found:
            out.append(found)
    return out


_ZLIB_CLASSIC: list[Any] = []  # [(deflate function, stored ok, name)] once found


def _classic_deflate(
    stored: bool = False,
) -> Callable[[bytes, int, int, int, int], bytes]:
    """A classic zlib deflate(data, level, mem, strategy, wbits), else UnpackError
    saying why; `stored`: level-0 recipes must restore too."""
    if not _ZLIB_CLASSIC:
        _ZLIB_CLASSIC.append(_find_classic_deflate())
    run, stored_ok, name = _ZLIB_CLASSIC[0]
    if stored and not stored_ok:
        raise UnpackError(
            "this pack holds PNG files whose exact recipe is zlib level 0 (stored), "
            f"which restore only with zlib 1.2.12 or newer, and the classic zlib here is "
            f"{name}. Point FORGE_ZLIB_CLASSIC at zlib 1.2.12 or newer."
        )
    return run


def _find_classic_deflate() -> (
    tuple[Callable[[bytes, int, int, int, int], bytes], bool, str]
):
    ver = zlib.ZLIB_RUNTIME_VERSION
    ng = getattr(zlib, "ZLIBNG_VERSION", None)
    import re  # noqa: PLC0415

    best: tuple[Callable[[bytes, int, int, int, int], bytes], bool, str] | None = None
    if not ng and re.fullmatch(r"\d+(\.\d+){1,3}", ver):
        verdict = _zlib_judge(_zlib_python_deflate)
        if verdict is not None:
            best = (_zlib_python_deflate, verdict, f"Python's zlib {ver}")
            if verdict:
                return best
    tried: list[str] = []
    for path in _zlib_library_candidates():
        try:
            lib = _zlib_bind(ctypes.CDLL(path))
        except (OSError, AttributeError) as exc:
            tried.append(f"{path}: {exc}")
            continue

        def run(
            data: bytes,
            level: int,
            mem: int,
            strategy: int,
            wbits: int,
            _lib: Any = lib,
        ) -> bytes:
            return _zlib_deflate_ctypes(_lib, data, level, mem, strategy, wbits)

        verdict = _zlib_judge(run)
        if verdict is None:
            tried.append(f"{path} does not write classic zlib's deflate bytes")
            continue
        got = (run, verdict, f"zlib {(lib.zlibVersion() or b'').decode()} ({path})")
        if verdict:
            return got
        best = best or got
    if best is not None:
        return best
    kind = (
        f"zlib-ng {ng}"
        if ng
        else (f"zlib-ng ({ver})" if "ng" in ver.lower() else f"zlib {ver}")
    )
    if os.name == "nt":
        advice = (
            "Put a classic zlib1.dll (zlib 1.2.12 or newer, from zlib.net or MSYS2) "
            "beside forge_unpack.py or point FORGE_ZLIB_CLASSIC at one; Forge itself "
            "fetches it on first use."
        )
    else:
        advice = (
            "Point FORGE_ZLIB_CLASSIC at a classic zlib library (zlib 1.2.12 or newer, "
            "libz.so.1 or libz.dylib) or put it beside forge_unpack.py."
        )
    raise UnpackError(
        "this pack holds PNG files packed with Pack's exact PNG recipe, which "
        f"restore only with classic zlib, and this Python's zlib is {kind}"
        + (f" ({'; '.join(tried)})" if tried else "")
        + f". {advice}"
    )


# ---------------------- v1.1 Additive Media Stage Decoders ----------------------


def _find_djxl() -> str | None:
    env_bin = os.environ.get("FORGE_DJXL")
    if env_bin:
        p = Path(env_bin)
        return str(p) if p.is_file() and os.access(p, os.X_OK) else None
    here = Path(__file__).resolve().parent
    names = ("djxl.exe", "djxl") if os.name == "nt" else ("djxl",)
    for name in names:
        cand = here / name
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return shutil.which("djxl")


def _paeth_pure(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def _png_filter_standalone(
    pixels: bytes,
    row_types: bytes,
    height: int,
    stride: int,
    bpp: int,
    native_lib: ctypes.CDLL | None,
) -> bytes:
    if native_lib is not None and hasattr(native_lib, "fv_png_filter"):
        out_buf = ctypes.create_string_buffer(height * (stride + 1))
        rc = int(
            native_lib.fv_png_filter(
                pixels, len(pixels), row_types, height, stride, bpp, out_buf
            )
        )
        if rc != 0:
            raise UnpackError("invalid PNG scanline filter type")
        return out_buf.raw
    row_out = stride + 1
    out = bytearray(height * row_out)
    mv = memoryview(pixels)
    for y in range(height):
        ft = row_types[y]
        if ft > 4:
            raise UnpackError(f"invalid PNG filter type: {ft}")
        so = y * stride
        po = so - stride
        do = y * row_out
        out[do] = ft
        if ft == 0:
            out[do + 1 : do + row_out] = mv[so : so + stride]
        elif ft == 1:
            for x in range(bpp):
                out[do + 1 + x] = mv[so + x]
            for x in range(bpp, stride):
                out[do + 1 + x] = (mv[so + x] - mv[so + x - bpp]) & 0xFF
        elif ft == 2:
            if y == 0:
                out[do + 1 : do + row_out] = mv[so : so + stride]
            else:
                for x in range(stride):
                    out[do + 1 + x] = (mv[so + x] - mv[po + x]) & 0xFF
        elif ft == 3:
            for x in range(stride):
                a = mv[so + x - bpp] if x >= bpp else 0
                b = mv[po + x] if y > 0 else 0
                out[do + 1 + x] = (mv[so + x] - ((a + b) >> 1)) & 0xFF
        else:
            for x in range(stride):
                a = mv[so + x - bpp] if x >= bpp else 0
                b = mv[po + x] if y > 0 else 0
                c = mv[po + x - bpp] if (y > 0 and x >= bpp) else 0
                out[do + 1 + x] = (mv[so + x] - _paeth_pure(a, b, c)) & 0xFF
    return bytes(out)


def _make_fsize_limiter(max_bytes: int) -> Callable[[], None] | None:
    if os.name != "posix" or max_bytes <= 0:
        return None
    import resource  # noqa: PLC0415

    limit = max(max_bytes, 65536)

    def _limit() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

    return _limit


def _decode_jxl_jpeg_standalone(
    jxl_bytes: bytes, media: dict[str, Any], max_output_bytes: int | None = None
) -> bytes:
    exp_size = media.get("stored_size")
    if isinstance(exp_size, int) and len(jxl_bytes) != exp_size:
        raise UnpackError("JXL stored size mismatch")
    exp_sha = media.get("jxl_sha256")
    if isinstance(exp_sha, str) and hashlib.sha256(jxl_bytes).hexdigest() != exp_sha:
        raise UnpackError("damaged JXL payload (jxl_sha256 mismatch)")
    djxl = _find_djxl()
    if not djxl:
        raise UnpackError(
            "this file uses the JPEG XL media stage and requires 'djxl' (libjxl, BSD) "
            "on PATH or beside forge_unpack.py"
        )
    out_cap = (
        max_output_bytes + 65536
        if isinstance(max_output_bytes, int) and max_output_bytes > 0
        else MAX_PNG_PIXEL_BYTES
    )
    with tempfile.TemporaryDirectory(prefix="fpack_jxl_") as td:
        d = Path(td)
        in_jxl, out_jpg = d / "in.jxl", d / "out.jpg"
        in_jxl.write_bytes(jxl_bytes)
        try:
            res = subprocess.run(
                [djxl, "--quiet", str(in_jxl), str(out_jpg)],
                capture_output=True,
                text=True,
                timeout=300,
                preexec_fn=_make_fsize_limiter(out_cap),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise UnpackError(f"djxl failed to decode JPEG XL stream: {exc}") from exc
        if res.returncode != 0 or not out_jpg.is_file():
            raise UnpackError(
                f"djxl failed to decode JPEG XL stream: {(res.stderr or res.stdout).strip()}"
            )
        out_sz = out_jpg.stat().st_size
        if out_sz == 0 or out_sz > out_cap:
            raise UnpackError(f"djxl output size out of bounds: {out_sz}")
        return out_jpg.read_bytes()


def _decode_png_recipe_standalone(
    envelope: bytes, media: dict[str, Any], native_lib: ctypes.CDLL | None
) -> bytes:
    exp_size = media.get("stored_size")
    if isinstance(exp_size, int) and len(envelope) != exp_size:
        raise UnpackError("PNG recipe stored size mismatch")
    if len(envelope) < 12 or envelope[:4] != PNG_RECIPE_MAGIC:
        raise UnpackError("invalid PNG recipe magic")
    hcl = struct.unpack_from("<I", envelope, 4)[0]
    jxl_off = 8 + hcl
    if jxl_off + 4 > len(envelope):
        raise UnpackError("truncated PNG recipe header")
    jxl_len = struct.unpack_from("<I", envelope, jxl_off)[0]
    if jxl_off + 4 + jxl_len != len(envelope) or jxl_len == 0:
        raise UnpackError("truncated PNG recipe JXL payload")
    try:
        dlz = lzma.LZMADecompressor()
        hdr_plain = dlz.decompress(
            envelope[8:jxl_off], max_length=MAX_PNG_RECIPE_HEADER_BYTES + 1
        )
        if not dlz.eof or len(hdr_plain) > MAX_PNG_RECIPE_HEADER_BYTES:
            raise UnpackError("PNG recipe header exceeds safe bounds")
    except lzma.LZMAError as exc:
        raise UnpackError(f"corrupted PNG recipe header: {exc}") from exc
    if len(hdr_plain) < 4:
        raise UnpackError("truncated PNG recipe metadata")
    jlen = struct.unpack_from("<I", hdr_plain, 0)[0]
    if 4 + jlen > len(hdr_plain):
        raise UnpackError("malformed PNG recipe JSON length")
    try:
        hmeta = json.loads(hdr_plain[4 : 4 + jlen].decode("utf-8"))
        h, w, ch = (int(x) for x in hmeta["shape"])
        lv, mem, strategy, wbits = (int(x) for x in hmeta["recipe"])
        chunks_spec = hmeta["chunks"]
        trailing_len = int(hmeta.get("trailing_len", 0))
    except (UnicodeDecodeError, ValueError, KeyError, TypeError) as exc:
        raise UnpackError(f"malformed PNG recipe metadata: {exc}") from exc
    if (
        not isinstance(chunks_spec, list)
        or w <= 0
        or h <= 0
        or ch not in (1, 2, 3, 4)
        or w * h * ch > MAX_PNG_PIXEL_BYTES
        or trailing_len < 0
    ):
        raise UnpackError("PNG recipe dimensions out of bounds")
    pos = 4 + jlen
    if pos + h > len(hdr_plain):
        raise UnpackError("truncated PNG filter types")
    row_types = hdr_plain[pos : pos + h]
    pos += h
    non_idat: list[bytes] = []
    for entry in chunks_spec:
        if not isinstance(entry, dict):
            raise UnpackError("malformed PNG chunk entry")
        if entry.get("t") != "IDAT":
            try:
                blen = int(entry.get("blen", -1))
            except (ValueError, TypeError) as exc:
                raise UnpackError("invalid PNG chunk body length") from exc
            if blen < 0 or pos + blen > len(hdr_plain):
                raise UnpackError("truncated PNG non-IDAT chunk body")
            non_idat.append(hdr_plain[pos : pos + blen])
            pos += blen
    if pos + trailing_len != len(hdr_plain):
        raise UnpackError("PNG recipe trailing length mismatch")
    trailing = hdr_plain[pos : pos + trailing_len]

    deflate = _classic_deflate(stored=lv == 0)
    djxl = _find_djxl()
    if not djxl:
        raise UnpackError(
            "this PNG file uses the JPEG XL recipe stage and requires 'djxl' (libjxl, BSD) "
            "on PATH or beside forge_unpack.py"
        )
    max_pam_bytes = w * h * ch + 4096
    with tempfile.TemporaryDirectory(prefix="fpack_png_") as td:
        d = Path(td)
        in_jxl, out_pam = d / "pix.jxl", d / "out.pam"
        in_jxl.write_bytes(envelope[jxl_off + 4 :])
        try:
            res = subprocess.run(
                [djxl, "--quiet", str(in_jxl), str(out_pam)],
                capture_output=True,
                text=True,
                timeout=300,
                preexec_fn=_make_fsize_limiter(w * h * ch + 65536),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise UnpackError(f"djxl failed to decode PNG pixels: {exc}") from exc
        if res.returncode != 0 or not out_pam.is_file():
            raise UnpackError(
                f"djxl failed to decode PNG pixels: {(res.stderr or res.stdout).strip()}"
            )
        if out_pam.stat().st_size > max_pam_bytes:
            raise UnpackError("decoded PAM exceeds declared recipe pixel bounds")
        pam = out_pam.read_bytes()
    idx = pam.find(b"ENDHDR\n")
    if idx < 0 or not pam.startswith(b"P7\n"):
        raise UnpackError("invalid PAM header from djxl")
    try:
        pvals = dict(
            ln.strip().split(None, 1)
            for ln in pam[:idx].decode("ascii").splitlines()[1:]
            if len(ln.strip().split(None, 1)) == 2
        )
        dw = int(pvals["WIDTH"])
        dh = int(pvals["HEIGHT"])
        dch = int(pvals["DEPTH"])
        maxval = int(pvals["MAXVAL"])
    except (UnicodeDecodeError, KeyError, ValueError) as exc:
        raise UnpackError(f"invalid PAM header fields: {exc}") from exc
    if dw != w or dh != h or dch != ch or maxval != 255:
        raise UnpackError("decoded PAM header mismatch")
    pixels = pam[idx + 7 :]
    if len(pixels) != w * h * ch:
        raise UnpackError("decoded PAM pixel size mismatch")
    filtered = _png_filter_standalone(pixels, row_types, h, w * ch, ch, native_lib)
    try:
        z_stream = deflate(filtered, lv, mem, strategy, wbits)
    except (ValueError, zlib.error) as exc:
        raise UnpackError(f"PNG recipe zlib deflate failed: {exc}") from exc
    parts: list[bytes] = [PNG_SIG]
    z_pos = 0
    ni = 0
    for entry in chunks_spec:
        try:
            typ = str(entry["t"]).encode("latin1")
            crc = bytes.fromhex(str(entry["crc"]))
        except (KeyError, UnicodeEncodeError, ValueError) as exc:
            raise UnpackError(f"malformed PNG chunk metadata: {exc}") from exc
        if len(typ) != 4 or len(crc) != 4:
            raise UnpackError("invalid PNG chunk type or CRC length")
        if typ == b"IDAT":
            try:
                n = int(entry["n"])
            except (KeyError, ValueError, TypeError) as exc:
                raise UnpackError("invalid PNG IDAT chunk length") from exc
            if n < 0 or z_pos + n > len(z_stream):
                raise UnpackError("PNG IDAT split out of bounds")
            body = z_stream[z_pos : z_pos + n]
            z_pos += n
        else:
            body = non_idat[ni]
            ni += 1
        parts.extend((struct.pack(">I", len(body)), typ, body, crc))
    if z_pos != len(z_stream):
        raise UnpackError("PNG recipe IDAT length mismatch")
    if trailing:
        parts.append(trailing)
    return b"".join(parts)


def _decode_mp4_dedup_standalone(
    payload: bytes,
    media: dict[str, Any],
    read_ref_range: Callable[[int, int], bytes],
    emit: Callable[[bytes], None],
) -> None:
    exp_size = media.get("stored_size")
    if isinstance(exp_size, int) and len(payload) != exp_size:
        raise UnpackError("MP4 dedup stored size mismatch")
    if len(payload) < 8 or payload[:4] != MP4_DEDUP_MAGIC:
        raise UnpackError("invalid MP4 packet-dedup magic")
    tlen = struct.unpack_from("<I", payload, 4)[0]
    if 8 + tlen > len(payload):
        raise UnpackError("truncated MP4 packet-dedup table")
    try:
        dec = zlib.decompressobj()
        table_raw = dec.decompress(payload[8 : 8 + tlen], MAX_MP4_TABLE_BYTES + 1)
    except zlib.error as exc:
        raise UnpackError(f"corrupted MP4 packet-dedup table: {exc}") from exc
    if not dec.eof or len(table_raw) > MAX_MP4_TABLE_BYTES or len(table_raw) % 20 != 0:
        raise UnpackError("corrupted MP4 packet-dedup table")
    skel = memoryview(payload)[8 + tlen :]
    s_pos = 0
    prev_end = 0
    for off in range(0, len(table_raw), 20):
        b_pos, a_pos, size = struct.unpack_from("<QQI", table_raw, off)
        if b_pos < prev_end or size == 0:
            raise UnpackError("invalid MP4 packet-dedup span")
        gap = b_pos - prev_end
        if s_pos + gap > len(skel):
            raise UnpackError("MP4 packet-dedup skeleton truncated")
        if gap:
            emit(bytes(skel[s_pos : s_pos + gap]))
            s_pos += gap
        ref_b = read_ref_range(a_pos, size)
        if len(ref_b) != size:
            raise UnpackError("MP4 packet-dedup reference out of bounds")
        emit(ref_b)
        prev_end = b_pos + size
    if s_pos < len(skel):
        emit(bytes(skel[s_pos:]))


def _rebuild_mkv_standalone(
    skeleton_chunks: Iterable[bytes],
    spans: list[list[Any]],
    get_asset: Callable[[str], bytes],
    emit: Callable[[bytes], None],
) -> None:
    if not isinstance(spans, list):
        raise UnpackError("malformed MKV attachment spans list")
    parsed: list[tuple[int, int, str]] = []
    prev_end = 0
    for sp in spans:
        if not isinstance(sp, (list, tuple)) or len(sp) != 3:
            raise UnpackError("malformed MKV attachment span")
        try:
            off, length, sha = int(sp[0]), int(sp[1]), str(sp[2])
        except (ValueError, TypeError) as exc:
            raise UnpackError("invalid MKV attachment span values") from exc
        if off < prev_end or length <= 0:
            raise UnpackError("overlapping MKV attachment span")
        parsed.append((off, length, sha))
        prev_end = off + length
    it = iter(skeleton_chunks)
    buf = b""
    bp = 0

    def take(n: int) -> None:
        nonlocal buf, bp
        rem = n
        while rem > 0:
            if bp >= len(buf):
                try:
                    buf = next(it)
                except StopIteration as exc:
                    raise UnpackError("MKV skeleton truncated") from exc
                bp = 0
                if not buf:
                    continue
            step = min(rem, len(buf) - bp)
            emit(buf[bp : bp + step])
            bp += step
            rem -= step

    out_pos = 0
    for off, length, sha in parsed:
        gap = off - out_pos
        if gap:
            take(gap)
            out_pos += gap
        blob = get_asset(sha)
        if len(blob) != length:
            raise UnpackError("MKV asset size mismatch")
        emit(blob)
        out_pos += length
    if bp < len(buf):
        emit(buf[bp:])
    for rem_c in it:
        if rem_c:
            emit(rem_c)


# ------------------------- Standalone FTT1 Tensor-Train Decoder -------------------------

_FTT_MAGIC = b"FTT1"
_FTT_HDR_FMT = "<4sBBI"
_FTT_HDR_SIZE = struct.calcsize(_FTT_HDR_FMT)
_FTT_DIGEST_SIZE = 32
_FTT_MAX_RANK = 64
_FTT_MAX_SITES = 48
_FTT_DTYPE_INFO: dict[str, tuple[str, int, bool, bool, str]] = {
    "|u1": ("B", 1, False, False, "|"),
    "|i1": ("b", 1, False, True, "|"),
    "<u2": ("H", 2, False, False, "<"),
    "<i2": ("h", 2, False, True, "<"),
    "<u4": ("I", 4, False, False, "<"),
    "<i4": ("i", 4, False, True, "<"),
    "<u8": ("Q", 8, False, False, "<"),
    "<i8": ("q", 8, False, True, "<"),
    ">u2": ("H", 2, False, False, ">"),
    ">i2": ("h", 2, False, True, ">"),
    ">u4": ("I", 4, False, False, ">"),
    ">i4": ("i", 4, False, True, ">"),
    "<f2": ("e", 2, True, True, "<"),
    "<f4": ("f", 4, True, True, "<"),
    "<f8": ("d", 8, True, True, "<"),
    ">f2": ("e", 2, True, True, ">"),
    ">f4": ("f", 4, True, True, ">"),
    ">f8": ("d", 8, True, True, ">"),
}
_FTT_INT_BOUNDS: dict[str, tuple[int, int]] = {
    "B": (0, 255),
    "b": (-128, 127),
    "H": (0, 65535),
    "h": (-32768, 32767),
    "I": (0, 4294967295),
    "i": (-2147483648, 2147483647),
    "Q": (0, (1 << 64) - 1),
    "q": (-(1 << 63), (1 << 63) - 1),
}
_FTT_UINT_CHARS: dict[int, str] = {1: "B", 2: "H", 4: "I", 8: "Q"}


def _ftt_decompress_stream(data: bytes, codec: str, max_size: int) -> bytes:
    if codec == "zstd":
        try:
            from compression import zstd as _czstd  # type: ignore[import-not-found]
        except ImportError as exc:
            raise UnpackError(
                "tt_array stream requires Python 3.14+ compression.zstd"
            ) from exc
        try:
            dobj_z = _czstd.ZstdDecompressor()
            out = dobj_z.decompress(data, max_length=max_size + 1)
        except Exception as exc:  # noqa: BLE001
            raise UnpackError(f"tt_array zstd decode failed: {exc}") from exc
        if len(out) > max_size or not dobj_z.eof:
            raise UnpackError("tt_array decompressed stream exceeds safety cap")
        return out
    if codec == "zlib":
        try:
            dobj = zlib.decompressobj()
            out = dobj.decompress(data, max_size + 1)
            if len(out) > max_size or dobj.unconsumed_tail:
                raise UnpackError("tt_array decompressed stream exceeds safety cap")
            return out
        except zlib.error as exc:
            raise UnpackError(f"tt_array zlib decode failed: {exc}") from exc
    raise UnpackError(f"unsupported tt_array stream codec: {codec!r}")


def _ftt_untranspose(planes: bytes, itemsize: int) -> bytes:
    if itemsize <= 1 or not planes:
        return planes
    n = len(planes) // itemsize
    out = bytearray(len(planes))
    for b_idx in range(itemsize):
        out[b_idx::itemsize] = planes[b_idx * n : (b_idx + 1) * n]
    return bytes(out)


def _ftt_decode_block_pure(
    bmeta: dict[str, Any], comp_body: bytes, max_output_bytes: int
) -> bytes:
    dtype_str = str(bmeta.get("dtype") or "")
    if dtype_str not in _FTT_DTYPE_INFO:
        raise UnpackError(f"unsupported tt_array dtype: {dtype_str!r}")
    s_char, itemsize, is_float, _, endian = _FTT_DTYPE_INFO[dtype_str]
    raw_shape = bmeta.get("shape")
    if (
        not isinstance(raw_shape, list)
        or not raw_shape
        or any(type(d) is not int or d <= 0 for d in raw_shape)
    ):
        raise UnpackError("invalid tt_array shape")
    orig_shape = tuple(int(d) for d in raw_shape)
    orig_elems = math.prod(orig_shape)
    if orig_elems * itemsize > max_output_bytes:
        raise UnpackError("tt_array output exceeds safety cap")

    stages = bmeta.get("stages")
    if not isinstance(stages, list) or not (1 <= len(stages) <= 2):
        raise UnpackError("invalid tt_array stages")
    max_pad_elems = min(512 * 1024 * 1024, max(orig_elems * 4, 4096))
    for st in stages:
        if not isinstance(st, dict):
            raise UnpackError("malformed tt_array stage")
        modes = st.get("modes")
        perm = st.get("perm")
        cshapes = st.get("core_shapes")
        pshp = st.get("padded_shape")
        clen_v = st.get("core_byte_len")
        if (
            not isinstance(modes, list)
            or not (1 <= len(modes) <= _FTT_MAX_SITES)
            or not isinstance(perm, list)
            or len(perm) != len(modes)
            or not isinstance(cshapes, list)
            or len(cshapes) != len(modes)
            or not isinstance(pshp, list)
            or st.get("q_bits") not in (15, 24)
            or type(clen_v) is not int
            or clen_v < 0
            or sorted(int(x) for x in perm) != list(range(len(modes)))
        ):
            raise UnpackError("malformed tt_array stage metadata")
        prev_r = 1
        tpad = 1
        for m, cs in zip(modes, cshapes, strict=True):
            if (
                type(m) is not int
                or m <= 0
                or m > 1024 * 1024
                or not isinstance(cs, list)
                or len(cs) != 3
                or any(type(v) is not int or v <= 0 for v in cs)
                or cs[0] != prev_r
                or cs[1] != m
                or cs[2] > _FTT_MAX_RANK
            ):
                raise UnpackError("invalid tt_array core shape")
            tpad *= m
            if tpad > max_pad_elems:
                raise UnpackError("tt_array padded size exceeds safety cap")
            prev_r = cs[2]
        if prev_r != 1 or tpad != math.prod(int(x) for x in pshp):
            raise UnpackError("tt_array shape/rank mismatch")
        if len(pshp) == len(orig_shape):
            for p, o in zip(pshp, orig_shape, strict=True):
                if int(p) < int(o):
                    raise UnpackError("tt_array padded_shape smaller than orig_shape")
        elif not (len(pshp) == 1 and int(pshp[0]) >= orig_elems):
            raise UnpackError("tt_array incompatible padded_shape")
        pref_prod = 1
        max_work = min((512 * 1024 * 1024) // 8, max(tpad * 64, 65536))
        for m, cs in zip(modes, cshapes, strict=True):
            pref_prod *= m
            if pref_prod * cs[2] > max_work:
                raise UnpackError("tt_array contraction workspace exceeds safety cap")

    res_len = bmeta.get("residual_byte_len", 0)
    if type(res_len) is not int or res_len < 0:
        raise UnpackError("invalid tt_array residual_byte_len")
    total_exp = sum(int(st["core_byte_len"]) for st in stages) + res_len
    if total_exp > max_output_bytes + 64 * 1024 * 1024:
        raise UnpackError("tt_array uncompressed payload exceeds safety cap")
    uncomp = _ftt_decompress_stream(
        comp_body, str(bmeta.get("comp_codec") or "zstd"), max(total_exp, 1024)
    )
    if len(uncomp) != total_exp:
        raise UnpackError("tt_array uncompressed length mismatch")

    pos = 0
    acc: list[Any] | None = None
    for st in stages:
        clen = int(st["core_byte_len"])
        blob = uncomp[pos : pos + clen]
        pos += clen
        q_bits = int(st["q_bits"])
        s_last = int(st["s_last"])
        c_isz = 2 if q_bits == 15 else 4
        raw_c = _ftt_untranspose(blob, c_isz)
        tot_v = sum(s[0] * s[1] * s[2] for s in st["core_shapes"])
        if len(raw_c) != tot_v * c_isz:
            raise UnpackError("tt_array core size mismatch")
        u_vals = struct.unpack(f"<{tot_v}{'H' if c_isz == 2 else 'I'}", raw_c)
        i_vals = [(u >> 1) ^ -(u & 1) for u in u_vals]
        q_cores: list[tuple[tuple[int, int, int], list[int]]] = []
        cp = 0
        for s in st["core_shapes"]:
            cnt = s[0] * s[1] * s[2]
            q_cores.append(((s[0], s[1], s[2]), i_vals[cp : cp + cnt]))
            cp += cnt

        as_int = (not is_float) and len(stages) == 1
        n_sites = len(q_cores)
        if n_sites == 1:
            prod = q_cores[0][1]
            q_eff = 0
        else:
            half = 1 << (q_bits - 1)
            (_, n0, r1), c0 = q_cores[0]
            cur_rows = [c0[i * r1 : (i + 1) * r1] for i in range(n0)]
            for k in range(1, n_sites - 1):
                (rl, nk, rr), ck = q_cores[k]
                cols = nk * rr
                ck_rows = [ck[i * cols : (i + 1) * cols] for i in range(rl)]
                nxt_rows: list[list[int]] = []
                for row in cur_rows:
                    ac = [0] * cols
                    for il in range(rl):
                        rv = row[il]
                        if rv:
                            cr = ck_rows[il]
                            for j in range(cols):
                                ac[j] += rv * cr[j]
                    for mi in range(nk):
                        b = mi * rr
                        nxt_rows.append(
                            [(ac[b + j] + half) >> q_bits for j in range(rr)]
                        )
                cur_rows = nxt_rows
            (rl, nlast, _), clast = q_cores[-1]
            cl_rows = [clast[i * nlast : (i + 1) * nlast] for i in range(rl)]
            prod = []
            for row in cur_rows:
                ac = [0] * nlast
                for il in range(rl):
                    rv = row[il]
                    if rv:
                        cr = cl_rows[il]
                        for j in range(nlast):
                            ac[j] += rv * cr[j]
                prod.extend(ac)
            q_eff = q_bits

        if as_int:
            rshift = q_eff - s_last
            if rshift > 0:
                if rshift >= 63:
                    flat_v: list[Any] = [0] * len(prod)
                else:
                    rh = 1 << (rshift - 1)
                    flat_v = [(v + rh) >> rshift for v in prod]
            else:
                ls = -rshift
                if ls == 0:
                    flat_v = list(prod)
                elif ls >= 62:
                    lim = (1 << 62) - 1
                    flat_v = [lim if v > 0 else (-lim if v < 0 else 0) for v in prod]
                else:
                    shi = ((1 << 62) - 1) >> ls
                    slo = -shi
                    flat_v = [
                        (slo if v < slo else (shi if v > shi else v)) << ls
                        for v in prod
                    ]
        else:
            shift_pre = 6 if (q_eff == 24) else 0
            tot_exp_f = s_last - (q_eff - shift_pre)
            if shift_pre:
                sh = 1 << (shift_pre - 1)
                flat_v = [
                    math.ldexp(float((v + sh) >> shift_pre), tot_exp_f) for v in prod
                ]
            else:
                flat_v = [math.ldexp(float(v), tot_exp_f) for v in prod]

        # Undo permutation & crop padded_shape -> orig_shape
        modes = [int(x) for x in st["modes"]]
        perm = [int(x) for x in st["perm"]]
        pshp = tuple(int(x) for x in st["padded_shape"])
        n_m = len(modes)
        if perm != list(range(n_m)):
            omodes = [0] * n_m
            for ni, oi in enumerate(perm):
                omodes[oi] = modes[ni]
            p_st = [1] * n_m
            for i in range(n_m - 2, -1, -1):
                p_st[i] = p_st[i + 1] * modes[i + 1]
            o2p = [0] * n_m
            for ni, oi in enumerate(perm):
                o2p[oi] = p_st[ni]
            u_st = [1] * n_m
            for i in range(n_m - 2, -1, -1):
                u_st[i] = u_st[i + 1] * omodes[i + 1]
            unp = [flat_v[0]] * len(flat_v)
            for idx in range(len(flat_v)):
                rem = idx
                pi = 0
                for mi in range(n_m):
                    co, rem = divmod(rem, u_st[mi])
                    pi += co * o2p[mi]
                unp[idx] = flat_v[pi]
            cur_v = unp
        else:
            cur_v = flat_v
        if pshp != orig_shape:
            if len(pshp) == 1 and len(orig_shape) > 1:
                cur_v = cur_v[: math.prod(orig_shape)]
            else:
                nd = len(orig_shape)
                p_s = [1] * nd
                o_s = [1] * nd
                for i in range(nd - 2, -1, -1):
                    p_s[i] = p_s[i + 1] * pshp[i + 1]
                    o_s[i] = o_s[i + 1] * orig_shape[i + 1]
                tot_o = math.prod(orig_shape)
                cropped = [cur_v[0]] * tot_o
                for idx in range(tot_o):
                    rem = idx
                    pi = 0
                    for ax in range(nd):
                        co, rem = divmod(rem, o_s[ax])
                        pi += co * p_s[ax]
                    cropped[idx] = cur_v[pi]
                cur_v = cropped
        acc = cur_v if acc is None else [a + b for a, b in zip(acc, cur_v, strict=True)]

    assert acc is not None
    if bool(bmeta.get("fortran_order", False)) and len(orig_shape) > 1:
        nd = len(orig_shape)
        c_s = [1] * nd
        for i in range(nd - 2, -1, -1):
            c_s[i] = c_s[i + 1] * orig_shape[i + 1]
        f_s = [1] * nd
        for i in range(1, nd):
            f_s[i] = f_s[i - 1] * orig_shape[i - 1]
        reord = [acc[0]] * len(acc)
        for fi in range(len(acc)):
            rem = fi
            ci = 0
            for ax in range(nd - 1, -1, -1):
                co, rem = divmod(rem, f_s[ax])
                ci += co * c_s[ax]
            reord[fi] = acc[ci]
        acc = reord

    pref = endian if endian != "|" else ""
    if is_float:

        def _sf(v: float) -> float:
            if not math.isfinite(v):
                return v
            if s_char == "e" and abs(v) > 65504.0:
                return math.copysign(math.inf, v)
            if s_char == "f" and abs(v) > 3.4028234663852886e38:
                return math.copysign(math.inf, v)
            return v

        pred_raw = struct.pack(
            f"{pref}{len(acc)}{s_char}", *(_sf(float(v)) for v in acc)
        )
    else:
        lo, hi = _FTT_INT_BOUNDS[s_char]
        hi_eff = min(hi, (1 << 63) - 1)
        pred_raw = struct.pack(
            f"{pref}{len(acc)}{s_char}",
            *(lo if v < lo else (hi_eff if v > hi_eff else int(v)) for v in acc),
        )

    if str(bmeta.get("mode") or "lossless") == "lossless":
        res_planes = uncomp[pos:]
        zz_raw = _ftt_untranspose(res_planes, itemsize)
        if len(zz_raw) != len(pred_raw):
            raise UnpackError("tt_array residual size mismatch")
        n = len(pred_raw) // itemsize
        u_ch = _FTT_UINT_CHARS[itemsize]
        u_p = struct.unpack(f"{pref}{n}{u_ch}", pred_raw)
        zz_v = struct.unpack(f"<{n}{u_ch}", zz_raw)
        bits = itemsize * 8
        mask = (1 << bits) - 1
        sign = 1 << (bits - 1)
        out_u = [0] * n
        for i in range(n):
            b = u_p[i]
            if is_float:
                b = (~b & mask) if (b & sign) else (b | sign)
            z = zz_v[i]
            d = (z >> 1) ^ (-(z & 1))
            o = (b + d) & mask
            if is_float:
                o = (o ^ sign) if (o & sign) else (~o & mask)
            out_u[i] = o
        return struct.pack(f"{pref}{n}{u_ch}", *out_u)

    overrides = bmeta.get("overrides") or []
    if overrides:
        u_ch = _FTT_UINT_CHARS[itemsize]
        buf = bytearray(pred_raw)
        for idx_o, bits_u in overrides:
            off = int(idx_o) * itemsize
            if 0 <= off and off + itemsize <= len(buf):
                buf[off : off + itemsize] = struct.pack(f"{pref}{u_ch}", int(bits_u))
        return bytes(buf)
    return pred_raw


def _decode_tt_array_standalone(
    stored: bytes, max_output_bytes: int, pure_python: bool = False
) -> bytes:
    """Decode an `FTT1` tensor-pack payload (delegates to shared module when fast path allowed, else pure Python)."""
    if not pure_python:
        resolved_here = Path(__file__).resolve()
        if len(resolved_here.parents) > 3:
            shared_dir = resolved_here.parents[3] / "shared"
            if (shared_dir / "forge_tensor_pack.py").is_file():
                if str(shared_dir) not in sys.path:
                    sys.path.insert(0, str(shared_dir))
                import forge_tensor_pack as ftp  # noqa: PLC0415

                try:
                    return ftp.decode_ftt1(stored, max_output_bytes=max_output_bytes)
                except ftp.TensorPackError as exc:
                    raise UnpackError(str(exc)) from exc

    if len(stored) < _FTT_HDR_SIZE + _FTT_DIGEST_SIZE:
        raise UnpackError("FTT1 payload truncated")
    magic, ver, _, mlen = struct.unpack_from(_FTT_HDR_FMT, stored, 0)
    if magic != _FTT_MAGIC or ver != 1 or mlen <= 0 or mlen > 16 * 1024 * 1024:
        raise UnpackError("invalid FTT1 header")
    mend = _FTT_HDR_SIZE + mlen
    if mend + _FTT_DIGEST_SIZE > len(stored):
        raise UnpackError("FTT1 metadata out of bounds")
    if (
        hashlib.sha256(stored[:-_FTT_DIGEST_SIZE]).digest()
        != stored[-_FTT_DIGEST_SIZE:]
    ):
        raise UnpackError("FTT1 SHA-256 integrity check failed")
    try:
        meta = json.loads(stored[_FTT_HDR_SIZE:mend].decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise UnpackError(f"invalid FTT1 metadata JSON: {exc}") from exc
    if not isinstance(meta, dict):
        raise UnpackError("malformed FTT1 metadata")
    body = stored[mend:-_FTT_DIGEST_SIZE]
    kind = str(meta.get("kind") or "")

    try:
        if kind in ("npy", "pnm"):
            if len(body) < 4:
                raise UnpackError(f"truncated {kind} FTT1 body")
            hlen = struct.unpack_from("<I", body, 0)[0]
            if 4 + hlen > len(body):
                raise UnpackError(f"invalid {kind} FTT1 header length")
            blk = meta.get("block")
            if not isinstance(blk, dict):
                raise UnpackError("missing FTT1 block metadata")
            out = body[4 : 4 + hlen] + _ftt_decode_block_pure(
                blk, body[4 + hlen :], max_output_bytes
            )
        elif kind == "wav":
            if len(body) < 8:
                raise UnpackError("truncated wav FTT1 body")
            plen, slen = struct.unpack_from("<II", body, 0)
            if 8 + plen + slen > len(body):
                raise UnpackError("invalid wav FTT1 framing lengths")
            blk = meta.get("block")
            if not isinstance(blk, dict):
                raise UnpackError("missing FTT1 block metadata")
            out = (
                body[8 : 8 + plen]
                + _ftt_decode_block_pure(blk, body[8 + plen + slen :], max_output_bytes)
                + body[8 + plen : 8 + plen + slen]
            )
        elif kind == "npz":
            if len(body) < 4:
                raise UnpackError("truncated npz FTT1 body")
            sclen = struct.unpack_from("<I", body, 0)[0]
            if 4 + sclen > len(body):
                raise UnpackError("invalid npz FTT1 skeleton length")
            slens = meta.get("skel_lens")
            members = meta.get("members")
            if (
                not isinstance(slens, list)
                or not isinstance(members, list)
                or len(slens) != len(members) + 1
            ):
                raise UnpackError("malformed npz FTT1 metadata")
            skel_tot = sum(int(x) for x in slens)
            skel = _ftt_decompress_stream(
                body[4 : 4 + sclen],
                str(meta.get("skel_codec") or "zstd"),
                max(skel_tot, 1024),
            )
            if len(skel) != skel_tot:
                raise UnpackError("npz FTT1 skeleton length mismatch")
            out_b = bytearray()
            sp = 0
            bp = 4 + sclen
            patched: list[tuple[int, int, bytes]] = []
            is_lossy = str(meta.get("mode") or "lossless") == "lossy"
            for idx, ms in enumerate(members):
                sl = int(slens[idx])
                out_b.extend(skel[sp : sp + sl])
                sp += sl
                bl = int(ms["blob_len"])
                if bl < 0 or bp + bl > len(body):
                    raise UnpackError("truncated npz FTT1 member blob")
                blob = body[bp : bp + bl]
                bp += bl
                doff = len(out_b)
                if ms.get("kind") == "tt_npy":
                    if len(blob) < 4:
                        raise UnpackError("truncated tt_npy FTT1 member")
                    hl = struct.unpack_from("<I", blob, 0)[0]
                    if 4 + hl > len(blob):
                        raise UnpackError("invalid tt_npy FTT1 header length")
                    mb = blob[4 : 4 + hl] + _ftt_decode_block_pure(
                        ms["block"], blob[4 + hl :], max_output_bytes
                    )
                    out_b.extend(mb)
                    if is_lossy:
                        patched.append((doff, len(mb), mb))
                elif ms.get("kind") == "raw_comp":
                    mb = _ftt_decompress_stream(
                        blob,
                        str(ms.get("comp_codec") or "zstd"),
                        max(int(ms.get("orig_size", 0)), 1024),
                    )
                    out_b.extend(mb)
                else:
                    raise UnpackError(
                        f"unsupported npz member kind: {ms.get('kind')!r}"
                    )
                if len(out_b) > max_output_bytes:
                    raise UnpackError("decoded npz exceeds safety cap")
            out_b.extend(skel[sp:])
            if len(out_b) > max_output_bytes:
                raise UnpackError("decoded npz exceeds safety cap")
            if is_lossy and patched:
                eocd = out_b.rfind(b"PK\x05\x06", max(0, len(out_b) - 65557))
                if eocd >= 0 and eocd + 22 <= len(out_b):
                    cd_sz, cd_off = struct.unpack_from("<II", out_b, eocd + 12)
                    crc_map = {
                        doff: zlib.crc32(pl) & 0xFFFFFFFF for doff, _, pl in patched
                    }
                    cp = cd_off
                    cend = min(len(out_b), cd_off + cd_sz)
                    while cp + 46 <= cend and out_b[cp : cp + 4] == b"PK\x01\x02":
                        fl, el, cl = struct.unpack_from("<HHH", out_b, cp + 28)
                        lho = struct.unpack_from("<I", out_b, cp + 42)[0]
                        if (
                            lho + 30 <= len(out_b)
                            and out_b[lho : lho + 4] == b"PK\x03\x04"
                        ):
                            lfl, lel = struct.unpack_from("<HH", out_b, lho + 26)
                            do = lho + 30 + lfl + lel
                            if do in crc_map:
                                struct.pack_into("<I", out_b, lho + 14, crc_map[do])
                                struct.pack_into("<I", out_b, cp + 16, crc_map[do])
                        cp += 46 + fl + el + cl
            out = bytes(out_b)
        else:
            raise UnpackError(f"unsupported FTT1 kind: {kind!r}")
    except (KeyError, TypeError, ValueError, struct.error) as exc:
        raise UnpackError(f"malformed FTT1 payload: {exc}") from exc

    if hashlib.sha256(out).hexdigest() != str(meta.get("reconstructed_sha256") or ""):
        raise UnpackError("FTT1 decoded output SHA-256 mismatch")
    return out


def _safe_rel_path(rel: str) -> Path:
    if (
        not rel
        or rel.startswith("/")
        or rel.startswith("\\")
        or "\\" in rel
        or "\x00" in rel
    ):
        raise UnpackError(f"unsafe archive path: {rel!r}")
    segs = rel.split("/")
    if any(seg in ("", ".", "..") or ":" in seg for seg in segs):
        raise UnpackError(f"path traversal rejected: {rel!r}")
    p = Path(*segs)
    if p.is_absolute() or p.drive or p.root:
        raise UnpackError(f"path traversal rejected: {rel!r}")
    return p


def _ensure_safe_target(out_root: Path, rel: Path) -> Path:
    cur = out_root
    for part in rel.parts[:-1]:
        nxt = cur / part
        if nxt.is_symlink():
            raise UnpackError(f"refusing to traverse symlink directory: {nxt}")
        if not nxt.resolve().is_relative_to(out_root):
            raise UnpackError(f"path escapes destination root: {nxt}")
        nxt.mkdir(exist_ok=True)
        cur = nxt
    target = cur / rel.parts[-1]
    if target.is_symlink() or not target.resolve().is_relative_to(out_root):
        raise UnpackError(f"unsafe target path: {target}")
    return target


def unpack_or_verify(
    pack_path: Path,
    dest_dir: Path | None,
    *,
    passphrase: str | None = None,
    verify_only: bool = False,
    pure_python: bool = False,
) -> dict[str, Any]:
    """Verify or unpack a `.fpack` or `.fvlt` archive using native C or pure Python."""
    t0 = time.perf_counter()
    if not pack_path.is_file():
        raise UnpackError(f"file does not exist: {pack_path}")
    file_size = pack_path.stat().st_size
    if file_size < HEADER_SIZE + FOOTER_SIZE + MANIFEST_PREFIX_SIZE + 16:
        raise UnpackError("pack file truncated or invalid")

    with pack_path.open("rb") as f:
        header = f.read(HEADER_SIZE)
        (
            magic,
            ver,
            cipher_id,
            prof_id,
            flags,
            _mem_kib,
            _iters,
            _lanes,
            salt,
            chunk_cnt,
        ) = struct.unpack(HEADER_FMT, header)
        if magic != MAGIC or ver != 1:
            raise UnpackError("not a Forge Pack / Vault v1 file")
        if cipher_id not in CIPHER_NAMES:
            raise UnpackError(f"unsupported cipher id: {cipher_id}")

        if cipher_id != CIPHER_NONE:
            # Delegate encrypted vaults to shared/forge_vault.py when available.
            shared_dir = Path(__file__).resolve().parents[3] / "shared"
            if (shared_dir / "forge_vault.py").is_file() and not pure_python:
                if str(shared_dir) not in sys.path:
                    sys.path.insert(0, str(shared_dir))
                import forge_vault as fv  # noqa: PLC0415

                pw = (
                    passphrase
                    if passphrase is not None
                    else getpass.getpass("Vault passphrase: ")
                )
                try:
                    st = fv.unpack_vault(
                        pack_path, dest_dir, pw, verify_only=verify_only
                    )
                except fv.VaultError as exc:
                    raise UnpackError(str(exc)) from exc
                return {
                    "engine": "native-c",
                    "files": st.files,
                    "raw_bytes": st.raw_bytes,
                    "vault_bytes": st.vault_bytes,
                    "elapsed_sec": st.elapsed_sec,
                    "throughput_mbs": st.throughput_mbs,
                    "encrypted": True,
                }
            raise UnpackError(
                "encrypted .fvlt unpacking requires libforge_vault.so / forge_vault.dll "
                "(unencrypted .fpack files unpack anywhere in pure Python)"
            )

        lib = None if pure_python else _try_load_native()
        engine_name = "native-c" if lib is not None else "pure-python"

        def b3(data: bytes) -> bytes:
            if lib is not None:
                out = ctypes.create_string_buffer(32)
                lib.fv_blake3(data, len(data), out)
                return out.raw
            return blake3_pure(data)

        def b3_keyed(key: bytes, data: bytes) -> bytes:
            if lib is not None:
                out = ctypes.create_string_buffer(32)
                lib.fv_keyed_blake3(key, data, len(data), out)
                return out.raw
            return blake3_pure(data, key=key)

        def dec_chunk(codec_id: int, comp: bytes, raw_len: int, d: bytes) -> bytes:
            if lib is not None:
                out = ctypes.create_string_buffer(max(raw_len, 1))
                got = int(
                    lib.fv_decompress(
                        codec_id,
                        comp,
                        len(comp),
                        d if d else None,
                        len(d),
                        out,
                        raw_len,
                    )
                )
                if got != raw_len:
                    raise UnpackError(f"native decode failed (codec={codec_id})")
                return out.raw[:raw_len]
            return decompress_pure(codec_id, comp, raw_len, d)

        f.seek(file_size - FOOTER_SIZE)
        manifest_offset, fmagic = struct.unpack(FOOTER_FMT, f.read(FOOTER_SIZE))
        if (
            fmagic != FOOTER_MAGIC
            or manifest_offset < HEADER_SIZE
            or manifest_offset >= file_size - FOOTER_SIZE
        ):
            raise UnpackError("invalid pack footer")

        f.seek(manifest_offset)
        m_nlen, m_clen = struct.unpack(
            MANIFEST_PREFIX_FMT, f.read(MANIFEST_PREFIX_SIZE)
        )
        if (
            m_nlen != 0
            or m_clen < 32
            or manifest_offset + MANIFEST_PREFIX_SIZE + m_clen + FOOTER_SIZE
            != file_size
        ):
            raise UnpackError("invalid manifest bounds")
        m_payload = f.read(m_clen)
        m_comp, m_tag = m_payload[:-32], m_payload[-32:]
        m_aad = header + struct.pack("<QBI", manifest_offset, 0, m_clen)
        if b3(m_aad + m_comp) != m_tag:
            raise UnpackError("manifest BLAKE3 integrity check failed")
        m_plen = struct.unpack_from("<I", m_comp, 0)[0]
        if m_plen < 4 or m_plen > MAX_MANIFEST_PLAIN_BYTES:
            raise UnpackError("invalid manifest uncompressed size")
        m_codec = (
            CODEC_KRAKEN_HUFF8
            if (flags & HEADER_FLAG_MANIFEST_KRAKEN)
            else CODEC_ZSTD_FAST
        )
        m_plain = dec_chunk(m_codec, m_comp, m_plen, b"")
        json_len = struct.unpack_from("<I", m_plain, 0)[0]
        manifest = json.loads(m_plain[4 : 4 + json_len].decode("utf-8"))
        dict_bytes = m_plain[4 + json_len :]
        dedup_key = b3(b"forge-vault-v1:plain-dedup:" + salt)

        chunk_records: list[tuple[bytes, int, int, int, int, int]] = []
        f.seek(HEADER_SIZE)
        for idx in range(chunk_cnt):
            hdr = f.read(CHUNK_HDR_SIZE)
            if len(hdr) != CHUNK_HDR_SIZE:
                raise UnpackError(f"truncated chunk header at {idx}")
            cid, codec_id, chunk_flags, raw_len, nlen, ct_len = struct.unpack(
                CHUNK_HDR_FMT, hdr
            )
            off = f.tell()
            if (
                nlen != 0
                or raw_len > MAX_CHUNK_RAW_BYTES
                or ct_len < 36
                or off + ct_len > manifest_offset
            ):
                raise UnpackError(f"invalid chunk bounds at {idx}")
            f.seek(ct_len, os.SEEK_CUR)
            chunk_records.append((cid, codec_id, chunk_flags, raw_len, off, ct_len))
        if f.tell() != manifest_offset:
            raise UnpackError("unauthenticated gap between chunk store and manifest")

        decoded_cache: dict[int, bytes] = {}
        verified_chunks: set[int] = set()
        decoded_assets: dict[str, bytes] = {}
        raw_files = manifest.get("files")
        if not isinstance(raw_files, list):
            raise UnpackError("malformed manifest files list")
        entries_by_path: dict[str, dict[str, Any]] = {}
        for fe in raw_files:
            if (
                not isinstance(fe, dict)
                or not isinstance(fe.get("path"), str)
                or type(fe.get("size")) is not int
                or fe["size"] < 0
                or not isinstance(fe.get("chunks"), list)
            ):
                raise UnpackError("malformed file entry in manifest")
            entries_by_path[fe["path"]] = fe
        raw_assets = manifest.get("media_assets")
        if raw_assets is None:
            media_assets_spec: dict[str, dict[str, Any]] = {}
        elif isinstance(raw_assets, dict):
            media_assets_spec = raw_assets
        else:
            raise UnpackError("malformed manifest media_assets")
        ref_tables: dict[str, tuple[list[int], list[int]]] = {}

        def _valid_ci(val: Any) -> bool:
            return type(val) is int and 0 <= val < chunk_cnt

        png_recipe_files = 0
        png_stored_files = 0  # level-0 recipes (stored blocks)
        for fe in raw_files:
            for ci in fe["chunks"]:
                if not _valid_ci(ci):
                    raise UnpackError(f"invalid chunk index {ci}")
            media = fe.get("media")
            if media is not None:
                if not isinstance(media, dict):
                    raise UnpackError(f"malformed media metadata for {fe['path']!r}")
                st_name = media.get("stage")
                if st_name == "png_recipe_jxl":
                    png_recipe_files += 1
                    recipe = media.get("recipe")
                    if isinstance(recipe, list) and recipe and recipe[0] == 0:
                        png_stored_files += 1
                elif st_name == "mp4_packet_dedup":
                    rp = media.get("ref_path")
                    if not isinstance(rp, str) or not rp:
                        raise UnpackError("missing mp4_packet_dedup ref_path")
                    rfe = entries_by_path.get(rp)
                    if rfe is None or rfe.get("media") is not None:
                        raise UnpackError(f"invalid mp4_packet_dedup ref_path {rp!r}")
                elif st_name == "mkv_font_dedup":
                    sp_val = media.get("spans")
                    if not isinstance(sp_val, list):
                        raise UnpackError("malformed mkv_font_dedup spans")
                    for sp in sp_val:
                        if not isinstance(sp, (list, tuple)) or len(sp) != 3:
                            raise UnpackError("malformed mkv_font_dedup span")
                        asha = str(sp[2])
                        aspec = media_assets_spec.get(asha)
                        if (
                            not isinstance(aspec, dict)
                            or type(aspec.get("size")) is not int
                            or aspec["size"] < 0
                            or not isinstance(aspec.get("chunks"), list)
                        ):
                            raise UnpackError(f"missing or malformed asset {asha!r}")
                        for aci in aspec["chunks"]:
                            if not _valid_ci(aci):
                                raise UnpackError(f"invalid asset chunk index {aci}")
        if png_recipe_files:  # refuse before writing anything (zlib-ng here)
            try:
                _classic_deflate(stored=png_stored_files > 0)
            except UnpackError as exc:
                raise UnpackError(f"{exc} Nothing was written.") from None

        def read_chunk(ci: int) -> bytes:
            if not _valid_ci(ci):
                raise UnpackError(f"invalid chunk index {ci}")
            if ci in decoded_cache:
                return decoded_cache[ci]
            cid, codec_id, chunk_flags, raw_len, off, ct_len = chunk_records[ci]
            f.seek(off)
            payload = f.read(ct_len)
            comp, tag = payload[:-32], payload[-32:]
            aad = MAGIC + cid + struct.pack("<BBIQ", codec_id, chunk_flags, raw_len, ci)
            if b3(aad + comp) != tag:
                raise UnpackError(f"chunk {ci} BLAKE3 integrity mismatch")
            used_dict = bool(chunk_flags & CHUNK_FLAG_USED_DICT)
            raw_c = dec_chunk(codec_id, comp, raw_len, dict_bytes if used_dict else b"")
            if b3_keyed(dedup_key, raw_c) != cid:
                raise UnpackError(f"chunk {ci} content hash mismatch")
            verified_chunks.add(ci)
            decoded_cache[ci] = raw_c
            return raw_c

        def read_ref_range(ref_path: str, offset: int, length: int) -> bytes:
            if ref_path not in ref_tables:
                rfe = entries_by_path.get(ref_path)
                if rfe is None or rfe.get("media") is not None:
                    raise UnpackError(f"invalid mp4_packet_dedup ref_path {ref_path!r}")
                ends: list[int] = []
                cids_l: list[int] = []
                acc = 0
                for rci in rfe["chunks"]:
                    if not _valid_ci(rci):
                        raise UnpackError(f"invalid ref chunk index {rci}")
                    acc += chunk_records[rci][3]
                    ends.append(acc)
                    cids_l.append(rci)
                ref_tables[ref_path] = (ends, cids_l)
            ends, cids_l = ref_tables[ref_path]
            if offset < 0 or length < 0 or not ends or offset + length > ends[-1]:
                raise UnpackError("mp4_packet_dedup reference range out of bounds")
            out_b = bytearray()
            cur, rem = offset, length
            idx = bisect.bisect_right(ends, cur)
            while rem > 0 and idx < len(ends):
                c_start = ends[idx - 1] if idx > 0 else 0
                raw_c = read_chunk(cids_l[idx])
                in_off = cur - c_start
                take = min(rem, len(raw_c) - in_off)
                out_b.extend(raw_c[in_off : in_off + take])
                cur += take
                rem -= take
                idx += 1
            return bytes(out_b)

        def get_asset(sha: str) -> bytes:
            if sha in decoded_assets:
                return decoded_assets[sha]
            aspec = media_assets_spec.get(sha)
            if not isinstance(aspec, dict):
                raise UnpackError(f"missing media asset {sha!r}")
            blob = b"".join(read_chunk(aci) for aci in aspec["chunks"])
            if (
                len(blob) != int(aspec["size"])
                or hashlib.sha256(blob).hexdigest() != sha
            ):
                raise UnpackError(f"media asset {sha[:12]} SHA-256 mismatch")
            decoded_assets[sha] = blob
            return blob

        out_root: Path | None = None
        if dest_dir is not None and not verify_only:
            out_root = dest_dir
            out_root.mkdir(parents=True, exist_ok=True)
            out_root = out_root.resolve()
            for ed in manifest.get("empty_dirs", []):
                ed_rel = _safe_rel_path(ed)
                cur = out_root
                for part in ed_rel.parts:
                    nxt = cur / part
                    if nxt.is_symlink() or not nxt.resolve().is_relative_to(out_root):
                        raise UnpackError(f"unsafe directory path: {ed!r}")
                    nxt.mkdir(exist_ok=True)
                    cur = nxt

        total_raw = 0
        for fe in raw_files:
            rel = _safe_rel_path(fe["path"])
            hasher = hashlib.sha256()
            target: Path | None = None
            tmp_file: Path | None = None
            out_fh = None
            if out_root is not None and not verify_only:
                target = _ensure_safe_target(out_root, rel)
                tfd, tname = tempfile.mkstemp(prefix=".fpack_out_", dir=target.parent)
                tmp_file = Path(tname)
                out_fh = os.fdopen(tfd, "wb")
            try:
                written = 0
                expected_size = int(fe["size"])
                media = fe.get("media")
                if media is None:
                    for ci in fe["chunks"]:
                        raw_c = read_chunk(ci)
                        if written + len(raw_c) > expected_size:
                            raise UnpackError(
                                f"decoded output exceeded declared size for {fe['path']}"
                            )
                        hasher.update(raw_c)
                        if out_fh is not None:
                            out_fh.write(raw_c)
                        written += len(raw_c)
                else:
                    stage = str(media.get("stage") or "")

                    def _emit_f(
                        piece: bytes,
                        _h: Any = hasher,
                        _fh: Any = out_fh,
                        _cap: int = expected_size,
                        _path: str = str(fe["path"]),
                    ) -> None:
                        nonlocal written
                        if written + len(piece) > _cap:
                            raise UnpackError(
                                f"media stage output exceeded declared size for {_path}"
                            )
                        _h.update(piece)
                        if _fh is not None:
                            _fh.write(piece)
                        written += len(piece)

                    if stage == "jxl_jpeg":
                        stored = b"".join(read_chunk(ci) for ci in fe["chunks"])
                        _emit_f(
                            _decode_jxl_jpeg_standalone(
                                stored, media, max_output_bytes=expected_size
                            )
                        )
                    elif stage == "png_recipe_jxl":
                        stored = b"".join(read_chunk(ci) for ci in fe["chunks"])
                        _emit_f(_decode_png_recipe_standalone(stored, media, lib))
                    elif stage == "mp4_packet_dedup":
                        stored = b"".join(read_chunk(ci) for ci in fe["chunks"])
                        rp = str(media["ref_path"])
                        _decode_mp4_dedup_standalone(
                            stored,
                            media,
                            lambda off, ln, rpath=rp: read_ref_range(rpath, off, ln),
                            _emit_f,
                        )
                    elif stage == "mkv_font_dedup":
                        _rebuild_mkv_standalone(
                            (read_chunk(ci) for ci in fe["chunks"]),
                            media["spans"],
                            get_asset,
                            _emit_f,
                        )
                    elif stage == "tt_array":
                        stored = b"".join(read_chunk(ci) for ci in fe["chunks"])
                        _emit_f(
                            _decode_tt_array_standalone(
                                stored, expected_size, pure_python=pure_python
                            )
                        )
                    else:
                        raise UnpackError(f"unsupported media stage: {stage!r}")
                if out_fh is not None:
                    out_fh.flush()
                    out_fh.close()
                    out_fh = None
                if written != int(fe["size"]) or hasher.hexdigest() != fe["sha256"]:
                    raise UnpackError(f"SHA-256 verification failed for {fe['path']}")
                if tmp_file is not None and target is not None:
                    if os.name == "posix":
                        os.chmod(tmp_file, int(fe.get("mode", 0o644)) & 0o777)
                    os.replace(tmp_file, target)
                    tmp_file = None
            finally:
                if out_fh is not None:
                    out_fh.close()
                if tmp_file is not None:
                    tmp_file.unlink(missing_ok=True)
            total_raw += written

        for ci in range(chunk_cnt):
            if ci not in verified_chunks:
                _ = read_chunk(ci)

    elapsed = time.perf_counter() - t0
    return {
        "engine": engine_name,
        "profile": PROFILE_NAMES.get(prof_id, "fast"),
        "files": len(manifest["files"]),
        "raw_bytes": total_raw,
        "vault_bytes": file_size,
        "elapsed_sec": elapsed,
        "throughput_mbs": (
            (total_raw / (1024 * 1024)) / elapsed if elapsed > 0 else 0.0
        ),
        "encrypted": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Forge Pack Standalone Unpacker (.fpack / .fvlt — Windows & Linux)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    for name, help_text in (
        ("info", "Inspect header metadata of a .fpack/.fvlt file"),
        ("verify", "Verify BLAKE3/AEAD tags and SHA-256 checksums without writing"),
        ("unpack", "Unpack and SHA-256 verify all files into a destination folder"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("pack", help="Path to .fpack or .fvlt file")
        if name == "unpack":
            p.add_argument(
                "dest",
                nargs="?",
                default=None,
                help="Destination folder (default: beside pack with pack's stem)",
            )
        p.add_argument(
            "--pure-python",
            action="store_true",
            help="Force pure-Python reference decoder (zero native libraries)",
        )
        p.add_argument(
            "--passphrase", default=None, help="Vault passphrase (if encrypted)"
        )

    args = parser.parse_args(argv)
    pack_path = Path(args.pack)
    try:
        if args.cmd == "info":
            with pack_path.open("rb") as f:
                hdr = f.read(HEADER_SIZE)
            magic, ver, cid, pid, flags, mem, iters, _lanes, _salt, cnt = struct.unpack(
                HEADER_FMT, hdr
            )
            if magic != MAGIC or ver != 1:
                raise UnpackError("not a Forge Pack v1 file")
            print(
                json.dumps(
                    {
                        "file": str(pack_path),
                        "size_bytes": pack_path.stat().st_size,
                        "encrypted": cid != CIPHER_NONE,
                        "cipher": CIPHER_NAMES.get(cid, str(cid)),
                        "profile": PROFILE_NAMES.get(pid, str(pid)),
                        "has_dict": bool(flags & 1),
                        "has_media": bool(flags & HEADER_FLAG_HAS_MEDIA),
                        "has_tensor": bool(flags & HEADER_FLAG_HAS_TENSOR),
                        "unique_chunks": cnt,
                        "kdf_mem_kib": mem,
                        "kdf_iters": iters,
                    },
                    indent=2,
                )
            )
            return 0
        if args.cmd == "verify":
            res = unpack_or_verify(
                pack_path,
                None,
                passphrase=args.passphrase,
                verify_only=True,
                pure_python=args.pure_python,
            )
            print(
                f"Verified OK ({res['engine']}): {res['files']} files, "
                f"{res['raw_bytes']:,} B in {res['elapsed_sec']:.3f} s "
                f"({res['throughput_mbs']:.1f} MB/s)"
            )
            return 0
        dest = Path(args.dest) if args.dest else pack_path.with_suffix("")
        res = unpack_or_verify(
            pack_path,
            dest,
            passphrase=args.passphrase,
            verify_only=False,
            pure_python=args.pure_python,
        )
        print(
            f"Unpacked OK ({res['engine']}): {res['files']} files "
            f"({res['raw_bytes']:,} B SHA-256 verified) -> {dest} "
            f"in {res['elapsed_sec']:.3f} s ({res['throughput_mbs']:.1f} MB/s)"
        )
        return 0
    except UnpackError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
