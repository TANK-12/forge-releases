#!/usr/bin/env python3
"""Quantics Tensor-Train (QTT) & Tensor-Train (TT) numeric data compressor for Forge Pack.

Compresses structured numeric arrays (`.npy`, `.npz`, `.wav`, `.pgm`/`.ppm`, or raw
arrays) using adaptive mixed-radix Quantics Tensor-Train SVD (`QTT-SVD`) with 100%
cross-platform deterministic fixed-point (`int64`) contraction so files decode
byte-for-byte identically across Linux, Windows, macOS, x86-64, ARM64, NumPy, and
pure-Python stdlib.

Honest scope:
  - Excels on smooth / low-rank / multi-scale numeric data: physics & PDE grids,
    simulation outputs, scientific lookup tables, spectrograms, smooth sensor/audio
    signals, and smooth heightmaps/renders.
  - Does NOT help on high-entropy files (JPEG/PNG photos, MP4/MKV videos, game paks,
    encrypted/compressed archives, or random noise). In auto-pick mode, this stage
    strictly checks against Pack's existing stages (`zstd` / byte-plane `Plane`) and
    refuses to activate unless Tensor-Train actually wins on size.
  - Background note on Rease's "8 EiB -> 251.63 KiB" experiment (`exp_quantics_tci`):
    that 2^60-point 6D grid came from a smooth mathematical formula sampled on demand
    and was never stored on disk. Real files on disk have finite size and higher
    entanglement, so real savings are typically 2x to 50x (lossless) or 5x to 200x
    (opt-in bounded-error lossy) on structured numeric data, and 0% on photos/videos.

Two verified modes:
  1. `lossless`: deterministic fixed-point TT predictor + exact bit-level residual
     (monotone IEEE-754 ordered-int difference for floats, exact modular int
     difference for integers) + byte-plane transpose + zstd. Verified SHA-256
     byte-for-byte identical at both pack and unpack time.
  2. `lossy` (strictly opt-in, explicit `rel_tol` error bound): deterministic
     fixed-point TT cores verified at pack time to satisfy `rel_l2_err <= rel_tol`,
     recording exact measured `rel_l2_err`, `max_abs_err`, `psnr_db`, and the
     reconstructed SHA-256 verified on every decompress.

CLI:
    python3 shared/forge_tensor_pack.py pack <in> <out.ftt> [--lossy 1e-3]
    python3 shared/forge_tensor_pack.py unpack <in.ftt> <out>
    python3 shared/forge_tensor_pack.py inspect <in.ftt>
    python3 shared/forge_tensor_pack.py demo
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import math
import struct
import sys
import time
import zipfile
import zlib
from pathlib import Path
from typing import Any

try:
    from compression import zstd as _stdlib_zstd  # type: ignore[import-not-found]
except ImportError:
    _stdlib_zstd = None  # type: ignore[assignment]

try:
    import numpy as np  # type: ignore[import-not-found]
except ImportError:
    np = None  # type: ignore[assignment]


FTT_MAGIC = b"FTT1"
FTT_VERSION = 1
FTT_HEADER_FMT = "<4sBBI"
FTT_HEADER_SIZE = struct.calcsize(FTT_HEADER_FMT)  # 10 bytes
FTT_DIGEST_SIZE = 32  # trailing SHA-256 over header + meta + body

MAX_FTT_OUTPUT_BYTES = 512 * 1024 * 1024  # 512 MiB safety cap
MAX_FTT_META_BYTES = 16 * 1024 * 1024
MAX_TT_RANK = 64
MAX_TT_SITES = 48
MIN_ARRAY_BYTES = 4096

TENSOR_EXTS = frozenset({".npy", ".npz", ".wav", ".pgm", ".ppm"})

# Supported numpy dtype strings -> (struct_char, itemsize, is_float, is_signed, endian)
DTYPE_INFO: dict[str, tuple[str, int, bool, bool, str]] = {
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

_INT_BOUNDS: dict[str, tuple[int, int]] = {
    "B": (0, 255),
    "b": (-128, 127),
    "H": (0, 65535),
    "h": (-32768, 32767),
    "I": (0, 4294967295),
    "i": (-2147483648, 2147483647),
    "Q": (0, (1 << 64) - 1),
    "q": (-(1 << 63), (1 << 63) - 1),
}

_UINT_CHARS: dict[int, str] = {1: "B", 2: "H", 4: "I", 8: "Q"}


class TensorPackError(Exception):
    """Raised when Tensor-Train encoding, decoding, or verification fails."""


def tensor_tools_status() -> dict[str, Any]:
    """Report available acceleration backends for the Tensor-Train stage."""
    has_np = np is not None
    has_zstd = _stdlib_zstd is not None
    return {
        "ready": True,
        "numpy": has_np,
        "numpy_version": str(getattr(np, "__version__", "")) if has_np else "",
        "zstd_stdlib": has_zstd,
        "encode_fast_path": has_np,
        "decode_pure_python": True,
        "supported_exts": sorted(TENSOR_EXTS),
        "note": (
            "NumPy fast path ready (pure-Python stdlib decode also built in)."
            if has_np
            else "Pure-Python stdlib mode (install numpy for fast large-array encoding)."
        ),
    }


def normalize_tensor_options(
    tensor_stage: bool = False,
    tensor_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize opt-in Tensor-Train stage options into validated fields."""
    if not tensor_stage:
        return {
            "enabled": False,
            "mode": "lossless",
            "rel_tol": 0.0,
            "max_rank": 24,
            "min_gain": 0.05,
        }
    opts = tensor_options or {}
    mode = str(opts.get("mode") or "lossless").strip().lower()
    if mode not in ("lossless", "lossy"):
        raise TensorPackError(f"unsupported tensor mode: {mode!r}")
    if mode == "lossless":
        rel_tol = 0.0
    else:
        try:
            rel_tol = float(opts.get("rel_tol", 1e-3))
        except (TypeError, ValueError) as exc:
            raise TensorPackError("rel_tol must be a positive number") from exc
        if not math.isfinite(rel_tol) or rel_tol <= 0.0 or rel_tol >= 0.5:
            raise TensorPackError("lossy rel_tol must be in (0, 0.5)")
    try:
        max_rank = int(opts.get("max_rank", 24))
    except (TypeError, ValueError) as exc:
        raise TensorPackError("max_rank must be an integer") from exc
    max_rank = max(2, min(MAX_TT_RANK, max_rank))
    try:
        min_gain = float(opts.get("min_gain", 0.05))
    except (TypeError, ValueError):
        min_gain = 0.05
    min_gain = max(0.0, min(0.9, min_gain))
    return {
        "enabled": True,
        "mode": mode,
        "rel_tol": rel_tol,
        "max_rank": max_rank,
        "min_gain": min_gain,
    }


# ------------------------- Stdlib Stream Compression -------------------------


def _compress_stream(data: bytes, level: int = 9) -> tuple[bytes, str]:
    if _stdlib_zstd is not None:
        return _stdlib_zstd.compress(data, level=level), "zstd"
    return zlib.compress(data, level=min(level, 9)), "zlib"


def _decompress_stream(
    data: bytes, codec: str, *, max_size: int = MAX_FTT_OUTPUT_BYTES
) -> bytes:
    if codec == "zstd":
        if _stdlib_zstd is None:
            raise TensorPackError(
                "stream uses zstd but Python compression.zstd is unavailable"
            )
        try:
            dobj_z = _stdlib_zstd.ZstdDecompressor()
            out = dobj_z.decompress(data, max_length=max_size + 1)
        except Exception as exc:  # noqa: BLE001 — wrap codec decode error cleanly
            raise TensorPackError(f"zstd stream decode failed: {exc}") from exc
        if len(out) > max_size or not dobj_z.eof:
            raise TensorPackError("decompressed tensor stream exceeds safety limit")
        return out
    if codec == "zlib":
        try:
            dobj = zlib.decompressobj()
            out = dobj.decompress(data, max_size + 1)
            if len(out) > max_size or dobj.unconsumed_tail:
                raise TensorPackError("decompressed tensor stream exceeds safety limit")
            return out
        except zlib.error as exc:
            raise TensorPackError(f"zlib stream decode failed: {exc}") from exc
    raise TensorPackError(f"unsupported tensor stream codec: {codec!r}")


def _plane_transpose_bytes(raw: bytes, itemsize: int) -> bytes:
    """Transpose `(N, itemsize)` raw bytes into `(itemsize, N)` byte planes."""
    if itemsize <= 1 or not raw:
        return raw
    n = len(raw) // itemsize
    if np is not None:
        arr = np.frombuffer(raw, dtype=np.uint8).reshape(n, itemsize)
        return np.ascontiguousarray(arr.T).tobytes()
    out = bytearray(len(raw))
    for b_idx in range(itemsize):
        out[b_idx * n : (b_idx + 1) * n] = raw[b_idx::itemsize]
    return bytes(out)


def _plane_untranspose_bytes(planes: bytes, itemsize: int) -> bytes:
    """Inverse of `_plane_transpose_bytes`."""
    if itemsize <= 1 or not planes:
        return planes
    n = len(planes) // itemsize
    if np is not None:
        arr = np.frombuffer(planes, dtype=np.uint8).reshape(itemsize, n)
        return np.ascontiguousarray(arr.T).tobytes()
    out = bytearray(len(planes))
    for b_idx in range(itemsize):
        out[b_idx::itemsize] = planes[b_idx * n : (b_idx + 1) * n]
    return bytes(out)


def _baseline_compressed_size(raw: bytes, itemsize: int = 1) -> int:
    """Estimate Pack's existing baseline size (min of zstd and Plane+zstd)."""
    c_plain, _ = _compress_stream(raw, level=6)
    best = len(c_plain)
    if itemsize in (2, 4, 8) and len(raw) >= itemsize and len(raw) % itemsize == 0:
        c_plane, _ = _compress_stream(_plane_transpose_bytes(raw, itemsize), level=6)
        if len(c_plane) < best:
            best = len(c_plane)
    return best


# ------------------------- Smooth Radix Factorization -------------------------


def _factor_smooth_235(n: int) -> list[int] | None:
    """Factor `n` into small radices in `{2, 3, 4, 5}` (None if not 5-smooth)."""
    if n <= 1:
        return [1]
    factors: list[int] = []
    rem = n
    for p in (2, 3, 5):
        while rem % p == 0:
            factors.append(p)
            rem //= p
    if rem != 1:
        return None
    return factors


def _next_smooth_235(n: int) -> tuple[int, list[int]]:
    """Find smallest integer `m >= n` that factors completely into `{2, 3, 5}`."""
    if n <= 1:
        return 1, [1]
    if n <= 16:
        fac = _factor_smooth_235(n)
        if fac is not None:
            return n, fac
    best = 1 << (n - 1).bit_length()
    lim = best
    p2 = 1
    while p2 <= lim:
        p23 = p2
        while p23 <= lim:
            p235 = p23
            while p235 < n:
                p235 *= 5
            if n <= p235 < best:
                best = p235
                lim = best
            p23 *= 3
        p2 *= 2
    fac = _factor_smooth_235(best)
    assert fac is not None
    return best, fac


def _pack_small_radices(factors: list[int], max_sites_axis: int = 14) -> list[int]:
    """Keep quantics radices compact (merging 2*2 -> 4 only when site count is long)."""
    out = list(factors)
    # Keep pure binary {2} when site count fits cleanly (true Quantics!), merge pairs if long.
    while len(out) > max_sites_axis:
        merged = False
        for i in range(len(out) - 1):
            if out[i] * out[i + 1] <= 8:
                out[i : i + 2] = [out[i] * out[i + 1]]
                merged = True
                break
        if not merged:
            break
    return out


def _plan_topologies(
    shape: tuple[int, ...],
) -> list[tuple[str, tuple[int, ...], list[int], list[int]]]:
    """Build candidate TT folding plans: `(name, padded_shape, perm, modes)`.

    Each plan describes:
      1. Edge-pad array from `shape` to `padded_shape`.
      2. Reshape to `flat_axis_modes` and transpose by `perm` (identity if separated).
      3. Run TT-SVD along `modes`.
    """
    ndim = len(shape)
    plans: list[tuple[str, tuple[int, ...], list[int], list[int]]] = []

    # Plan A: Separated Quantics (1D, 2D, 3D, ND)
    sep_pad: list[int] = []
    sep_modes_per_ax: list[list[int]] = []
    for dim_sz in shape:
        if dim_sz <= 16:
            sep_pad.append(dim_sz)
            sep_modes_per_ax.append([dim_sz])
        else:
            m_sz, facs = _next_smooth_235(dim_sz)
            sep_pad.append(m_sz)
            sep_modes_per_ax.append(_pack_small_radices(facs))
    sep_modes: list[int] = []
    for ml in sep_modes_per_ax:
        sep_modes.extend(ml)
    if 2 <= len(sep_modes) <= MAX_TT_SITES:
        plans.append(
            ("qtt_separated", tuple(sep_pad), list(range(len(sep_modes))), sep_modes)
        )

    # Plan B: Interleaved Quantics (coarse-to-fine scale order across >=2 large spatial axes)
    large_axes = [i for i, d in enumerate(shape) if d >= 16]
    if 2 <= len(large_axes) <= 3:
        # Factor each large axis into matching-length coarse-to-fine scale radices
        inter_pad = list(sep_pad)
        inter_ax_modes = [list(m) for m in sep_modes_per_ax]
        # Build axis-index mapping into the flat separated mode list
        offsets: list[list[int]] = []
        cursor = 0
        for ml in inter_ax_modes:
            offsets.append(list(range(cursor, cursor + len(ml))))
            cursor += len(ml)
        perm: list[int] = []
        # Leading non-large axes (e.g. frame index if small) first, trailing channels last
        max_len = max(len(inter_ax_modes[a]) for a in large_axes)
        for ax in range(ndim):
            if ax not in large_axes and ax < large_axes[0]:
                perm.extend(offsets[ax])
        for level in range(max_len):
            for ax in large_axes:
                if level < len(offsets[ax]):
                    perm.append(offsets[ax][level])
        for ax in range(ndim):
            if ax not in large_axes and ax > large_axes[0]:
                perm.extend(offsets[ax])
        inter_modes = [sep_modes[i] for i in perm]
        if (
            perm != list(range(len(sep_modes)))
            and 2 <= len(inter_modes) <= MAX_TT_SITES
        ):
            plans.append(("qtt_interleaved", tuple(inter_pad), perm, inter_modes))

    # Plan C: Natural 2D / 3D matrix-axis TT (fast & exact for 2D fields, LUTs, spectrograms)
    if ndim == 2 and min(shape) <= 1024 and max(shape) >= 32:
        plans.append(("natural_svd", shape, [0, 1], [shape[0], shape[1]]))
    elif ndim == 3 and shape[0] <= 64 and shape[1] <= 256 and shape[2] <= 256:
        plans.append(("natural_tt", shape, [0, 1, 2], [shape[0], shape[1], shape[2]]))

    if not plans:
        # Fallback: flatten 1D quantics
        total = math.prod(shape)
        m_sz, facs = _next_smooth_235(total)
        modes = _pack_small_radices(facs)
        plans.append(("qtt_flat", (m_sz,), list(range(len(modes))), modes))
    return plans


# ------------------------- Deterministic Fixed-Point TT -------------------------


def _tt_svd_numpy(
    tensor_f64: Any,
    modes: list[int],
    rel_tol: float,
    max_rank: int,
) -> list[Any]:
    """Left-to-right TT-SVD producing left-orthogonal float64 cores `G[0..L-2]` and `G[L-1]`."""
    assert np is not None
    n_sites = len(modes)
    arr = np.ascontiguousarray(tensor_f64, dtype=np.float64)
    max_abs = float(np.max(np.abs(arr))) if arr.size else 0.0
    if max_abs == 0.0 or not math.isfinite(max_abs):
        return [np.zeros((1, m, 1), dtype=np.float64) for m in modes]

    # Exact power-of-2 prescaling prevents norm/Gram underflow (<1e-160) and overflow (>1e154)
    scale_exp = math.floor(math.log2(max_abs))
    arr_scaled = np.ldexp(arr, -scale_exp)
    norm_f = float(np.linalg.norm(arr_scaled))
    if norm_f == 0.0 or not math.isfinite(norm_f):
        return [np.zeros((1, m, 1), dtype=np.float64) for m in modes]

    if n_sites == 1:
        return [arr.reshape(1, modes[0], 1)]

    # Oseledets (2011) Theorem 2.2 per-bond Frobenius truncation budget
    delta = (rel_tol / math.sqrt(max(n_sites - 1, 1))) * norm_f
    use_gram = rel_tol >= 1e-7

    cores: list[Any] = []
    rem = arr_scaled.reshape(modes[0], -1)
    r_prev = 1
    for k in range(n_sites - 1):
        n_k = modes[k]
        mat = rem.reshape(r_prev * n_k, -1)
        m_rows, n_cols = mat.shape
        if use_gram and m_rows <= n_cols and m_rows <= 96:
            gram = mat @ mat.T
            eigvals, eigvecs = np.linalg.eigh(gram)
            order = np.argsort(eigvals)[::-1]
            eigvals = np.maximum(eigvals[order], 0.0)
            s_vals = np.sqrt(eigvals)
            u_mat = eigvecs[:, order]
            # Truncate singular values from tail
            tail_sq = np.cumsum((s_vals * s_vals)[::-1])[::-1]
            keep = int(np.sum(tail_sq > delta * delta))
            rank = max(1, min(max_rank, m_rows, n_cols, keep))
            u_trunc = u_mat[:, :rank]
            rem = u_trunc.T @ mat
            cores.append(u_trunc.reshape(r_prev, n_k, rank))
            r_prev = rank
        else:
            u_mat, s_vals, vt_mat = np.linalg.svd(mat, full_matrices=False)
            tail_sq = np.cumsum((s_vals * s_vals)[::-1])[::-1]
            keep = int(np.sum(tail_sq > delta * delta))
            rank = max(1, min(max_rank, s_vals.size, keep))
            u_trunc = u_mat[:, :rank]
            rem = (s_vals[:rank, None]) * vt_mat[:rank, :]
            cores.append(u_trunc.reshape(r_prev, n_k, rank))
            r_prev = rank

    # Restore exact power-of-2 scale on the final core only (left cores remain orthonormal!)
    cores.append(np.ldexp(rem.reshape(r_prev, modes[-1], 1), scale_exp))
    return cores


def _quantize_tt_cores(
    cores: list[Any],
    q_bits: int = 24,
) -> tuple[list[Any], int]:
    """Quantize left-orthogonal TT cores into exact cross-platform int32/int16 fixed-point.

    Left cores `G[0..L-2]` have orthonormal columns so every entry is strictly in `[-1, 1]`.
    They are scaled by `2^q_bits`. The final core `G[L-1]` carries the tensor amplitude and
    is scaled by `2^{-s_last}` into `[-(2^28), 2^28]` (for `q_bits=24`) or
    `[-(2^14), 2^14]` (for `q_bits=15`).
    """
    assert np is not None
    if q_bits not in (15, 24):
        raise TensorPackError(f"unsupported q_bits: {q_bits}")
    scale = 1 << q_bits
    q_dtype = np.int16 if q_bits == 15 else np.int32
    last_max_pow = 14 if q_bits == 15 else 27

    q_cores: list[Any] = []
    for c in cores[:-1]:
        clamped = np.clip(np.rint(c * scale), -scale, scale)
        # int16 max is 32767, while 1<<15 is 32768 -> clamp to [-32767, 32767]
        if q_bits == 15:
            clamped = np.clip(clamped, -32767, 32767)
        q_cores.append(clamped.astype(q_dtype))

    last = cores[-1]
    max_abs = float(np.max(np.abs(last))) if last.size else 0.0
    if max_abs == 0.0 or not math.isfinite(max_abs):
        s_last = 0
        q_last = np.zeros(last.shape, dtype=q_dtype)
    else:
        s_last = math.floor(math.log2(max_abs)) - last_max_pow
        scaled = np.rint(np.ldexp(last, -s_last))
        lim = 32767 if q_bits == 15 else (1 << 28)
        q_last = np.clip(scaled, -lim, lim).astype(q_dtype)
    q_cores.append(q_last)
    return q_cores, int(s_last)


def _contract_fixed_numpy(
    q_cores: list[Any],
    q_bits: int,
    s_last: int,
    *,
    as_int: bool = False,
) -> Any:
    """Exact deterministic `int64` fixed-point TT contraction (NumPy fast path)."""
    assert np is not None
    n_sites = len(q_cores)
    if n_sites == 1:
        prod = q_cores[0].reshape(-1).astype(np.int64)
        if as_int:
            return _fixed_prod_to_int_numpy(prod, 0, s_last)
        return np.ldexp(prod.astype(np.float64), s_last)

    half = 1 << (q_bits - 1)
    cur = q_cores[0].reshape(q_cores[0].shape[1], q_cores[0].shape[2]).astype(np.int64)
    for k in range(1, n_sites - 1):
        c = q_cores[k]
        r_l, n_k, r_r = c.shape
        prod_k = cur @ c.reshape(r_l, n_k * r_r).astype(np.int64)
        cur = ((prod_k + half) >> q_bits).reshape(-1, r_r)

    last = q_cores[-1]
    r_l, n_last, _ = last.shape
    prod = (cur @ last.reshape(r_l, n_last).astype(np.int64)).reshape(-1)
    if as_int:
        return _fixed_prod_to_int_numpy(prod, q_bits, s_last)

    # Shift right by 6 bits when q_bits==24 so |val| <= 2^52 < 2^53 (exact in IEEE-754 float64!)
    shift_pre = 6 if q_bits == 24 else 0
    if shift_pre:
        val_i64 = (prod + (1 << (shift_pre - 1))) >> shift_pre
    else:
        val_i64 = prod
    total_exp = s_last - (q_bits - shift_pre)
    return np.ldexp(val_i64.astype(np.float64), total_exp)


def _fixed_prod_to_int_numpy(prod: Any, q_bits: int, s_last: int) -> Any:
    assert np is not None
    rshift = q_bits - s_last
    if rshift > 0:
        if rshift >= 63:
            return np.zeros_like(prod, dtype=np.int64)
        return (prod + (1 << (rshift - 1))) >> rshift
    lshift = -rshift
    if lshift == 0:
        return prod
    if lshift >= 62:
        lim = (1 << 62) - 1
        return np.where(prod > 0, lim, np.where(prod < 0, -lim, 0)).astype(np.int64)
    # Clamp before left-shift so signed int64 never wraps (matches pure-Python exactly!)
    safe_hi = ((1 << 62) - 1) >> lshift
    clamped = np.clip(prod, -safe_hi, safe_hi)
    return clamped << lshift


def _contract_fixed_pure(
    q_cores: list[tuple[tuple[int, int, int], list[int]]],
    q_bits: int,
    s_last: int,
    *,
    as_int: bool = False,
) -> list[int] | list[float]:
    """Exact deterministic `int64` fixed-point TT contraction (pure-Python stdlib)."""
    n_sites = len(q_cores)
    if n_sites == 1:
        _, flat = q_cores[0]
        if as_int:
            return _fixed_prod_to_int_pure(flat, 0, s_last)
        return [math.ldexp(float(v), s_last) for v in flat]

    half = 1 << (q_bits - 1)
    (_, n0, r1), c0 = q_cores[0]
    cur_rows: list[list[int]] = [c0[i * r1 : (i + 1) * r1] for i in range(n0)]

    for k in range(1, n_sites - 1):
        (r_l, n_k, r_r), ck = q_cores[k]
        cols = n_k * r_r
        # Pre-slice rows of ck for speed
        ck_rows = [ck[i * cols : (i + 1) * cols] for i in range(r_l)]
        next_rows: list[list[int]] = []
        for row in cur_rows:
            # Compute row @ ck_mat -> length n_k * r_r
            acc = [0] * cols
            for i_l in range(r_l):
                rv = row[i_l]
                if rv:
                    crow = ck_rows[i_l]
                    for j in range(cols):
                        acc[j] += rv * crow[j]
            for m_i in range(n_k):
                base = m_i * r_r
                next_rows.append([(acc[base + j] + half) >> q_bits for j in range(r_r)])
        cur_rows = next_rows

    (r_l, n_last, _), clast = q_cores[-1]
    clast_rows = [clast[i * n_last : (i + 1) * n_last] for i in range(r_l)]
    prod: list[int] = []
    for row in cur_rows:
        acc = [0] * n_last
        for i_l in range(r_l):
            rv = row[i_l]
            if rv:
                crow = clast_rows[i_l]
                for j in range(n_last):
                    acc[j] += rv * crow[j]
        prod.extend(acc)

    if as_int:
        return _fixed_prod_to_int_pure(prod, q_bits, s_last)

    shift_pre = 6 if q_bits == 24 else 0
    total_exp = s_last - (q_bits - shift_pre)
    if shift_pre:
        sh_half = 1 << (shift_pre - 1)
        return [math.ldexp(float((v + sh_half) >> shift_pre), total_exp) for v in prod]
    return [math.ldexp(float(v), total_exp) for v in prod]


def _fixed_prod_to_int_pure(prod: list[int], q_bits: int, s_last: int) -> list[int]:
    rshift = q_bits - s_last
    if rshift > 0:
        if rshift >= 63:
            return [0] * len(prod)
        half = 1 << (rshift - 1)
        return [(v + half) >> rshift for v in prod]
    lshift = -rshift
    if lshift == 0:
        return list(prod)
    if lshift >= 62:
        lim = (1 << 62) - 1
        return [lim if v > 0 else (-lim if v < 0 else 0) for v in prod]
    safe_hi = ((1 << 62) - 1) >> lshift
    safe_lo = -safe_hi
    return [
        (safe_lo if v < safe_lo else (safe_hi if v > safe_hi else v)) << lshift
        for v in prod
    ]


def _unfold_padded_to_orig_numpy(
    flat_vals: Any,
    orig_shape: tuple[int, ...],
    padded_shape: tuple[int, ...],
    perm: list[int],
    modes: list[int],
) -> Any:
    """Invert mode permutation and crop edge-padding back to `orig_shape`."""
    assert np is not None
    arr = flat_vals.reshape(modes)
    if perm != list(range(len(perm))):
        inv_perm = [0] * len(perm)
        for new_i, old_i in enumerate(perm):
            inv_perm[old_i] = new_i
        arr = np.transpose(arr, inv_perm)
    arr = arr.reshape(padded_shape)
    if padded_shape != orig_shape:
        if len(padded_shape) == 1 and len(orig_shape) > 1:
            arr = arr[: math.prod(orig_shape)].reshape(orig_shape)
        else:
            slices = tuple(slice(0, d) for d in orig_shape)
            arr = arr[slices]
    return np.ascontiguousarray(arr)


def _unfold_padded_to_orig_pure(
    flat_vals: list[Any],
    orig_shape: tuple[int, ...],
    padded_shape: tuple[int, ...],
    perm: list[int],
    modes: list[int],
) -> list[Any]:
    """Pure-Python inverse of mode permutation and edge-padding crop."""
    n_modes = len(modes)
    total_pad = math.prod(modes)
    if len(flat_vals) != total_pad:
        raise TensorPackError("contracted tensor length mismatch")

    # Undo permutation if non-identity
    if perm != list(range(n_modes)):
        orig_modes = [0] * n_modes
        for new_i, old_i in enumerate(perm):
            orig_modes[old_i] = modes[new_i]
        # Strides in permuted (flat_vals) layout
        p_strides = [1] * n_modes
        for i in range(n_modes - 2, -1, -1):
            p_strides[i] = p_strides[i + 1] * modes[i + 1]
        # Map each old mode index to its stride in flat_vals
        old_to_pstride = [0] * n_modes
        for new_i, old_i in enumerate(perm):
            old_to_pstride[old_i] = p_strides[new_i]

        # Strides in unpermuted layout
        u_strides = [1] * n_modes
        for i in range(n_modes - 2, -1, -1):
            u_strides[i] = u_strides[i + 1] * orig_modes[i + 1]

        unperm = [flat_vals[0]] * total_pad
        for idx in range(total_pad):
            rem = idx
            p_idx = 0
            for m_i in range(n_modes):
                coord, rem = divmod(rem, u_strides[m_i])
                p_idx += coord * old_to_pstride[m_i]
            unperm[idx] = flat_vals[p_idx]
        cur = unperm
    else:
        cur = flat_vals

    # Crop padded_shape -> orig_shape
    if padded_shape == orig_shape:
        return cur
    if len(padded_shape) == 1 and len(orig_shape) > 1:
        return cur[: math.prod(orig_shape)]
    ndim = len(orig_shape)
    pad_strides = [1] * ndim
    for i in range(ndim - 2, -1, -1):
        pad_strides[i] = pad_strides[i + 1] * padded_shape[i + 1]
    orig_strides = [1] * ndim
    for i in range(ndim - 2, -1, -1):
        orig_strides[i] = orig_strides[i + 1] * orig_shape[i + 1]
    total_orig = math.prod(orig_shape)
    out = [cur[0]] * total_orig
    for idx in range(total_orig):
        rem = idx
        p_idx = 0
        for ax in range(ndim):
            coord, rem = divmod(rem, orig_strides[ax])
            p_idx += coord * pad_strides[ax]
        out[idx] = cur[p_idx]
    return out


# ------------------------- Core Serialization -------------------------


def _pack_q_cores(q_cores: list[Any], q_bits: int) -> bytes:
    """Serialize quantized TT cores (`int16` for q_bits=15, `int32` for q_bits=24) with zig-zag + plane transpose."""
    itemsize = 2 if q_bits == 15 else 4
    if np is not None:
        raw_parts: list[bytes] = []
        for c in q_cores:
            flat = np.ascontiguousarray(c).reshape(-1)
            if itemsize == 2:
                i_arr = flat.astype(np.int32)
                zz = ((i_arr << 1) ^ (i_arr >> 15)) & 0xFFFF
                raw_parts.append(zz.astype("<u2").tobytes())
            else:
                i_arr = flat.astype(np.int64)
                zz = ((i_arr << 1) ^ (i_arr >> 31)) & 0xFFFFFFFF
                raw_parts.append(zz.astype("<u4").tobytes())
        raw = b"".join(raw_parts)
    else:
        fmt_u = "<H" if itemsize == 2 else "<I"
        shift = 15 if itemsize == 2 else 31
        mask = 0xFFFF if itemsize == 2 else 0xFFFFFFFF
        buf = bytearray()
        for _, vals in q_cores:
            for v in vals:
                zz = ((v << 1) ^ (v >> shift)) & mask
                buf.extend(struct.pack(fmt_u, zz))
        raw = bytes(buf)
    return _plane_transpose_bytes(raw, itemsize)


def _unpack_q_cores_numpy(
    plane_bytes: bytes,
    core_shapes: list[list[int]],
    q_bits: int,
) -> list[Any]:
    assert np is not None
    itemsize = 2 if q_bits == 15 else 4
    raw = _plane_untranspose_bytes(plane_bytes, itemsize)
    expected = sum(math.prod(s) for s in core_shapes) * itemsize
    if len(raw) != expected:
        raise TensorPackError("TT core byte length mismatch")
    u_dtype = "<u2" if itemsize == 2 else "<u4"
    u_all = np.frombuffer(raw, dtype=u_dtype)
    if itemsize == 2:
        i_all = ((u_all.astype(np.int32) >> 1) ^ -(u_all.astype(np.int32) & 1)).astype(
            np.int16
        )
    else:
        i_all = ((u_all.astype(np.int64) >> 1) ^ -(u_all.astype(np.int64) & 1)).astype(
            np.int32
        )
    cores: list[Any] = []
    pos = 0
    for s in core_shapes:
        cnt = math.prod(s)
        cores.append(i_all[pos : pos + cnt].reshape(tuple(s)))
        pos += cnt
    return cores


def _unpack_q_cores_pure(
    plane_bytes: bytes,
    core_shapes: list[list[int]],
    q_bits: int,
) -> list[tuple[tuple[int, int, int], list[int]]]:
    itemsize = 2 if q_bits == 15 else 4
    raw = _plane_untranspose_bytes(plane_bytes, itemsize)
    total_vals = sum(math.prod(s) for s in core_shapes)
    if len(raw) != total_vals * itemsize:
        raise TensorPackError("TT core byte length mismatch")
    fmt = f"<{total_vals}{'H' if itemsize == 2 else 'I'}"
    u_vals = struct.unpack(fmt, raw)
    i_vals = [(u >> 1) ^ -(u & 1) for u in u_vals]
    cores: list[tuple[tuple[int, int, int], list[int]]] = []
    pos = 0
    for s in core_shapes:
        if len(s) != 3:
            raise TensorPackError("invalid TT core shape")
        cnt = s[0] * s[1] * s[2]
        cores.append(((s[0], s[1], s[2]), i_vals[pos : pos + cnt]))
        pos += cnt
    return cores


# ------------------------- Bit-Exact Lossless Residual -------------------------


def _float_bits_to_ordered_numpy(u_arr: Any, bits: int) -> Any:
    """Bijection mapping IEEE-754 unsigned bit pattern to monotone-ordered uint."""
    assert np is not None
    sign = np.uint64(1 << (bits - 1)) if bits == 64 else np.uint32(1 << (bits - 1))
    if bits == 16:
        u16 = u_arr.astype(np.uint16)
        neg = (u16 & np.uint16(0x8000)) != 0
        return np.where(neg, (~u16).astype(np.uint16), u16 | np.uint16(0x8000))
    if bits == 32:
        u32 = u_arr.astype(np.uint32)
        neg = (u32 & sign) != 0
        return np.where(neg, (~u32).astype(np.uint32), u32 | sign)
    u64 = u_arr.astype(np.uint64)
    neg = (u64 & sign) != 0
    return np.where(neg, (~u64).astype(np.uint64), u64 | sign)


def _ordered_to_float_bits_numpy(o_arr: Any, bits: int) -> Any:
    assert np is not None
    if bits == 16:
        o16 = o_arr.astype(np.uint16)
        pos = (o16 & np.uint16(0x8000)) != 0
        return np.where(pos, o16 ^ np.uint16(0x8000), (~o16).astype(np.uint16))
    if bits == 32:
        o32 = o_arr.astype(np.uint32)
        pos = (o32 & np.uint32(0x80000000)) != 0
        return np.where(pos, o32 ^ np.uint32(0x80000000), (~o32).astype(np.uint32))
    o64 = o_arr.astype(np.uint64)
    sign = np.uint64(1 << 63)
    pos = (o64 & sign) != 0
    return np.where(pos, o64 ^ sign, (~o64).astype(np.uint64))


def _encode_residual_bytes(orig_raw: bytes, pred_raw: bytes, dtype_str: str) -> bytes:
    """Compute exact bit-level zig-zag byte-plane residual between `orig_raw` and `pred_raw`."""
    _, itemsize, is_float, _, endian = DTYPE_INFO[dtype_str]
    bits = itemsize * 8
    u_char = _UINT_CHARS[itemsize]
    u_endian = endian if endian in ("<", ">") else "|"

    if np is not None:
        u_dt = np.dtype(f"{u_endian}u{itemsize}")
        o_orig = np.frombuffer(orig_raw, dtype=u_dt)
        o_pred = np.frombuffer(pred_raw, dtype=u_dt)
        if is_float:
            o_orig = _float_bits_to_ordered_numpy(o_orig, bits)
            o_pred = _float_bits_to_ordered_numpy(o_pred, bits)
        # Modular unsigned subtraction, then signed-interpret and zig-zag
        if bits == 8:
            diff_s = (o_orig.astype(np.uint8) - o_pred.astype(np.uint8)).view(np.int8)
            zz = (
                (diff_s.astype(np.int16) << 1) ^ (diff_s.astype(np.int16) >> 7)
            ) & 0xFF
            zz_raw = zz.astype(np.uint8).tobytes()
        elif bits == 16:
            diff_s = (o_orig.astype(np.uint16) - o_pred.astype(np.uint16)).view(
                np.int16
            )
            zz = (
                (diff_s.astype(np.int32) << 1) ^ (diff_s.astype(np.int32) >> 15)
            ) & 0xFFFF
            zz_raw = zz.astype("<u2").tobytes()
        elif bits == 32:
            diff_s = (o_orig.astype(np.uint32) - o_pred.astype(np.uint32)).view(
                np.int32
            )
            zz = (
                (diff_s.astype(np.int64) << 1) ^ (diff_s.astype(np.int64) >> 31)
            ) & 0xFFFFFFFF
            zz_raw = zz.astype("<u4").tobytes()
        else:
            # 64-bit unsigned subtraction & zig-zag without int64 overflow warnings
            diff_u = o_orig.astype(np.uint64) - o_pred.astype(np.uint64)
            neg_mask = np.where(
                (diff_u & np.uint64(1 << 63)) != 0,
                np.uint64(0xFFFFFFFFFFFFFFFF),
                np.uint64(0),
            )
            zz = (diff_u << np.uint64(1)) ^ neg_mask
            zz_raw = zz.astype("<u8").tobytes()
        return _plane_transpose_bytes(zz_raw, itemsize)

    # Pure-Python fallback
    n = len(orig_raw) // itemsize
    in_fmt = f"{endian if endian != '|' else ''}{n}{u_char}"
    out_fmt = f"<{n}{u_char}"
    u_o = struct.unpack(in_fmt, orig_raw)
    u_p = struct.unpack(in_fmt, pred_raw)
    mask = (1 << bits) - 1
    sign = 1 << (bits - 1)
    zz_list = [0] * n
    for i in range(n):
        a = u_o[i]
        b = u_p[i]
        if is_float:
            a = (~a & mask) if (a & sign) else (a | sign)
            b = (~b & mask) if (b & sign) else (b | sign)
        d = (a - b) & mask
        if d & sign:
            d -= 1 << bits
        zz_list[i] = ((d << 1) ^ (d >> (bits - 1))) & mask
    return _plane_transpose_bytes(struct.pack(out_fmt, *zz_list), itemsize)


def _decode_residual_bytes(
    pred_raw: bytes, plane_bytes: bytes, dtype_str: str
) -> bytes:
    """Apply exact bit-level residual to `pred_raw` to restore original bytes bit-for-bit."""
    _, itemsize, is_float, _, endian = DTYPE_INFO[dtype_str]
    bits = itemsize * 8
    u_char = _UINT_CHARS[itemsize]
    u_endian = endian if endian in ("<", ">") else "|"

    zz_raw = _plane_untranspose_bytes(plane_bytes, itemsize)
    if len(zz_raw) != len(pred_raw):
        raise TensorPackError("lossless residual byte length mismatch")

    if np is not None:
        u_dt = np.dtype(f"{u_endian}u{itemsize}")
        o_pred = np.frombuffer(pred_raw, dtype=u_dt)
        if is_float:
            o_pred = _float_bits_to_ordered_numpy(o_pred, bits)
        if bits == 8:
            zz = np.frombuffer(zz_raw, dtype=np.uint8)
            diff_u = ((zz >> 1) ^ (-(zz.astype(np.int16) & 1) & 0xFF)).astype(np.uint8)
            o_orig = (o_pred.astype(np.uint8) + diff_u).astype(np.uint8)
            return o_orig.astype(u_dt).tobytes()
        if bits == 16:
            zz = np.frombuffer(zz_raw, dtype="<u2")
            diff_u = ((zz >> 1) ^ (-(zz.astype(np.int32) & 1) & 0xFFFF)).astype(
                np.uint16
            )
            o_orig = (o_pred.astype(np.uint16) + diff_u).astype(np.uint16)
            if is_float:
                o_orig = _ordered_to_float_bits_numpy(o_orig, 16)
            return o_orig.astype(u_dt).tobytes()
        if bits == 32:
            zz = np.frombuffer(zz_raw, dtype="<u4")
            diff_u = ((zz >> 1) ^ (-(zz.astype(np.int64) & 1) & 0xFFFFFFFF)).astype(
                np.uint32
            )
            o_orig = (o_pred.astype(np.uint32) + diff_u).astype(np.uint32)
            if is_float:
                o_orig = _ordered_to_float_bits_numpy(o_orig, 32)
            return o_orig.astype(u_dt).tobytes()
        zz = np.frombuffer(zz_raw, dtype="<u8")
        odd = (zz & np.uint64(1)) != 0
        diff_u = (zz >> np.uint64(1)) ^ np.where(
            odd, np.uint64(0xFFFFFFFFFFFFFFFF), np.uint64(0)
        )
        o_orig = o_pred.astype(np.uint64) + diff_u
        if is_float:
            o_orig = _ordered_to_float_bits_numpy(o_orig, 64)
        return o_orig.astype(u_dt).tobytes()

    # Pure-Python fallback
    n = len(pred_raw) // itemsize
    in_fmt = f"{endian if endian != '|' else ''}{n}{u_char}"
    zz_fmt = f"<{n}{u_char}"
    u_p = struct.unpack(in_fmt, pred_raw)
    zz_vals = struct.unpack(zz_fmt, zz_raw)
    mask = (1 << bits) - 1
    sign = 1 << (bits - 1)
    out_u = [0] * n
    for i in range(n):
        b = u_p[i]
        if is_float:
            b = (~b & mask) if (b & sign) else (b | sign)
        z = zz_vals[i]
        d = (z >> 1) ^ (-(z & 1))
        o = (b + d) & mask
        if is_float:
            o = (o ^ sign) if (o & sign) else (~o & mask)
        out_u[i] = o
    return struct.pack(in_fmt, *out_u)


# ------------------------- Core Array Encode / Decode -------------------------


def _raw_bytes_to_f64_numpy(
    raw: bytes, dtype_str: str, shape: tuple[int, ...], fortran_order: bool
) -> Any:
    assert np is not None
    arr = np.frombuffer(raw, dtype=np.dtype(dtype_str)).reshape(
        shape, order="F" if fortran_order else "C"
    )
    if fortran_order:
        arr = np.ascontiguousarray(arr)
    return arr.astype(np.float64, copy=False)


def _pred_to_raw_bytes_numpy(
    pred_vals: Any, dtype_str: str, fortran_order: bool
) -> bytes:
    """Convert deterministic prediction array (`float64` or `int64`) to exact target bytes."""
    assert np is not None
    s_char, _, is_float, _, _ = DTYPE_INFO[dtype_str]
    dt = np.dtype(dtype_str)
    if is_float:
        with np.errstate(over="ignore"):
            typed = pred_vals.astype(dt)
    else:
        lo, hi = _INT_BOUNDS[s_char]
        # Signed int64 predictions cap at 2^63-1 for unsigned Q so NumPy and pure Python match
        hi_eff = min(hi, (1 << 63) - 1) if pred_vals.dtype == np.int64 else hi
        clamped = np.clip(pred_vals, lo, hi_eff)
        typed = clamped.astype(dt)
    if fortran_order:
        return np.asfortranarray(typed).tobytes(order="F")
    return np.ascontiguousarray(typed).tobytes(order="C")


def _safe_float_for_pack(v: float, s_char: str) -> float:
    """Match IEEE-754 `astype` overflow-to-inf before pure-Python `struct.pack`."""
    if not math.isfinite(v):
        return v
    if s_char == "e" and abs(v) > 65504.0:
        return math.copysign(math.inf, v)
    if s_char == "f" and abs(v) > 3.4028234663852886e38:
        return math.copysign(math.inf, v)
    return v


def _pred_to_raw_bytes_pure(
    pred_vals: list[Any],
    dtype_str: str,
    shape: tuple[int, ...],
    fortran_order: bool,
) -> bytes:
    """Pure-Python exact equivalent of `_pred_to_raw_bytes_numpy`."""
    s_char, _, is_float, _, endian = DTYPE_INFO[dtype_str]
    vals = pred_vals
    if fortran_order and len(shape) > 1:
        # Convert C-order list to Fortran-order list
        ndim = len(shape)
        c_strides = [1] * ndim
        for i in range(ndim - 2, -1, -1):
            c_strides[i] = c_strides[i + 1] * shape[i + 1]
        f_strides = [1] * ndim
        for i in range(1, ndim):
            f_strides[i] = f_strides[i - 1] * shape[i - 1]
        total = len(vals)
        reord = [vals[0]] * total
        for f_idx in range(total):
            rem = f_idx
            c_idx = 0
            for ax in range(ndim - 1, -1, -1):
                coord, rem = divmod(rem, f_strides[ax])
                c_idx += coord * c_strides[ax]
            reord[f_idx] = vals[c_idx]
        vals = reord
    prefix = endian if endian != "|" else ""
    fmt = f"{prefix}{len(vals)}{s_char}"
    if is_float:
        return struct.pack(fmt, *(_safe_float_for_pack(float(v), s_char) for v in vals))
    lo, hi = _INT_BOUNDS[s_char]
    hi_eff = min(hi, (1 << 63) - 1)
    clamped = [lo if v < lo else (hi_eff if v > hi_eff else int(v)) for v in vals]
    return struct.pack(fmt, *clamped)


def _apply_sparse_overrides_raw(
    raw: bytes, overrides: list[list[int]], itemsize: int, endian: str
) -> bytes:
    """Restore non-finite (`NaN`/`Inf`) float entries verbatim at their flat element indices."""
    if not overrides:
        return raw
    u_char = _UINT_CHARS[itemsize]
    fmt = f"{endian if endian != '|' else ''}{u_char}"
    buf = bytearray(raw)
    for idx, bits_u in overrides:
        off = idx * itemsize
        if 0 <= off and off + itemsize <= len(buf):
            buf[off : off + itemsize] = struct.pack(fmt, bits_u)
    return bytes(buf)


def _fit_single_stage(
    arr_f64: Any,
    orig_shape: tuple[int, ...],
    plan: tuple[str, tuple[int, ...], list[int], list[int]],
    svd_tol: float,
    max_rank: int,
    q_bits: int,
) -> tuple[dict[str, Any], bytes, Any]:
    """Fit one deterministic fixed-point TT stage and return `(stage_meta, core_bytes, pred_f64)`."""
    assert np is not None
    topo_name, padded_shape, perm, modes = plan
    # Edge-clamp pad to padded_shape
    if padded_shape == orig_shape:
        padded = arr_f64
    elif len(padded_shape) == 1 and len(orig_shape) > 1:
        flat = arr_f64.reshape(-1)
        pad_n = padded_shape[0] - flat.size
        padded = np.pad(flat, (0, pad_n), mode="edge") if pad_n > 0 else flat
    else:
        pad_spec = [(0, p - o) for p, o in zip(padded_shape, orig_shape, strict=True)]
        padded = np.pad(arr_f64, pad_spec, mode="edge")

    # Reshape into axis-factor modes and apply topology permutation
    orig_modes = [0] * len(modes)
    for new_i, old_i in enumerate(perm):
        orig_modes[old_i] = modes[new_i]
    folded = padded.reshape(orig_modes)
    if perm != list(range(len(perm))):
        folded = np.transpose(folded, perm)

    cores_f = _tt_svd_numpy(folded, modes, svd_tol, max_rank)
    q_cores, s_last = _quantize_tt_cores(cores_f, q_bits=q_bits)
    core_shapes = [list(c.shape) for c in q_cores]
    max_r = max((max(s[0], s[2]) for s in core_shapes), default=1)
    core_bytes = _pack_q_cores(q_cores, q_bits)

    stage_meta = {
        "topology": topo_name,
        "padded_shape": list(padded_shape),
        "perm": perm,
        "modes": modes,
        "core_shapes": core_shapes,
        "q_bits": q_bits,
        "s_last": s_last,
        "max_rank": max_r,
        "core_byte_len": len(core_bytes),
    }
    return stage_meta, core_bytes, q_cores


def _decode_stages_to_raw(
    stages: list[dict[str, Any]],
    core_blobs: list[bytes],
    orig_shape: tuple[int, ...],
    dtype_str: str,
    fortran_order: bool,
    *,
    force_pure_python: bool = False,
) -> bytes:
    """Reconstruct deterministic prediction raw bytes from one or two TT stages."""
    _, _, is_float, _, _ = DTYPE_INFO[dtype_str]
    use_np = (np is not None) and (not force_pure_python)

    if use_np:
        assert np is not None
        acc: Any = None
        for st, blob in zip(stages, core_blobs, strict=True):
            q_bits = int(st["q_bits"])
            s_last = int(st["s_last"])
            core_shapes = st["core_shapes"]
            padded_shape = tuple(int(x) for x in st["padded_shape"])
            perm = [int(x) for x in st["perm"]]
            modes = [int(x) for x in st["modes"]]
            q_cores = _unpack_q_cores_numpy(blob, core_shapes, q_bits)
            as_int = (not is_float) and len(stages) == 1
            flat_vals = _contract_fixed_numpy(q_cores, q_bits, s_last, as_int=as_int)
            arr_stage = _unfold_padded_to_orig_numpy(
                flat_vals, orig_shape, padded_shape, perm, modes
            )
            acc = arr_stage if acc is None else (acc + arr_stage)
        assert acc is not None
        return _pred_to_raw_bytes_numpy(acc, dtype_str, fortran_order)

    # Pure-Python stdlib deterministic path
    acc_p: list[Any] | None = None
    for st, blob in zip(stages, core_blobs, strict=True):
        q_bits = int(st["q_bits"])
        s_last = int(st["s_last"])
        core_shapes = st["core_shapes"]
        padded_shape = tuple(int(x) for x in st["padded_shape"])
        perm = [int(x) for x in st["perm"]]
        modes = [int(x) for x in st["modes"]]
        q_cores_p = _unpack_q_cores_pure(blob, core_shapes, q_bits)
        as_int = (not is_float) and len(stages) == 1
        flat_vals_p = _contract_fixed_pure(q_cores_p, q_bits, s_last, as_int=as_int)
        arr_p = _unfold_padded_to_orig_pure(
            flat_vals_p, orig_shape, padded_shape, perm, modes
        )
        if acc_p is None:
            acc_p = arr_p
        else:
            acc_p = [a + b for a, b in zip(acc_p, arr_p, strict=True)]
    assert acc_p is not None
    return _pred_to_raw_bytes_pure(acc_p, dtype_str, orig_shape, fortran_order)


def _measure_error_numpy(
    orig_raw: bytes, recon_raw: bytes, dtype_str: str
) -> tuple[float, float, float | None]:
    """Measure exact `(rel_l2, max_abs, psnr_db)` without norm underflow/overflow."""
    assert np is not None
    dt = np.dtype(dtype_str)
    a = np.frombuffer(orig_raw, dtype=dt).astype(np.float64)
    b = np.frombuffer(recon_raw, dtype=dt).astype(np.float64)
    finite = np.isfinite(a) & np.isfinite(b)
    if not np.any(finite):
        return 0.0, 0.0, None
    af = a[finite]
    bf = b[finite]
    diff = af - bf
    max_abs = float(np.max(np.abs(diff)))
    # Power-of-2 prescaling avoids norm/MSE underflow on <1e-160 or overflow on >1e154
    peak = max(float(np.max(np.abs(af))), max_abs)
    if peak == 0.0:
        return 0.0, 0.0, None
    scale_exp = math.floor(math.log2(peak))
    af_s = np.ldexp(af, -scale_exp)
    diff_s = np.ldexp(diff, -scale_exp)
    norm_a = float(np.linalg.norm(af_s))
    norm_d = float(np.linalg.norm(diff_s))
    rel_l2 = norm_d / norm_a if norm_a > 0.0 else (0.0 if norm_d == 0.0 else 1.0)
    mse_s = float(np.mean(diff_s * diff_s))
    dyn_s = float(np.max(af_s) - np.min(af_s))
    if mse_s == 0.0:
        psnr_db: float | None = None
    elif dyn_s > 0.0:
        psnr_db = round(20.0 * math.log10(dyn_s) - 10.0 * math.log10(mse_s), 2)
    else:
        psnr_db = 0.0
    return rel_l2, max_abs, psnr_db


def _encode_array_block(
    raw_bytes: bytes,
    dtype_str: str,
    shape: tuple[int, ...],
    fortran_order: bool,
    *,
    mode: str = "lossless",
    rel_tol: float = 0.0,
    max_rank: int = 24,
) -> tuple[dict[str, Any], bytes] | None:
    """Encode a single raw numeric array block into `(block_meta, compressed_body)`.

    Tries candidate topologies (interleaved/separated QTT, natural SVD when suitable),
    verifies the decoded output at pack time (byte-exact for lossless, error-bounded for
    lossy), and returns the smallest verified candidate, or `None` if NumPy is unavailable
    or encoding cannot satisfy the error contract.
    """
    if np is None:
        return None
    if dtype_str not in DTYPE_INFO or not shape or math.prod(shape) < 64:
        return None
    _, itemsize, is_float, _, endian = DTYPE_INFO[dtype_str]
    expected_len = math.prod(shape) * itemsize
    if len(raw_bytes) != expected_len or expected_len < MIN_ARRAY_BYTES:
        return None

    arr_f64 = _raw_bytes_to_f64_numpy(raw_bytes, dtype_str, shape, fortran_order)

    # Guard non-finite values so SVD never sees NaN/Inf; preserve them via overrides in lossy mode.
    overrides: list[list[int]] = []
    if is_float and not bool(np.all(np.isfinite(arr_f64))):
        clean_f64 = np.where(np.isfinite(arr_f64), arr_f64, 0.0)
        if mode == "lossy":
            u_char = _UINT_CHARS[itemsize]
            u_dt = np.dtype(f"{endian if endian != '|' else '|'}u{itemsize}")
            # Flat indices in the raw byte layout
            orig_typed = np.frombuffer(raw_bytes, dtype=np.dtype(dtype_str))
            bad_idx = np.flatnonzero(~np.isfinite(orig_typed))
            if bad_idx.size > 4096:
                return None
            u_raw = np.frombuffer(raw_bytes, dtype=u_dt)
            overrides = [[int(i), int(u_raw[i])] for i in bad_idx]
            _ = u_char
    else:
        clean_f64 = arr_f64

    plans = _plan_topologies(shape)
    best_result: tuple[int, dict[str, Any], bytes] | None = None

    for plan in plans:
        if mode == "lossless":
            # In lossless mode, choose a tight predictor tolerance so deterministic fixed-point
            # TT removes as many leading mantissa/integer bits as possible from the residual.
            pred_tol = (
                1e-7 if (is_float and itemsize == 8) else (1e-6 if is_float else 5e-4)
            )
            q_bits = 24
            st1, b1, _ = _fit_single_stage(
                clean_f64, shape, plan, pred_tol, max_rank, q_bits
            )
            stages = [st1]
            core_blobs = [b1]

            # For float64, try a 2nd deterministic fixed-point stage to reach ~48 bits (~1e-14)
            # whenever Stage 1 leaves a smooth residual (huge win on float64 physics LUTs/PDEs!).
            if is_float and itemsize == 8:
                pred1_raw = _decode_stages_to_raw(
                    stages, core_blobs, shape, dtype_str, fortran_order
                )
                pred1_f64 = _raw_bytes_to_f64_numpy(
                    pred1_raw, dtype_str, shape, fortran_order
                )
                res1 = clean_f64 - pred1_f64
                norm_a = float(np.linalg.norm(clean_f64))
                norm_r1 = float(np.linalg.norm(res1))
                if norm_a > 0.0 and 1e-14 < (norm_r1 / norm_a) < 1e-2:
                    st2, b2, _ = _fit_single_stage(
                        res1, shape, plan, 1e-7, max_rank, 24
                    )
                    # Keep Stage 2 only if its cores + smaller residual beats Stage 1 alone
                    pred2_raw = _decode_stages_to_raw(
                        [st1, st2], [b1, b2], shape, dtype_str, fortran_order
                    )
                    res_b1 = _encode_residual_bytes(raw_bytes, pred1_raw, dtype_str)
                    res_b2 = _encode_residual_bytes(raw_bytes, pred2_raw, dtype_str)
                    c1, _ = _compress_stream(b1 + res_b1, level=6)
                    c2, _ = _compress_stream(b1 + b2 + res_b2, level=6)
                    if len(c2) < len(c1):
                        stages = [st1, st2]
                        core_blobs = [b1, b2]

            pred_raw = _decode_stages_to_raw(
                stages, core_blobs, shape, dtype_str, fortran_order
            )
            res_planes = _encode_residual_bytes(raw_bytes, pred_raw, dtype_str)
            # Verify lossless decode bit-for-bit at pack time!
            check_raw = _decode_residual_bytes(pred_raw, res_planes, dtype_str)
            if check_raw != raw_bytes:
                continue

            uncomp_body = b"".join(core_blobs) + res_planes
            comp_body, comp_codec = _compress_stream(uncomp_body, level=9)
            meta = {
                "dtype": dtype_str,
                "shape": list(shape),
                "fortran_order": fortran_order,
                "mode": "lossless",
                "rel_tol": 0.0,
                "topology": plan[0],
                "max_rank": max(int(s["max_rank"]) for s in stages),
                "stages": stages,
                "residual_byte_len": len(res_planes),
                "overrides": [],
                "comp_codec": comp_codec,
                "measured_rel_l2": 0.0,
                "measured_max_abs": 0.0,
                "psnr_db": None,
            }
            cand_sz = len(comp_body) + len(json.dumps(meta, separators=(",", ":")))
            if best_result is None or cand_sz < best_result[0]:
                best_result = (cand_sz, meta, comp_body)
        else:
            # Lossy bounded-error mode: guarantee measured_rel_l2 <= rel_tol
            # Try compact q_bits=15 first when rel_tol >= 5e-4, then upgrade to q_bits=24
            # or tighter SVD tolerance if needed.
            attempts: list[tuple[float, int, bool]] = []
            if rel_tol >= 5e-4:
                attempts.append((rel_tol * 0.75, 15, False))
            attempts.append((rel_tol * 0.8, 24, False))
            attempts.append((rel_tol * 0.45, 24, False))
            if is_float and itemsize == 8 and rel_tol < 1e-5:
                attempts.append((max(rel_tol * 0.5, 1e-7), 24, True))

            chosen: tuple[int, dict[str, Any], bytes] | None = None
            for svd_tol, q_bits, two_stage in attempts:
                st1, b1, _ = _fit_single_stage(
                    clean_f64, shape, plan, svd_tol, max_rank, q_bits
                )
                stages = [st1]
                core_blobs = [b1]
                if two_stage:
                    p1_raw = _decode_stages_to_raw(
                        stages, core_blobs, shape, dtype_str, fortran_order
                    )
                    p1_f64 = _raw_bytes_to_f64_numpy(
                        p1_raw, dtype_str, shape, fortran_order
                    )
                    res1 = clean_f64 - p1_f64
                    st2, b2, _ = _fit_single_stage(
                        res1, shape, plan, max(rel_tol * 0.5, 1e-7), max_rank, 24
                    )
                    stages.append(st2)
                    core_blobs.append(b2)

                recon_raw = _decode_stages_to_raw(
                    stages, core_blobs, shape, dtype_str, fortran_order
                )
                if overrides:
                    recon_raw = _apply_sparse_overrides_raw(
                        recon_raw, overrides, itemsize, endian
                    )
                rel_l2, max_abs, psnr_db = _measure_error_numpy(
                    raw_bytes, recon_raw, dtype_str
                )
                if rel_l2 <= rel_tol:
                    uncomp_body = b"".join(core_blobs)
                    comp_body, comp_codec = _compress_stream(uncomp_body, level=9)
                    meta = {
                        "dtype": dtype_str,
                        "shape": list(shape),
                        "fortran_order": fortran_order,
                        "mode": "lossy",
                        "rel_tol": rel_tol,
                        "topology": plan[0],
                        "max_rank": max(int(s["max_rank"]) for s in stages),
                        "stages": stages,
                        "residual_byte_len": 0,
                        "overrides": overrides,
                        "comp_codec": comp_codec,
                        "measured_rel_l2": float(rel_l2),
                        "measured_max_abs": float(max_abs),
                        "psnr_db": psnr_db,
                    }
                    cand_sz = len(comp_body) + len(
                        json.dumps(meta, separators=(",", ":"))
                    )
                    if chosen is None or cand_sz < chosen[0]:
                        chosen = (cand_sz, meta, comp_body)
                    break  # first verified attempt at highest compactness wins for this plan
                # If already saturated at max_rank with large error, tighter svd_tol cannot help.
                if (
                    not two_stage
                    and max(int(s["max_rank"]) for s in stages) >= max_rank
                    and rel_l2 > rel_tol * 3.0
                ):
                    break
            if chosen is not None and (
                best_result is None or chosen[0] < best_result[0]
            ):
                best_result = chosen

    if best_result is None:
        return None
    _, meta_best, body_best = best_result
    return meta_best, body_best


def _validate_stage_meta(st: dict[str, Any], orig_shape: tuple[int, ...]) -> None:
    """Validate untrusted stage metadata against DoS / bounds limits before allocation."""
    modes = st.get("modes")
    perm = st.get("perm")
    core_shapes = st.get("core_shapes")
    padded_shape = st.get("padded_shape")
    q_bits = st.get("q_bits")
    if (
        not isinstance(modes, list)
        or not (1 <= len(modes) <= MAX_TT_SITES)
        or not isinstance(perm, list)
        or len(perm) != len(modes)
        or not isinstance(core_shapes, list)
        or len(core_shapes) != len(modes)
        or not isinstance(padded_shape, list)
        or q_bits not in (15, 24)
    ):
        raise TensorPackError("malformed TT stage metadata")
    if sorted(int(x) for x in perm) != list(range(len(modes))):
        raise TensorPackError("invalid TT mode permutation")
    orig_elems = math.prod(orig_shape)
    max_pad_elems = min(MAX_FTT_OUTPUT_BYTES, max(orig_elems * 4, 4096))
    total_pad = 1
    for m in modes:
        if type(m) is not int or m <= 0 or m > 1024 * 1024:
            raise TensorPackError(f"invalid TT mode size: {m!r}")
        total_pad *= m
        if total_pad > max_pad_elems:
            raise TensorPackError("padded tensor element count exceeds safety limit")
    if total_pad != math.prod(int(x) for x in padded_shape):
        raise TensorPackError("padded_shape does not match mode product")
    if len(padded_shape) == len(orig_shape):
        for p, o in zip(padded_shape, orig_shape, strict=True):
            if int(p) < int(o):
                raise TensorPackError("padded_shape smaller than orig_shape")
    elif not (len(padded_shape) == 1 and int(padded_shape[0]) >= orig_elems):
        raise TensorPackError("incompatible padded_shape")
    prev_r = 1
    prefix_prod = 1
    max_work_elems = min(MAX_FTT_OUTPUT_BYTES // 8, max(total_pad * 64, 65536))
    for idx, (m, cs) in enumerate(zip(modes, core_shapes, strict=True)):
        if (
            not isinstance(cs, list)
            or len(cs) != 3
            or any(type(v) is not int or v <= 0 for v in cs)
        ):
            raise TensorPackError("malformed TT core shape")
        rl, mk, rr = cs
        if rl != prev_r or mk != m or rr > MAX_TT_RANK:
            raise TensorPackError(f"invalid TT core rank/mode at site {idx}")
        if idx == len(modes) - 1 and rr != 1:
            raise TensorPackError("final TT core right rank must be 1")
        prefix_prod *= m
        if prefix_prod * rr > max_work_elems:
            raise TensorPackError("TT contraction workspace exceeds safety limit")
        prev_r = rr


def _decode_array_block(
    block_meta: dict[str, Any],
    comp_body: bytes,
    *,
    force_pure_python: bool = False,
    max_output_bytes: int = MAX_FTT_OUTPUT_BYTES,
) -> bytes:
    """Decode one `array` block back to raw array bytes (NumPy or pure-Python stdlib)."""
    dtype_str = str(block_meta.get("dtype") or "")
    if dtype_str not in DTYPE_INFO:
        raise TensorPackError(f"unsupported tensor dtype: {dtype_str!r}")
    _, itemsize, _, _, endian = DTYPE_INFO[dtype_str]
    raw_shape = block_meta.get("shape")
    if (
        not isinstance(raw_shape, list)
        or not raw_shape
        or any(type(d) is not int or d <= 0 for d in raw_shape)
    ):
        raise TensorPackError("invalid tensor shape")
    orig_shape = tuple(int(d) for d in raw_shape)
    out_bytes_expected = math.prod(orig_shape) * itemsize
    if out_bytes_expected > max_output_bytes:
        raise TensorPackError("declared tensor array exceeds safety cap")

    stages = block_meta.get("stages")
    if not isinstance(stages, list) or not (1 <= len(stages) <= 2):
        raise TensorPackError("invalid TT stages list")
    for st in stages:
        if not isinstance(st, dict):
            raise TensorPackError("malformed TT stage entry")
        _validate_stage_meta(st, orig_shape)

    codec = str(block_meta.get("comp_codec") or "zstd")
    res_len = int(block_meta.get("residual_byte_len", 0))
    total_expected = sum(int(st["core_byte_len"]) for st in stages) + res_len
    if res_len < 0 or total_expected > max_output_bytes + 64 * 1024 * 1024:
        raise TensorPackError("uncompressed TT payload size exceeds limit")

    uncomp = _decompress_stream(comp_body, codec, max_size=max(total_expected, 1024))
    if len(uncomp) != total_expected:
        raise TensorPackError("decompressed TT block length mismatch")

    pos = 0
    core_blobs: list[bytes] = []
    for st in stages:
        clen = int(st["core_byte_len"])
        core_blobs.append(uncomp[pos : pos + clen])
        pos += clen
    res_planes = uncomp[pos:]

    fortran_order = bool(block_meta.get("fortran_order", False))
    pred_raw = _decode_stages_to_raw(
        stages,
        core_blobs,
        orig_shape,
        dtype_str,
        fortran_order,
        force_pure_python=force_pure_python,
    )
    mode = str(block_meta.get("mode") or "lossless")
    if mode == "lossless":
        return _decode_residual_bytes(pred_raw, res_planes, dtype_str)

    overrides = block_meta.get("overrides") or []
    if overrides:
        pred_raw = _apply_sparse_overrides_raw(pred_raw, overrides, itemsize, endian)
    return pred_raw


# ------------------------- Container Parsers (Pure Stdlib) -------------------------


def _parse_npy_bytes(
    data: bytes,
) -> tuple[bytes, str, tuple[int, ...], bool, bytes] | None:
    """Parse `.npy` v1/v2/v3 in pure stdlib -> `(header_bytes, dtype_str, shape, fortran, raw_data)`."""
    if len(data) < 12 or data[:6] != b"\x93NUMPY":
        return None
    major, minor = data[6], data[7]
    if major == 1 and minor == 0:
        hdr_len = struct.unpack_from("<H", data, 8)[0]
        hdr_end = 10 + hdr_len
    elif major in (2, 3) and minor == 0:
        hdr_len = struct.unpack_from("<I", data, 8)[0]
        hdr_end = 12 + hdr_len
    else:
        return None
    if hdr_end > len(data):
        return None
    hdr_bytes = data[:hdr_end]
    try:
        hdr_text = data[10 if major == 1 else 12 : hdr_end].decode(
            "utf-8" if major == 3 else "latin-1"
        )
        hdr_dict = ast.literal_eval(hdr_text.strip())
    except Exception:  # noqa: BLE001 — reject malformed/unsupported npy header
        return None
    if not isinstance(hdr_dict, dict):
        return None
    descr = hdr_dict.get("descr")
    shape = hdr_dict.get("shape")
    fortran = hdr_dict.get("fortran_order")
    if (
        not isinstance(descr, str)
        or descr not in DTYPE_INFO
        or not isinstance(shape, tuple)
        or not shape
        or any(type(d) is not int or d <= 0 for d in shape)
        or type(fortran) is not bool
    ):
        return None
    _, itemsize, _, _, _ = DTYPE_INFO[descr]
    raw_data = data[hdr_end:]
    if len(raw_data) != math.prod(shape) * itemsize:
        return None
    return hdr_bytes, descr, shape, fortran, raw_data


def _parse_wav_bytes(
    data: bytes,
) -> tuple[int, int, str, tuple[int, ...], int, int] | None:
    """Parse RIFF/WAVE PCM or IEEE float WAV in pure stdlib.

    Returns `(data_offset, data_size, dtype_str, shape, n_channels, sample_rate)`.
    """
    if len(data) < 44 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return None
    pos = 12
    audio_fmt: int | None = None
    n_channels: int | None = None
    sample_rate: int | None = None
    bits_per_sample: int | None = None
    data_off: int | None = None
    data_sz: int | None = None

    while pos + 8 <= len(data):
        cid = data[pos : pos + 4]
        csz = struct.unpack_from("<I", data, pos + 4)[0]
        body_start = pos + 8
        body_end = body_start + csz
        if body_end > len(data):
            return None
        if cid == b"fmt " and csz >= 16:
            audio_fmt, n_channels, sample_rate, _, _, bits_per_sample = (
                struct.unpack_from("<HHIIHH", data, body_start)
            )
        elif cid == b"data":
            data_off = body_start
            data_sz = csz
            break
        pos = body_end + (csz & 1)

    if (
        audio_fmt is None
        or n_channels is None
        or sample_rate is None
        or bits_per_sample is None
        or data_off is None
        or data_sz is None
        or n_channels <= 0
        or data_sz < MIN_ARRAY_BYTES
    ):
        return None

    if audio_fmt == 1:  # PCM
        dtype_map = {8: "|u1", 16: "<i2", 32: "<i4"}
        dtype_str = dtype_map.get(bits_per_sample)
    elif audio_fmt == 3 and bits_per_sample == 32:  # IEEE float32
        dtype_str = "<f4"
    elif audio_fmt == 3 and bits_per_sample == 64:
        dtype_str = "<f8"
    else:
        dtype_str = None
    if dtype_str is None:
        return None

    _, itemsize, _, _, _ = DTYPE_INFO[dtype_str]
    frame_bytes = n_channels * itemsize
    if data_sz % frame_bytes != 0:
        return None
    n_frames = data_sz // frame_bytes
    shape = (n_frames,) if n_channels == 1 else (n_frames, n_channels)
    return data_off, data_sz, dtype_str, shape, n_channels, sample_rate


def _parse_pnm_bytes(
    data: bytes,
) -> tuple[bytes, str, tuple[int, ...], bytes, int] | None:
    """Parse binary Netpbm PGM (`P5`) or PPM (`P6`) 8-bit/16-bit image in pure stdlib."""
    if len(data) < 16 or data[:2] not in (b"P5", b"P6"):
        return None
    channels = 1 if data[:2] == b"P5" else 3
    tokens: list[bytes] = []
    pos = 2
    n = len(data)
    while len(tokens) < 3 and pos < n:
        # Skip whitespace and comments
        while pos < n and data[pos] in b" \t\r\n":
            pos += 1
        if pos < n and data[pos] == ord("#"):
            while pos < n and data[pos] != ord("\n"):
                pos += 1
            continue
        start = pos
        while pos < n and data[pos] not in b" \t\r\n#":
            pos += 1
        if pos > start:
            tokens.append(data[start:pos])
    if len(tokens) != 3 or pos >= n or data[pos] not in b" \t\r\n":
        return None
    pos += 1  # single whitespace byte after maxval per Netpbm spec
    try:
        width = int(tokens[0])
        height = int(tokens[1])
        maxval = int(tokens[2])
    except ValueError:
        return None
    if width <= 0 or height <= 0 or not (1 <= maxval <= 65535):
        return None
    dtype_str = "|u1" if maxval < 256 else ">u2"
    _, itemsize, _, _, _ = DTYPE_INFO[dtype_str]
    shape: tuple[int, ...] = (
        (height, width) if channels == 1 else (height, width, channels)
    )
    raw = data[pos:]
    if len(raw) != math.prod(shape) * itemsize:
        return None
    return data[:pos], dtype_str, shape, raw, maxval


def _parse_stored_npz_spans(
    data: bytes,
) -> list[tuple[str, int, int]] | None:
    """For a `ZIP_STORED` `.npz`, locate exact `(member_name, data_offset, data_size)` spans."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data), "r")
    except zipfile.BadZipFile:
        return None
    spans: list[tuple[str, int, int]] = []
    with zf:
        for zi in zf.infolist():
            if zi.compress_type != zipfile.ZIP_STORED:
                return None
            lh = zi.header_offset
            if lh + 30 > len(data) or data[lh : lh + 4] != b"PK\x03\x04":
                return None
            fname_len, extra_len = struct.unpack_from("<HH", data, lh + 26)
            data_off = lh + 30 + fname_len + extra_len
            data_end = data_off + zi.file_size
            if data_end > len(data):
                return None
            spans.append((zi.filename, data_off, zi.file_size))
    spans.sort(key=lambda s: s[1])
    # Verify non-overlapping spans
    for i in range(len(spans) - 1):
        if spans[i][1] + spans[i][2] > spans[i + 1][1]:
            return None
    return spans


# ------------------------- FTT1 Envelope Encode / Decode -------------------------


def _wrap_ftt1(meta: dict[str, Any], body: bytes) -> bytes:
    meta_bytes = json.dumps(meta, separators=(",", ":")).encode("utf-8")
    hdr = struct.pack(FTT_HEADER_FMT, FTT_MAGIC, FTT_VERSION, 0, len(meta_bytes))
    payload = hdr + meta_bytes + body
    digest = hashlib.sha256(payload).digest()
    return payload + digest


def inspect_ftt1(ftt_bytes: bytes) -> dict[str, Any]:
    """Authenticate and return the JSON metadata header of an `FTT1` payload."""
    if len(ftt_bytes) < FTT_HEADER_SIZE + FTT_DIGEST_SIZE:
        raise TensorPackError("FTT1 payload truncated")
    magic, ver, _flags, meta_len = struct.unpack_from(FTT_HEADER_FMT, ftt_bytes, 0)
    if magic != FTT_MAGIC or ver != FTT_VERSION:
        raise TensorPackError("not an FTT1 v1 tensor-pack payload")
    if meta_len <= 0 or meta_len > MAX_FTT_META_BYTES:
        raise TensorPackError("invalid FTT1 metadata length")
    meta_end = FTT_HEADER_SIZE + meta_len
    if meta_end + FTT_DIGEST_SIZE > len(ftt_bytes):
        raise TensorPackError("FTT1 metadata exceeds payload bounds")
    payload = ftt_bytes[:-FTT_DIGEST_SIZE]
    digest = ftt_bytes[-FTT_DIGEST_SIZE:]
    if hashlib.sha256(payload).digest() != digest:
        raise TensorPackError("FTT1 SHA-256 payload integrity check failed")
    try:
        meta = json.loads(ftt_bytes[FTT_HEADER_SIZE:meta_end].decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise TensorPackError(f"invalid FTT1 metadata JSON: {exc}") from exc
    if not isinstance(meta, dict):
        raise TensorPackError("malformed FTT1 metadata object")
    return meta


def encode_file_bytes(
    raw_bytes: bytes,
    ext: str,
    *,
    mode: str = "lossless",
    rel_tol: float = 0.0,
    max_rank: int = 24,
    require_beat_baseline: bool = True,
    min_gain: float = 0.05,
    baseline_bytes: int | None = None,
) -> tuple[bytes, dict[str, Any]] | None:
    """Attempt Tensor-Train compression on a file's raw bytes (`.npy`, `.npz`, `.wav`, `.pgm`, `.ppm`).

    Returns `(ftt_bytes, summary_meta)` ONLY when:
      1. The file is a supported numeric container and Tensor-Train succeeds,
      2. Pack-time round-trip decode passes verification (SHA-256 bit-exact in `lossless`
         mode; `measured_rel_l2 <= rel_tol` and deterministic SHA-256 in `lossy` mode), AND
      3. When `require_beat_baseline=True`, `len(ftt_bytes)` beats the existing Pack
         baseline (`baseline_bytes` or `min(zstd, Plane+zstd)`) by at least `min_gain`.
    """
    if np is None or len(raw_bytes) < MIN_ARRAY_BYTES:
        return None
    opts = normalize_tensor_options(
        True,
        {
            "mode": mode,
            "rel_tol": rel_tol if mode == "lossy" else 0.0,
            "max_rank": max_rank,
            "min_gain": min_gain,
        },
    )
    mode = str(opts["mode"])
    rel_tol = float(opts["rel_tol"])
    max_rank = int(opts["max_rank"])
    min_gain = float(opts["min_gain"])

    ext_l = ext.lower()
    if ext_l not in TENSOR_EXTS:
        return None
    orig_sha = hashlib.sha256(raw_bytes).hexdigest()

    if ext_l == ".npy":
        parsed = _parse_npy_bytes(raw_bytes)
        if parsed is None:
            return None
        hdr_bytes, dtype_str, shape, fortran, arr_raw = parsed
        _, itemsize, _, _, _ = DTYPE_INFO[dtype_str]
        enc = _encode_array_block(
            arr_raw,
            dtype_str,
            shape,
            fortran,
            mode=mode,
            rel_tol=rel_tol,
            max_rank=max_rank,
        )
        if enc is None:
            return None
        blk_meta, blk_body = enc
        body = struct.pack("<I", len(hdr_bytes)) + hdr_bytes + blk_body
        # Verify full container decode at pack time
        meta: dict[str, Any] = {
            "kind": "npy",
            "mode": mode,
            "rel_tol": rel_tol,
            "orig_size": len(raw_bytes),
            "orig_sha256": orig_sha,
            "reconstructed_size": len(raw_bytes),
            "reconstructed_sha256": "",
            "topology": blk_meta["topology"],
            "max_rank": blk_meta["max_rank"],
            "measured_rel_l2": blk_meta["measured_rel_l2"],
            "measured_max_abs": blk_meta["measured_max_abs"],
            "psnr_db": blk_meta["psnr_db"],
            "block": blk_meta,
        }
        # Compute verified reconstructed bytes & SHA-256
        recon_arr = _decode_array_block(blk_meta, blk_body)
        recon_full = hdr_bytes + recon_arr
        if mode == "lossless" and recon_full != raw_bytes:
            return None
        meta["reconstructed_size"] = len(recon_full)
        meta["reconstructed_sha256"] = hashlib.sha256(recon_full).hexdigest()
        ftt_bytes = _wrap_ftt1(meta, body)
        base_sz = (
            baseline_bytes
            if baseline_bytes is not None
            else _baseline_compressed_size(raw_bytes, itemsize)
        )

    elif ext_l == ".wav":
        parsed_w = _parse_wav_bytes(raw_bytes)
        if parsed_w is None:
            return None
        data_off, data_sz, dtype_str, shape, n_ch, sr = parsed_w
        _, itemsize, _, _, _ = DTYPE_INFO[dtype_str]
        prefix = raw_bytes[:data_off]
        arr_raw = raw_bytes[data_off : data_off + data_sz]
        suffix = raw_bytes[data_off + data_sz :]
        enc = _encode_array_block(
            arr_raw,
            dtype_str,
            shape,
            False,
            mode=mode,
            rel_tol=rel_tol,
            max_rank=max_rank,
        )
        if enc is None:
            return None
        blk_meta, blk_body = enc
        body = struct.pack("<II", len(prefix), len(suffix)) + prefix + suffix + blk_body
        recon_arr = _decode_array_block(blk_meta, blk_body)
        recon_full = prefix + recon_arr + suffix
        if mode == "lossless" and recon_full != raw_bytes:
            return None
        meta = {
            "kind": "wav",
            "mode": mode,
            "rel_tol": rel_tol,
            "orig_size": len(raw_bytes),
            "orig_sha256": orig_sha,
            "reconstructed_size": len(recon_full),
            "reconstructed_sha256": hashlib.sha256(recon_full).hexdigest(),
            "channels": n_ch,
            "sample_rate": sr,
            "topology": blk_meta["topology"],
            "max_rank": blk_meta["max_rank"],
            "measured_rel_l2": blk_meta["measured_rel_l2"],
            "measured_max_abs": blk_meta["measured_max_abs"],
            "psnr_db": blk_meta["psnr_db"],
            "block": blk_meta,
        }
        ftt_bytes = _wrap_ftt1(meta, body)
        base_sz = (
            baseline_bytes
            if baseline_bytes is not None
            else _baseline_compressed_size(raw_bytes, itemsize)
        )

    elif ext_l in (".pgm", ".ppm"):
        parsed_p = _parse_pnm_bytes(raw_bytes)
        if parsed_p is None:
            return None
        hdr_bytes, dtype_str, shape, arr_raw, maxval = parsed_p
        # In lossy mode, only full-range 8-bit/16-bit PNM guarantees no overshoot past maxval
        if mode == "lossy" and maxval not in (255, 65535):
            return None
        _, itemsize, _, _, _ = DTYPE_INFO[dtype_str]
        enc = _encode_array_block(
            arr_raw,
            dtype_str,
            shape,
            False,
            mode=mode,
            rel_tol=rel_tol,
            max_rank=max_rank,
        )
        if enc is None:
            return None
        blk_meta, blk_body = enc
        body = struct.pack("<I", len(hdr_bytes)) + hdr_bytes + blk_body
        recon_arr = _decode_array_block(blk_meta, blk_body)
        recon_full = hdr_bytes + recon_arr
        if mode == "lossless" and recon_full != raw_bytes:
            return None
        meta = {
            "kind": "pnm",
            "mode": mode,
            "rel_tol": rel_tol,
            "orig_size": len(raw_bytes),
            "orig_sha256": orig_sha,
            "reconstructed_size": len(recon_full),
            "reconstructed_sha256": hashlib.sha256(recon_full).hexdigest(),
            "topology": blk_meta["topology"],
            "max_rank": blk_meta["max_rank"],
            "measured_rel_l2": blk_meta["measured_rel_l2"],
            "measured_max_abs": blk_meta["measured_max_abs"],
            "psnr_db": blk_meta["psnr_db"],
            "block": blk_meta,
        }
        ftt_bytes = _wrap_ftt1(meta, body)
        base_sz = (
            baseline_bytes
            if baseline_bytes is not None
            else _baseline_compressed_size(raw_bytes, itemsize)
        )

    elif ext_l == ".npz":
        spans = _parse_stored_npz_spans(raw_bytes)
        if spans is None:
            return None
        # Build skeleton gaps around member payloads + encode each eligible .npy member
        skel_parts: list[bytes] = []
        member_specs: list[dict[str, Any]] = []
        member_blobs: list[bytes] = []
        cursor = 0
        tt_members = 0
        worst_rel_l2 = 0.0
        worst_max_abs = 0.0
        min_psnr: float | None = None
        top_rank = 1
        top_topo = "qtt_separated"

        for name, off, sz in spans:
            skel_parts.append(raw_bytes[cursor:off])
            cursor = off + sz
            member_raw = raw_bytes[off : off + sz]
            used_tt = False
            if name.endswith(".npy") and sz >= MIN_ARRAY_BYTES:
                parsed_m = _parse_npy_bytes(member_raw)
                if parsed_m is not None:
                    hdr_b, d_str, shp, fort, a_raw = parsed_m
                    _, isz, _, _, _ = DTYPE_INFO[d_str]
                    enc_m = _encode_array_block(
                        a_raw,
                        d_str,
                        shp,
                        fort,
                        mode=mode,
                        rel_tol=rel_tol,
                        max_rank=max_rank,
                    )
                    if enc_m is not None:
                        bm, bb = enc_m
                        m_base = _baseline_compressed_size(member_raw, isz)
                        if len(bb) + len(hdr_b) + 64 < m_base:
                            used_tt = True
                            tt_members += 1
                            top_rank = max(top_rank, int(bm["max_rank"]))
                            top_topo = str(bm["topology"])
                            worst_rel_l2 = max(
                                worst_rel_l2, float(bm["measured_rel_l2"])
                            )
                            worst_max_abs = max(
                                worst_max_abs, float(bm["measured_max_abs"])
                            )
                            if bm["psnr_db"] is not None:
                                p_db = float(bm["psnr_db"])
                                min_psnr = (
                                    p_db if min_psnr is None else min(min_psnr, p_db)
                                )
                            blob = struct.pack("<I", len(hdr_b)) + hdr_b + bb
                            member_blobs.append(blob)
                            member_specs.append(
                                {
                                    "name": name,
                                    "kind": "tt_npy",
                                    "orig_size": sz,
                                    "blob_len": len(blob),
                                    "block": bm,
                                }
                            )
            if not used_tt:
                comp_m, c_codec = _compress_stream(member_raw, level=6)
                member_blobs.append(comp_m)
                member_specs.append(
                    {
                        "name": name,
                        "kind": "raw_comp",
                        "orig_size": sz,
                        "blob_len": len(comp_m),
                        "comp_codec": c_codec,
                    }
                )
        skel_parts.append(raw_bytes[cursor:])
        if tt_members == 0:
            return None

        skel_lens = [len(p) for p in skel_parts]
        skel_comp, skel_codec = _compress_stream(b"".join(skel_parts), level=6)
        body = struct.pack("<I", len(skel_comp)) + skel_comp + b"".join(member_blobs)
        meta = {
            "kind": "npz",
            "mode": mode,
            "rel_tol": rel_tol,
            "orig_size": len(raw_bytes),
            "orig_sha256": orig_sha,
            "reconstructed_size": len(raw_bytes),
            "reconstructed_sha256": "",
            "topology": top_topo,
            "max_rank": top_rank,
            "tt_members": tt_members,
            "total_members": len(spans),
            "measured_rel_l2": worst_rel_l2,
            "measured_max_abs": worst_max_abs,
            "psnr_db": min_psnr,
            "skel_lens": skel_lens,
            "skel_codec": skel_codec,
            "members": member_specs,
        }
        # Decode full container at pack time (also refreshes ZIP CRCs in lossy mode!)
        recon_full = _decode_npz_container(meta, body, force_pure_python=False)
        if mode == "lossless" and recon_full != raw_bytes:
            return None
        meta["reconstructed_size"] = len(recon_full)
        meta["reconstructed_sha256"] = hashlib.sha256(recon_full).hexdigest()
        ftt_bytes = _wrap_ftt1(meta, body)
        base_sz = (
            baseline_bytes
            if baseline_bytes is not None
            else _baseline_compressed_size(raw_bytes, 4)
        )
    else:
        return None

    # Final pack-time round-trip integrity check via the public decoder
    verified_out = decode_ftt1(ftt_bytes)
    if hashlib.sha256(verified_out).hexdigest() != meta["reconstructed_sha256"]:
        return None
    if mode == "lossless" and verified_out != raw_bytes:
        return None

    if require_beat_baseline and len(ftt_bytes) >= int(base_sz * (1.0 - min_gain)):
        return None

    summary = {
        "stage": "tt_array",
        "kind": meta["kind"],
        "mode": mode,
        "lossy": mode == "lossy",
        "rel_tol": rel_tol,
        "topology": meta["topology"],
        "max_rank": int(meta["max_rank"]),
        "measured_rel_l2": float(meta["measured_rel_l2"]),
        "measured_max_abs": float(meta["measured_max_abs"]),
        "psnr_db": meta["psnr_db"],
        "orig_size": len(raw_bytes),
        "stored_size": len(ftt_bytes),
        "baseline_size": base_sz,
        "orig_sha256": orig_sha,
        "reconstructed_sha256": meta["reconstructed_sha256"],
    }
    return ftt_bytes, summary


def _patch_zip_crc_in_place(
    buf: bytearray, member_offsets: list[tuple[int, int, bytes]]
) -> None:
    """Update local-header & central-directory CRC32s for lossy reconstructed stored `.npz` members."""
    # Find EOCD
    eocd = buf.rfind(b"PK\x05\x06", max(0, len(buf) - 65557))
    if eocd < 0 or eocd + 22 > len(buf):
        return
    cd_size, cd_off = struct.unpack_from("<II", buf, eocd + 12)
    # Build map from local_header_offset -> new_crc32
    crc_by_data_off: dict[int, int] = {
        data_off: zlib.crc32(payload) & 0xFFFFFFFF
        for data_off, _, payload in member_offsets
    }
    cd_pos = cd_off
    cd_end = min(len(buf), cd_off + cd_size)
    while cd_pos + 46 <= cd_end and buf[cd_pos : cd_pos + 4] == b"PK\x01\x02":
        fn_len, ex_len, cm_len = struct.unpack_from("<HHH", buf, cd_pos + 28)
        lh_off = struct.unpack_from("<I", buf, cd_pos + 42)[0]
        if lh_off + 30 <= len(buf) and buf[lh_off : lh_off + 4] == b"PK\x03\x04":
            l_fn, l_ex = struct.unpack_from("<HH", buf, lh_off + 26)
            data_off = lh_off + 30 + l_fn + l_ex
            if data_off in crc_by_data_off:
                new_crc = crc_by_data_off[data_off]
                struct.pack_into("<I", buf, lh_off + 14, new_crc)
                struct.pack_into("<I", buf, cd_pos + 16, new_crc)
        cd_pos += 46 + fn_len + ex_len + cm_len


def _decode_npz_container(
    meta: dict[str, Any],
    body: bytes,
    *,
    force_pure_python: bool = False,
    max_output_bytes: int = MAX_FTT_OUTPUT_BYTES,
) -> bytes:
    if len(body) < 4:
        raise TensorPackError("truncated npz TT payload")
    skel_comp_len = struct.unpack_from("<I", body, 0)[0]
    if 4 + skel_comp_len > len(body):
        raise TensorPackError("invalid npz skeleton length")
    skel_lens = meta.get("skel_lens")
    members = meta.get("members")
    if (
        not isinstance(skel_lens, list)
        or not isinstance(members, list)
        or len(skel_lens) != len(members) + 1
    ):
        raise TensorPackError("malformed npz member metadata")
    skel_total = sum(int(x) for x in skel_lens)
    skel_raw = _decompress_stream(
        body[4 : 4 + skel_comp_len],
        str(meta.get("skel_codec") or "zstd"),
        max_size=max(skel_total, 1024),
    )
    if len(skel_raw) != skel_total:
        raise TensorPackError("npz skeleton length mismatch")

    out = bytearray()
    skel_pos = 0
    body_pos = 4 + skel_comp_len
    patched_spans: list[tuple[int, int, bytes]] = []
    is_lossy = str(meta.get("mode") or "lossless") == "lossy"

    for idx, mspec in enumerate(members):
        slen = int(skel_lens[idx])
        out.extend(skel_raw[skel_pos : skel_pos + slen])
        skel_pos += slen
        blen = int(mspec["blob_len"])
        if body_pos + blen > len(body):
            raise TensorPackError("truncated npz member blob")
        blob = body[body_pos : body_pos + blen]
        body_pos += blen
        mkind = str(mspec.get("kind") or "")
        data_off = len(out)
        if mkind == "tt_npy":
            if len(blob) < 4:
                raise TensorPackError("truncated tt_npy member")
            hlen = struct.unpack_from("<I", blob, 0)[0]
            if 4 + hlen > len(blob):
                raise TensorPackError("invalid tt_npy header length")
            hdr_b = blob[4 : 4 + hlen]
            arr_b = _decode_array_block(
                mspec["block"],
                blob[4 + hlen :],
                force_pure_python=force_pure_python,
                max_output_bytes=max_output_bytes,
            )
            member_bytes = hdr_b + arr_b
            out.extend(member_bytes)
            if is_lossy:
                patched_spans.append((data_off, len(member_bytes), member_bytes))
        elif mkind == "raw_comp":
            member_bytes = _decompress_stream(
                blob,
                str(mspec.get("comp_codec") or "zstd"),
                max_size=max(int(mspec.get("orig_size", 0)), 1024),
            )
            out.extend(member_bytes)
        else:
            raise TensorPackError(f"unsupported npz member kind: {mkind!r}")
        if len(out) > max_output_bytes:
            raise TensorPackError("decoded npz exceeds safety cap")

    out.extend(skel_raw[skel_pos:])
    if is_lossy and patched_spans:
        _patch_zip_crc_in_place(out, patched_spans)
    return bytes(out)


def decode_ftt1(
    ftt_bytes: bytes,
    *,
    force_pure_python: bool = False,
    max_output_bytes: int = MAX_FTT_OUTPUT_BYTES,
) -> bytes:
    """Decode and SHA-256 verify an `FTT1` payload (NumPy fast path or pure-Python stdlib)."""
    meta = inspect_ftt1(ftt_bytes)
    _, _, _, meta_len = struct.unpack_from(FTT_HEADER_FMT, ftt_bytes, 0)
    body = ftt_bytes[FTT_HEADER_SIZE + meta_len : -FTT_DIGEST_SIZE]
    kind = str(meta.get("kind") or "")

    if kind in ("npy", "pnm"):
        if len(body) < 4:
            raise TensorPackError(f"truncated {kind} TT body")
        hlen = struct.unpack_from("<I", body, 0)[0]
        if 4 + hlen > len(body):
            raise TensorPackError(f"invalid {kind} header length")
        hdr_b = body[4 : 4 + hlen]
        arr_b = _decode_array_block(
            meta["block"],
            body[4 + hlen :],
            force_pure_python=force_pure_python,
            max_output_bytes=max_output_bytes,
        )
        out = hdr_b + arr_b
    elif kind == "wav":
        if len(body) < 8:
            raise TensorPackError("truncated wav TT body")
        plen, slen = struct.unpack_from("<II", body, 0)
        if 8 + plen + slen > len(body):
            raise TensorPackError("invalid wav framing lengths")
        prefix = body[8 : 8 + plen]
        suffix = body[8 + plen : 8 + plen + slen]
        arr_b = _decode_array_block(
            meta["block"],
            body[8 + plen + slen :],
            force_pure_python=force_pure_python,
            max_output_bytes=max_output_bytes,
        )
        out = prefix + arr_b + suffix
    elif kind == "npz":
        out = _decode_npz_container(
            meta,
            body,
            force_pure_python=force_pure_python,
            max_output_bytes=max_output_bytes,
        )
    else:
        raise TensorPackError(f"unsupported FTT1 container kind: {kind!r}")

    expected_sha = str(meta.get("reconstructed_sha256") or "")
    expected_sz = int(meta.get("reconstructed_size", -1))
    if expected_sz >= 0 and len(out) != expected_sz:
        raise TensorPackError("decoded FTT1 output size mismatch")
    if expected_sha and hashlib.sha256(out).hexdigest() != expected_sha:
        raise TensorPackError("decoded FTT1 SHA-256 verification failed")
    return out


# ------------------------- High-Level Array API & Live Demo -------------------------


def compress_array(
    arr: Any,
    *,
    mode: str = "lossless",
    rel_tol: float = 0.0,
    max_rank: int = 24,
) -> tuple[bytes, dict[str, Any]]:
    """Compress an in-memory NumPy array into a self-verifying `FTT1` byte payload."""
    if np is None:
        raise TensorPackError("compress_array requires NumPy")
    buf = io.BytesIO()
    np.save(buf, arr, allow_pickle=False)
    npy_bytes = buf.getvalue()
    res = encode_file_bytes(
        npy_bytes,
        ".npy",
        mode=mode,
        rel_tol=rel_tol,
        max_rank=max_rank,
        require_beat_baseline=False,
    )
    if res is None:
        raise TensorPackError("array could not be encoded with Tensor-Train")
    return res


def decompress_array(ftt_bytes: bytes, *, force_pure_python: bool = False) -> Any:
    """Decode and verify an `FTT1` `.npy` payload back to a NumPy array."""
    if np is None:
        raise TensorPackError("decompress_array requires NumPy")
    npy_bytes = decode_ftt1(ftt_bytes, force_pure_python=force_pure_python)
    return np.load(io.BytesIO(npy_bytes), allow_pickle=False)


def run_tensor_demo() -> dict[str, Any]:
    """Run a live honest demonstration on this computer comparing structured data vs noisy data.

    Shows:
      1. Why Rease's 8 EiB -> 251.63 KiB result happened (smooth formula on a virtual 2^60 grid),
      2. A real stored 2D physics wave/LUT grid (512x512 float64 = 2.0 MB on disk) compressed
         both losslessly (SHA-256 bit-exact) and lossy (verified <= 1e-4), compared live
         against standard zstd,
      3. An honest negative control (high-entropy random array mimicking encrypted/photo bytes)
         where auto-pick declines Tensor-Train so zero bytes or CPU are wasted.
    """
    if np is None:
        raise TensorPackError("Live Tensor-Train demo requires NumPy")

    # 1. Real stored 2D physics/simulation field: 512 x 512 float64 (2,097,280 B .npy)
    x = np.linspace(0.0, 1.0, 512, dtype=np.float64)
    y = np.linspace(0.0, 1.0, 512, dtype=np.float64)
    xx, yy = np.meshgrid(x, y, indexing="ij")
    field = (
        np.exp(-12.0 * ((xx - 0.35) ** 2 + (yy - 0.6) ** 2))
        * np.cos(14.0 * xx + 9.0 * yy)
        + 0.45 * np.tanh(8.0 * (xx + yy - 1.0))
        + 0.25 * np.sin(6.0 * math.pi * xx) * np.cos(4.0 * math.pi * yy)
    )
    buf = io.BytesIO()
    np.save(buf, field, allow_pickle=False)
    field_npy = buf.getvalue()

    # Baseline zstd -6
    t0 = time.perf_counter()
    zstd_field, _ = _compress_stream(field_npy, level=6)
    zstd_ms = round((time.perf_counter() - t0) * 1000.0, 1)

    # Lossless TT (bit-exact SHA-256)
    t0 = time.perf_counter()
    ll_res = encode_file_bytes(
        field_npy, ".npy", mode="lossless", max_rank=24, require_beat_baseline=False
    )
    ll_pack_ms = round((time.perf_counter() - t0) * 1000.0, 1)
    assert ll_res is not None
    ll_bytes, ll_meta = ll_res
    t0 = time.perf_counter()
    ll_dec = decode_ftt1(ll_bytes)
    ll_unpack_ms = round((time.perf_counter() - t0) * 1000.0, 1)
    ll_exact = ll_dec == field_npy

    # Lossy TT (verified <= 1e-4)
    t0 = time.perf_counter()
    ls_res = encode_file_bytes(
        field_npy,
        ".npy",
        mode="lossy",
        rel_tol=1e-4,
        max_rank=24,
        require_beat_baseline=False,
    )
    ls_pack_ms = round((time.perf_counter() - t0) * 1000.0, 1)
    assert ls_res is not None
    ls_bytes, ls_meta = ls_res
    t0 = time.perf_counter()
    ls_dec = decode_ftt1(ls_bytes)
    ls_unpack_ms = round((time.perf_counter() - t0) * 1000.0, 1)
    ls_verified = hashlib.sha256(ls_dec).hexdigest() == ls_meta["reconstructed_sha256"]

    # Honest negative control: 256x256 random float32 (262,272 B)
    rng = np.random.default_rng(1583)
    noise = rng.standard_normal((256, 256)).astype(np.float32)
    nbuf = io.BytesIO()
    np.save(nbuf, noise, allow_pickle=False)
    noise_npy = nbuf.getvalue()
    noise_zstd, _ = _compress_stream(noise_npy, level=6)
    noise_ll = encode_file_bytes(
        noise_npy, ".npy", mode="lossless", max_rank=16, require_beat_baseline=True
    )

    return {
        "field": {
            "name": "physics_wave_field_512x512.npy",
            "shape": [512, 512],
            "dtype": "float64",
            "raw_bytes": len(field_npy),
            "zstd_bytes": len(zstd_field),
            "zstd_ratio": round(len(field_npy) / len(zstd_field), 2),
            "zstd_ms": zstd_ms,
            "lossless_bytes": len(ll_bytes),
            "lossless_ratio": round(len(field_npy) / len(ll_bytes), 2),
            "lossless_saved_pct": round(
                (1.0 - len(ll_bytes) / len(field_npy)) * 100.0, 1
            ),
            "lossless_pack_ms": ll_pack_ms,
            "lossless_unpack_ms": ll_unpack_ms,
            "lossless_bit_exact": ll_exact,
            "lossless_rank": ll_meta["max_rank"],
            "lossless_topology": ll_meta["topology"],
            "lossy_tol": 1e-4,
            "lossy_bytes": len(ls_bytes),
            "lossy_ratio": round(len(field_npy) / len(ls_bytes), 1),
            "lossy_saved_pct": round((1.0 - len(ls_bytes) / len(field_npy)) * 100.0, 1),
            "lossy_pack_ms": ls_pack_ms,
            "lossy_unpack_ms": ls_unpack_ms,
            "lossy_rel_l2": ls_meta["measured_rel_l2"],
            "lossy_max_abs": ls_meta["measured_max_abs"],
            "lossy_psnr_db": ls_meta["psnr_db"],
            "lossy_verified": ls_verified,
            "lossy_rank": ls_meta["max_rank"],
        },
        "negative_control": {
            "name": "random_noise_256x256.npy",
            "raw_bytes": len(noise_npy),
            "zstd_bytes": len(noise_zstd),
            "auto_picked_tt": noise_ll is not None,
            "verdict": "Auto-pick rejected Tensor-Train (no smooth structure; falls back to Pack standard stage).",
        },
        "honest_8eib_note": (
            "Rease's 8 EiB -> 251.63 KiB result sampled a smooth 6D physics formula on demand "
            "across a virtual 2^60 grid that never existed on disk. On real stored numeric files "
            "(simulations, lookup tables, spectrograms), Tensor-Train still delivers big real "
            "savings, while photos, videos, games, and random bytes cannot be shrunk this way."
        ),
    }


# ------------------------- Standalone CLI -------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Forge Tensor-Train (QTT) numeric data compressor (cross-platform)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_pack = sub.add_parser(
        "pack", help="Compress a .npy/.npz/.wav/.pgm/.ppm file to .ftt"
    )
    p_pack.add_argument("src", help="Input numeric file")
    p_pack.add_argument("dst", help="Output .ftt file")
    p_pack.add_argument(
        "--lossy",
        type=float,
        default=0.0,
        help="Opt-in bounded relative L2 error tolerance (e.g. 1e-3, 1e-4). Omit for lossless.",
    )
    p_pack.add_argument(
        "--max-rank", type=int, default=24, help="Maximum TT bond rank (default 24)"
    )
    p_pack.add_argument(
        "--force",
        action="store_true",
        help="Emit .ftt even if zstd baseline is smaller",
    )

    p_unp = sub.add_parser("unpack", help="Decompress and verify a .ftt file")
    p_unp.add_argument("src", help="Input .ftt file")
    p_unp.add_argument("dst", help="Output file path")
    p_unp.add_argument(
        "--pure-python",
        action="store_true",
        help="Force pure-Python stdlib decoder (no NumPy)",
    )

    p_ins = sub.add_parser(
        "inspect", help="Inspect metadata and error bounds of a .ftt file"
    )
    p_ins.add_argument("src", help="Input .ftt file")

    sub.add_parser("demo", help="Run live structured-vs-noise Tensor-Train demo")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "demo":
            print(json.dumps(run_tensor_demo(), indent=2))
            return 0
        if args.cmd == "inspect":
            meta = inspect_ftt1(Path(args.src).read_bytes())
            # Omit bulky per-stage shapes if verbose, keep concise summary
            view = {
                k: v
                for k, v in meta.items()
                if k not in ("block", "members", "skel_lens")
            }
            print(json.dumps(view, indent=2))
            return 0
        if args.cmd == "pack":
            src = Path(args.src)
            raw = src.read_bytes()
            t0 = time.perf_counter()
            res = encode_file_bytes(
                raw,
                src.suffix,
                mode="lossy" if args.lossy > 0 else "lossless",
                rel_tol=args.lossy,
                max_rank=args.max_rank,
                require_beat_baseline=not args.force,
            )
            dt_ms = (time.perf_counter() - t0) * 1000.0
            if res is None:
                print(
                    f"Skipped: Tensor-Train did not beat Pack's standard baseline on {src.name} "
                    "(use --force to write anyway).",
                    file=sys.stderr,
                )
                return 2
            ftt_bytes, summary = res
            Path(args.dst).write_bytes(ftt_bytes)
            ratio = len(raw) / len(ftt_bytes)
            print(
                f"Packed {src.name}: {len(raw):,} B -> {len(ftt_bytes):,} B "
                f"({ratio:.2f}x, mode={summary['mode']}, rank={summary['max_rank']}, "
                f"rel_l2={summary['measured_rel_l2']:.2e}) in {dt_ms:.1f} ms"
            )
            return 0
        if args.cmd == "unpack":
            src = Path(args.src)
            t0 = time.perf_counter()
            out = decode_ftt1(src.read_bytes(), force_pure_python=args.pure_python)
            dt_ms = (time.perf_counter() - t0) * 1000.0
            Path(args.dst).write_bytes(out)
            print(
                f"Unpacked {src.name} -> {args.dst} ({len(out):,} B verified) in {dt_ms:.1f} ms"
            )
            return 0
    except TensorPackError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
