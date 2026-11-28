#!/usr/bin/env python3
"""Forge Vault — Super-fast-decode compressed & authenticated-encrypted storage.

Combines:
  - Proven cryptography ONLY: Argon2id KDF -> BLAKE3 domain-separated subkeys ->
    AES-256-GCM (hardware VAES/VPCLMULQDQ via OpenSSL, deterministic 96-bit
    counter nonce per vault key) or XChaCha20-Poly1305 (via libsodium, 192-bit
    CSPRNG nonce). Compress first, encrypt second; every header, manifest, and
    chunk is AEAD-authenticated with strict AAD binding.
  - Cross-file FastCDC (Gear-hash content-defined chunking) with keyed-BLAKE3
    deduplication (never leaks plaintext hashes) and streaming O(1)-RAM packing.
  - Per-file-type smart codec routing (`shared/vault/profiles.json`) using our
    custom C super-fast-decode codecs (Selkie-SIMD, Phrase-Selkie, Kraken-Huff4,
    Kraken-tANS4, Plane-AVX2) plus optional trained domain dictionary and
    entropy-probe bypass for already-compressed media.

CLI:
    forge-vault pack <src> <out.fvlt> [--profile fast] [--cipher aes256gcm]
    forge-vault unpack <in.fvlt> <dest_dir>
    forge-vault verify <in.fvlt>
    forge-vault info <in.fvlt>
"""

from __future__ import annotations

import argparse
import bisect
import ctypes
import getpass
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import forge_media  # noqa: E402
import forge_tensor_pack  # noqa: E402
import forge_vault_portable as fvp  # noqa: E402

VAULT_DIR = HERE / "vault"
PROFILES_PATH = VAULT_DIR / "profiles.json"
LIB_PATH = VAULT_DIR / ("forge_vault.dll" if os.name == "nt" else "libforge_vault.so")

MAGIC = b"FVLT0001"
FOOTER_MAGIC = b"FVTE"
HEADER_FMT = "<8sBBBBIII16sQ"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 48 bytes
CHUNK_HDR_FMT = "<32sBBIBI"
CHUNK_HDR_SIZE = struct.calcsize(CHUNK_HDR_FMT)  # 43 bytes
MANIFEST_PREFIX_FMT = "<BI"
MANIFEST_PREFIX_SIZE = struct.calcsize(MANIFEST_PREFIX_FMT)  # 5 bytes
FOOTER_FMT = "<Q4s"
FOOTER_SIZE = struct.calcsize(FOOTER_FMT)  # 12 bytes

HEADER_FLAG_HAS_DICT = 0x01
HEADER_FLAG_MANIFEST_KRAKEN = 0x02
HEADER_FLAG_HAS_MEDIA = 0x04
HEADER_FLAG_HAS_TENSOR = 0x08
CHUNK_FLAG_USED_DICT = 0x01
MAX_CHUNK_RAW_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_PLAIN_BYTES = 128 * 1024 * 1024
MAX_DECODE_CACHE_BYTES = 64 * 1024 * 1024
MIN_KDF_MEM_KIB = 8192
MAX_KDF_MEM_KIB = 1024 * 1024
MIN_KDF_ITERS = 1
MAX_KDF_ITERS = 64

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
CIPHER_NAMES = {
    CIPHER_NONE: "none",
    CIPHER_AES256GCM: "aes256gcm",
    CIPHER_XCHACHA20: "xchacha20",
}

PROFILE_IDS = {"ultra_fast": 0, "fast": 1, "balanced": 2, "max": 3}
PROFILE_NAMES = {v: k for k, v in PROFILE_IDS.items()}

_LIB: ctypes.CDLL | None = None
_LIB_FAILED: str | None = None


class VaultError(Exception):
    """Raised when vault packing, unpacking, authentication, or verification fails."""


class VaultAuthError(VaultError):
    """Raised on wrong passphrase or AEAD authentication / tamper failure."""


def load_profiles() -> dict[str, Any]:
    """Load declarative vault profiles and file-type routing registry."""
    return json.loads(PROFILES_PATH.read_text(encoding="utf-8"))


def _build_native_lib() -> Path:
    """Locate or atomically compile the native Forge Vault shared library."""
    env_lib = os.environ.get("FORGE_VAULT_LIB")
    if env_lib:
        p = Path(env_lib)
        if not p.is_file():
            raise VaultError(f"FORGE_VAULT_LIB does not exist: {p}")
        return p
    if os.name == "nt":
        for candidate in (
            VAULT_DIR / "forge_vault.dll",
            VAULT_DIR / "libforge_vault.dll",
        ):
            if candidate.is_file():
                return candidate
        raise VaultError(
            "Native Windows library shared/vault/forge_vault.dll is not built yet. "
            "Build it on Windows (MSVC/MinGW) and place forge_vault.dll in shared/vault/."
        )
    c_files = [VAULT_DIR / "fast_codecs.c", VAULT_DIR / "vault_crypto.c"]
    h_files = [VAULT_DIR / "fast_codecs.h", VAULT_DIR / "vault_crypto.h"]
    target_lib = LIB_PATH
    if not os.access(VAULT_DIR, os.W_OK):
        cache_dir = (
            Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
            / "forge"
            / "vault"
        )
        cache_dir.mkdir(parents=True, exist_ok=True)
        target_lib = cache_dir / LIB_PATH.name
    if not target_lib.exists() or (
        all(p.exists() for p in c_files + h_files)
        and target_lib.stat().st_mtime
        < max(p.stat().st_mtime for p in c_files + h_files)
    ):
        tmp_so = target_lib.with_name(f".libforge_vault.{os.getpid()}.tmp.so")
        cmd = [
            "gcc",
            "-O3",
            "-march=native",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-shared",
            "-fPIC",
            *(str(p) for p in c_files),
            "-o",
            str(tmp_so),
            "-lsodium",
            "-lcrypto",
            "-lblake3",
            "-lzstd",
            "-lm",
        ]
        try:
            subprocess.run(cmd, check=True)
            os.replace(tmp_so, target_lib)
        finally:
            tmp_so.unlink(missing_ok=True)
    return target_lib


def _portable_forced() -> bool:
    val = os.environ.get("FORGE_VAULT_FORCE_PORTABLE", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def native_lib_status() -> dict[str, Any]:
    """Check whether the native C codec/crypto engine or portable engine is active."""
    if _portable_forced():
        return {
            "ready": True,
            "mode": "portable",
            "engine": "portable",
            "forced": True,
            "platform": sys.platform,
        }
    try:
        lib_path = _build_native_lib()
        get_lib()
        return {
            "ready": True,
            "mode": "native",
            "engine": "native",
            "path": str(lib_path),
            "platform": sys.platform,
        }
    except (VaultError, OSError, subprocess.CalledProcessError) as exc:
        return {
            "ready": True,
            "mode": "portable",
            "engine": "portable",
            "native_error": str(exc),
            "platform": sys.platform,
        }


def try_get_lib() -> ctypes.CDLL | None:
    """Return the native C Forge Vault engine when available, else None."""
    if _portable_forced():
        return None
    try:
        return get_lib()
    except (VaultError, OSError, subprocess.CalledProcessError):
        return None


def get_lib() -> ctypes.CDLL:
    """Load and bind the native C Forge Vault engine."""
    global _LIB
    if _LIB is not None:
        return _LIB
    so = _build_native_lib()
    lib = ctypes.CDLL(str(so))

    lib.fv_crypto_init.argtypes = []
    lib.fv_crypto_init.restype = ctypes.c_int

    lib.fv_random_bytes.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.fv_random_bytes.restype = ctypes.c_int

    lib.fv_kdf_argon2id.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_char_p,
    ]
    lib.fv_kdf_argon2id.restype = ctypes.c_int

    lib.fv_derive_subkey.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.fv_derive_subkey.restype = None

    lib.fv_keyed_blake3.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
    ]
    lib.fv_keyed_blake3.restype = None

    lib.fv_blake3.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
    ]
    lib.fv_blake3.restype = None

    lib.fv_aead_encrypt.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    lib.fv_aead_encrypt.restype = ctypes.c_int64

    lib.fv_aead_decrypt.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    lib.fv_aead_decrypt.restype = ctypes.c_int64

    lib.fv_fastcdc_cut.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_size_t,
        ctypes.c_size_t,
        ctypes.c_size_t,
    ]
    lib.fv_fastcdc_cut.restype = ctypes.c_size_t

    lib.fv_compress_bound.argtypes = [ctypes.c_size_t]
    lib.fv_compress_bound.restype = ctypes.c_size_t

    lib.fv_decompressed_size.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.fv_decompressed_size.restype = ctypes.c_int64

    lib.fv_entropy_probe.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.fv_entropy_probe.restype = ctypes.c_double

    lib.fv_train_dict.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    lib.fv_train_dict.restype = ctypes.c_size_t

    lib.fv_compress.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    lib.fv_compress.restype = ctypes.c_size_t

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

    if hasattr(lib, "fv_png_unfilter"):
        lib.fv_png_unfilter.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        lib.fv_png_unfilter.restype = ctypes.c_int

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

    if lib.fv_crypto_init() != 0:
        raise VaultError("failed to initialize native crypto engine")
    _LIB = lib
    return lib


# ------------------------------ Low-Level Wrappers ------------------------------


def compress_bytes(
    data: bytes,
    codec_id: int = CODEC_KRAKEN_HUFF8,
    level: int = 2,
    dictionary: bytes = b"",
) -> bytes:
    """Compress raw bytes using a Forge Vault native or portable codec."""
    lib = try_get_lib()
    if lib is None:
        try:
            return fvp.compress_portable(data, codec_id, level, dictionary)
        except fvp.PortableVaultError as exc:
            raise VaultError(str(exc)) from exc
    cap = int(lib.fv_compress_bound(len(data))) + 4096
    out = ctypes.create_string_buffer(cap)
    dict_ptr = dictionary if dictionary else None
    n = int(
        lib.fv_compress(
            codec_id,
            level,
            data,
            len(data),
            dict_ptr,
            len(dictionary),
            out,
            cap,
        )
    )
    if n == 0:
        raise VaultError(f"compression failed (codec={codec_id}, len={len(data)})")
    return out.raw[:n]


def decompress_bytes(
    data: bytes,
    raw_len: int,
    codec_id: int = CODEC_KRAKEN_HUFF8,
    dictionary: bytes = b"",
) -> bytes:
    """Decompress bytes produced by `compress_bytes` and verify exact output size."""
    if raw_len < 0 or raw_len > MAX_CHUNK_RAW_BYTES:
        raise VaultError(f"chunk raw_len out of safe bounds: {raw_len}")
    lib = try_get_lib()
    if lib is None:
        try:
            return fvp.decompress_portable(codec_id, data, raw_len, dictionary)
        except fvp.PortableVaultError as exc:
            raise VaultError(str(exc)) from exc
    out = ctypes.create_string_buffer(max(raw_len, 1))
    dict_ptr = dictionary if dictionary else None
    got = int(
        lib.fv_decompress(
            codec_id,
            data,
            len(data),
            dict_ptr,
            len(dictionary),
            out,
            raw_len,
        )
    )
    if got != raw_len:
        raise VaultError(
            f"decompression failed (codec={codec_id}, got={got}, expected={raw_len})"
        )
    return out.raw[:raw_len]


def entropy_probe(data: bytes) -> float:
    """Fast 16 KB sample Shannon entropy estimate (0.0 .. 8.0 bits/byte)."""
    lib = try_get_lib()
    if lib is None:
        return fvp.entropy_probe_pure(data)
    return float(lib.fv_entropy_probe(data, len(data)))


def train_dict(samples: bytes, max_dict_bytes: int = 65536) -> bytes:
    """Train a compact shared dictionary from concatenated domain samples."""
    if len(samples) < 512 or max_dict_bytes < 1024:
        return b""
    lib = try_get_lib()
    if lib is None:
        return b""
    out = ctypes.create_string_buffer(max_dict_bytes)
    n = int(lib.fv_train_dict(samples, len(samples), out, max_dict_bytes))
    return out.raw[:n]


def fastcdc_split(
    data: bytes,
    min_size: int = 32768,
    avg_size: int = 131072,
    max_size: int = 524288,
) -> list[bytes]:
    """Split `data` into content-defined chunks using FastCDC Gear hashing."""
    if not data:
        return []
    lib = try_get_lib()
    mv = memoryview(data)
    out: list[bytes] = []
    pos = 0
    total = len(data)
    while pos < total:
        rem = total - pos
        if rem <= min_size:
            out.append(bytes(mv[pos:]))
            break
        window = bytes(mv[pos : pos + min(rem, max_size)])
        cut = (
            int(lib.fv_fastcdc_cut(window, len(window), min_size, avg_size, max_size))
            if lib is not None
            else fvp.fastcdc_cut_pure(window, min_size, avg_size, max_size)
        )
        if cut <= 0:
            cut = len(window)
        out.append(window[:cut])
        pos += cut
    return out


def _iter_file_chunks(
    fpath: Path, min_size: int, avg_size: int, max_size: int
) -> tuple[list[bytes], str, int]:
    """Stream a file in bounded RAM, returning FastCDC chunks, SHA-256 hex, and size."""
    lib = try_get_lib()
    hasher = hashlib.sha256()
    chunks: list[bytes] = []
    total = 0
    buf = bytearray()
    read_unit = max(max_size * 2, 1024 * 1024)
    with fpath.open("rb") as fh:
        while True:
            piece = fh.read(read_unit)
            if piece:
                hasher.update(piece)
                total += len(piece)
                buf.extend(piece)
            while len(buf) >= max_size:
                window = bytes(buf[:max_size])
                cut = (
                    int(
                        lib.fv_fastcdc_cut(
                            window, max_size, min_size, avg_size, max_size
                        )
                    )
                    if lib is not None
                    else fvp.fastcdc_cut_pure(window, min_size, avg_size, max_size)
                )
                if cut <= 0:
                    cut = max_size
                chunks.append(window[:cut])
                del buf[:cut]
            if not piece:
                break
    while buf:
        if len(buf) <= min_size:
            chunks.append(bytes(buf))
            buf.clear()
        else:
            window = bytes(buf)
            cut = (
                int(
                    lib.fv_fastcdc_cut(
                        window, len(window), min_size, avg_size, max_size
                    )
                )
                if lib is not None
                else fvp.fastcdc_cut_pure(window, min_size, avg_size, max_size)
            )
            if cut <= 0:
                cut = len(window)
            chunks.append(window[:cut])
            del buf[:cut]
    return chunks, hasher.hexdigest(), total


def _derive_keys(
    passphrase: str | bytes,
    salt: bytes,
    mem_kib: int,
    iterations: int,
    lanes: int = 1,
) -> tuple[bytes, bytes, bytes]:
    """Derive (manifest_key, chunk_key, dedup_key) via Argon2id + BLAKE3 KDF."""
    if not (MIN_KDF_MEM_KIB <= mem_kib <= MAX_KDF_MEM_KIB):
        raise VaultAuthError(f"KDF memory parameter out of bounds: {mem_kib} KiB")
    if not (MIN_KDF_ITERS <= iterations <= MAX_KDF_ITERS):
        raise VaultAuthError(f"KDF iterations out of bounds: {iterations}")
    if lanes != 1:
        raise VaultAuthError(f"unsupported KDF parallelism: {lanes}")

    lib = try_get_lib()
    if lib is None:
        try:
            return fvp.derive_keys_pure(passphrase, salt, mem_kib, iterations, lanes)
        except fvp.PortableVaultError as exc:
            raise VaultError(str(exc)) from exc
    pw = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
    if len(salt) != 16:
        raise VaultError("salt must be 16 bytes")
    master = ctypes.create_string_buffer(32)
    try:
        rc = int(
            lib.fv_kdf_argon2id(
                pw, len(pw), salt, len(salt), mem_kib, iterations, lanes, master
            )
        )
        if rc != 0:
            raise VaultError(f"Argon2id KDF failed (rc={rc})")

        m_key = ctypes.create_string_buffer(32)
        c_key = ctypes.create_string_buffer(32)
        d_key = ctypes.create_string_buffer(32)
        lib.fv_derive_subkey(master, b"forge-vault-v1:manifest", m_key)
        lib.fv_derive_subkey(master, b"forge-vault-v1:chunk", c_key)
        lib.fv_derive_subkey(master, b"forge-vault-v1:dedup", d_key)
        return m_key.raw, c_key.raw, d_key.raw
    finally:
        ctypes.memset(master, 0, 32)


def _aead_encrypt(
    cipher_id: int, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes
) -> bytes:
    lib = try_get_lib()
    if lib is None:
        try:
            return fvp.aead_encrypt_pure(cipher_id, key, nonce, aad, plaintext)
        except fvp.PortableVaultError as exc:
            raise VaultError(str(exc)) from exc
    cap = len(plaintext) + 16
    out = ctypes.create_string_buffer(cap)
    n = int(
        lib.fv_aead_encrypt(
            cipher_id,
            key,
            nonce,
            len(nonce),
            aad,
            len(aad),
            plaintext,
            len(plaintext),
            out,
            cap,
        )
    )
    if n < 0:
        raise VaultError("AEAD encryption failed")
    return out.raw[:n]


def _aead_decrypt(
    cipher_id: int, key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes
) -> bytes:
    if len(ciphertext) < 16:
        raise VaultAuthError("ciphertext too short for AEAD tag")
    lib = try_get_lib()
    if lib is None:
        try:
            return fvp.aead_decrypt_pure(cipher_id, key, nonce, aad, ciphertext)
        except fvp.PortableAuthError as exc:
            raise VaultAuthError(str(exc)) from exc
        except fvp.PortableVaultError as exc:
            raise VaultError(str(exc)) from exc
    plain_len = len(ciphertext) - 16
    out = ctypes.create_string_buffer(max(plain_len, 1))
    n = int(
        lib.fv_aead_decrypt(
            cipher_id,
            key,
            nonce,
            len(nonce),
            aad,
            len(aad),
            ciphertext,
            len(ciphertext),
            out,
            plain_len,
        )
    )
    if n < 0:
        raise VaultAuthError(
            "authentication failed (wrong passphrase or corrupted data)"
        )
    return out.raw[:n]


def _keyed_chunk_id(dedup_key: bytes, raw_chunk: bytes) -> bytes:
    lib = try_get_lib()
    if lib is None:
        return fvp.blake3_pure(raw_chunk, key=dedup_key)
    out = ctypes.create_string_buffer(32)
    lib.fv_keyed_blake3(dedup_key, raw_chunk, len(raw_chunk), out)
    return out.raw


def blake3_hash(data: bytes) -> bytes:
    """Compute an unkeyed 32-byte BLAKE3 digest."""
    lib = try_get_lib()
    if lib is None:
        return fvp.blake3_pure(data)
    out = ctypes.create_string_buffer(32)
    lib.fv_blake3(data, len(data), out)
    return out.raw


def _plain_dedup_key(salt: bytes) -> bytes:
    """Derive a per-pack 32-byte FastCDC dedup key from the pack header salt."""
    return blake3_hash(b"forge-vault-v1:plain-dedup:" + salt)


def _random_bytes(n: int) -> bytes:
    lib = try_get_lib()
    if lib is None:
        return os.urandom(n)
    buf = ctypes.create_string_buffer(n)
    if int(lib.fv_random_bytes(buf, n)) != 0:
        raise VaultError("CSPRNG failed")
    return buf.raw


def _classify_path(path: Path, cfg: dict[str, Any]) -> str:
    ext = path.suffix.lower()
    for kind, exts in cfg["file_types"].items():
        if ext in exts:
            return kind
    return "default"


def _safe_rel_path(rel: str) -> Path:
    """Validate an archive relative path against traversal, drive prefixes, or backslash escapes."""
    if (
        not rel
        or rel.startswith("/")
        or rel.startswith("\\")
        or "\\" in rel
        or "\x00" in rel
    ):
        raise VaultError(f"unsafe archive path: {rel!r}")
    segs = rel.split("/")
    if any(seg in ("", ".", "..") or ":" in seg for seg in segs):
        raise VaultError(f"path traversal rejected: {rel!r}")
    p = Path(*segs)
    if p.is_absolute() or p.drive or p.root:
        raise VaultError(f"path traversal rejected: {rel!r}")
    return p


def _ensure_safe_target(out_root: Path, rel: Path) -> Path:
    """Verify no symlink or drive escape exists along `out_root / rel` before mkdir."""
    cur = out_root
    for part in rel.parts[:-1]:
        nxt = cur / part
        if nxt.is_symlink():
            raise VaultError(f"refusing to traverse symlink directory: {nxt}")
        if not nxt.resolve().is_relative_to(out_root):
            raise VaultError(f"resolved path escapes destination root: {nxt}")
        if nxt.exists() and not nxt.is_dir():
            raise VaultError(f"path exists and is not a directory: {nxt}")
        nxt.mkdir(exist_ok=True)
        cur = nxt
    target = cur / rel.parts[-1]
    if target.is_symlink():
        raise VaultError(f"refusing to overwrite symlink: {target}")
    if not cur.resolve().is_relative_to(
        out_root
    ) or not target.resolve().is_relative_to(out_root):
        raise VaultError(f"resolved path escapes destination root: {target}")
    return target


@dataclass
class VaultStats:
    """Measured statistics for a pack or unpack operation."""

    files: int
    raw_bytes: int
    vault_bytes: int
    unique_chunks: int
    total_chunk_refs: int
    dedup_saved_bytes: int
    dict_bytes: int
    elapsed_sec: float
    codec_counts: dict[str, int]
    cipher: str
    profile: str
    encrypted: bool = True
    bypassed_files: int = 0
    bypassed_bytes: int = 0
    skipped_files: int = 0
    skipped_bytes: int = 0
    media_stage: bool = False
    media_files: int = 0
    media_saved_bytes: int = 0
    media_stage_counts: dict[str, int] = field(default_factory=dict)
    tensor_stage: bool = False
    tensor_files: int = 0
    tensor_lossy_files: int = 0
    tensor_saved_bytes: int = 0
    tensor_stage_counts: dict[str, int] = field(default_factory=dict)

    @property
    def ratio(self) -> float:
        return self.raw_bytes / self.vault_bytes if self.vault_bytes else 0.0

    @property
    def saved_pct(self) -> float:
        return (
            (1.0 - (self.vault_bytes / self.raw_bytes)) * 100.0
            if self.raw_bytes > 0
            else 0.0
        )

    @property
    def throughput_mbs(self) -> float:
        return (
            (self.raw_bytes / (1024 * 1024)) / self.elapsed_sec
            if self.elapsed_sec > 0
            else 0.0
        )


def _collect_sources(
    sources: Sequence[Path | str],
) -> tuple[list[tuple[str, Path]], list[str]]:
    """Collect regular files and empty dirs deterministically (read-only, no symlinks)."""
    if not sources:
        raise VaultError("no source files or folders provided")
    src_paths = [Path(s) for s in sources]
    for sp in src_paths:
        if not sp.exists():
            raise VaultError(f"source path does not exist: {sp}")
        if not (sp.is_file() or sp.is_dir()):
            raise VaultError(f"source must be a regular file or directory: {sp}")

    multi = len(src_paths) > 1
    allocated_roots: set[str] = set()
    files: list[tuple[str, Path]] = []
    empty_dirs: list[str] = []

    for sp in src_paths:
        root_name = sp.name or "root"
        if multi:
            candidate = root_name
            suffix_num = 1
            while candidate in allocated_roots:
                candidate = f"{root_name}_{suffix_num}"
                suffix_num += 1
            allocated_roots.add(candidate)
            prefix = candidate
        else:
            prefix = ""

        if sp.is_file():
            rel = prefix if multi else sp.name
            files.append((rel, sp))
        else:
            has_any = False
            for p in sorted(sp.rglob("*")):
                if p.is_symlink():
                    continue
                sub = p.relative_to(sp).as_posix()
                rel = f"{prefix}/{sub}" if prefix else sub
                if p.is_file():
                    has_any = True
                    files.append((rel, p))
                elif p.is_dir():
                    try:
                        if not any(p.iterdir()):
                            has_any = True
                            empty_dirs.append(rel)
                    except OSError:
                        continue
            if not has_any and prefix:
                empty_dirs.append(prefix)

    return files, empty_dirs


def scan_sources(
    sources: Sequence[Path | str],
    *,
    profile: str = "fast",
    skip_incompressible: bool = False,
    media_stage: bool = False,
    media_options: dict[str, Any] | None = None,
    tensor_stage: bool = False,
    tensor_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Read-only pre-pack scan showing auto-pick codec routing, media stage, and tensor stage counts."""
    cfg = load_profiles()
    if profile not in cfg["profiles"]:
        raise VaultError(f"unknown profile: {profile!r}")
    prof_cfg = cfg["profiles"][profile]
    mopts = forge_media.normalize_media_options(media_stage, media_options)
    try:
        topts = forge_tensor_pack.normalize_tensor_options(tensor_stage, tensor_options)
    except forge_tensor_pack.TensorPackError as exc:
        raise VaultError(str(exc)) from exc
    files, empty_dirs = _collect_sources(sources)

    by_kind: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    compressible_files = 0
    compressible_bytes = 0
    incompressible_files = 0
    incompressible_bytes = 0
    media_eligible_files = 0
    media_eligible_bytes = 0
    tensor_eligible_files = 0
    tensor_eligible_bytes = 0
    media_candidates: dict[str, int] = {
        "jpeg": 0,
        "png": 0,
        "mp4": 0,
        "mkv": 0,
    }
    sample_items: list[dict[str, Any]] = []

    mp4_count = sum(
        1 for _, fp in files if fp.suffix.lower() in forge_media.MP4_DEDUP_EXTS
    )
    mkv_count = sum(
        1 for _, fp in files if fp.suffix.lower() in forge_media.MKV_FONT_EXTS
    )

    for rel, fpath in files:
        try:
            size = int(fpath.stat().st_size)
        except OSError:
            continue
        kind = _classify_path(fpath, cfg)
        ext = fpath.suffix.lower()
        route = prof_cfg["routing"].get(kind, prof_cfg["routing"]["default"])
        codec_key = str(route["codec"])
        codec_label = str(cfg["codecs"][codec_key]["label"])
        is_media = kind == "incompressible"

        media_eligible = False
        if mopts["enabled"] and not skip_incompressible:
            if mopts["jpeg"] and ext in forge_media.JPEG_EXTS:
                media_eligible = True
                media_candidates["jpeg"] += 1
            elif mopts["png"] and ext in forge_media.PNG_EXTS:
                media_eligible = True
                media_candidates["png"] += 1
            elif (
                mopts["video_dedup"]
                and mp4_count >= 2
                and ext in forge_media.MP4_DEDUP_EXTS
            ):
                media_eligible = True
                media_candidates["mp4"] += 1
            elif (
                mopts["mkv_fonts"]
                and mkv_count >= 2
                and ext in forge_media.MKV_FONT_EXTS
            ):
                media_eligible = True
                media_candidates["mkv"] += 1

        tensor_eligible = bool(
            topts["enabled"]
            and ext in forge_tensor_pack.TENSOR_EXTS
            and forge_tensor_pack.MIN_ARRAY_BYTES <= size <= 256 * 1024 * 1024
        )
        if tensor_eligible:
            tensor_eligible_files += 1
            tensor_eligible_bytes += size

        total_bytes += size
        if is_media:
            incompressible_files += 1
            incompressible_bytes += size
        else:
            compressible_files += 1
            compressible_bytes += size
        if media_eligible:
            media_eligible_files += 1
            media_eligible_bytes += size

        if is_media and skip_incompressible:
            action = "skip"
        elif is_media and mopts["enabled"]:
            action = "media_stage"
        elif is_media:
            action = "raw_bypass"
        else:
            action = "compress"

        bucket = by_kind.setdefault(
            kind,
            {
                "kind": kind,
                "files": 0,
                "bytes": 0,
                "codec": codec_key,
                "codec_label": codec_label,
                "action": action,
            },
        )
        bucket["files"] += 1
        bucket["bytes"] += size

        if len(sample_items) < 200:
            sample_items.append(
                {
                    "path": rel,
                    "size": size,
                    "kind": kind,
                    "codec": codec_key,
                    "skipped": bool(is_media and skip_incompressible),
                    "bypassed": bool(
                        is_media and not skip_incompressible and not media_eligible
                    ),
                    "media_eligible": media_eligible,
                    "tensor_eligible": tensor_eligible,
                }
            )

    return {
        "profile": profile,
        "skip_incompressible": skip_incompressible,
        "media_stage": mopts["enabled"],
        "media_options": mopts,
        "media_eligible_files": media_eligible_files,
        "media_eligible_bytes": media_eligible_bytes,
        "media_candidates": media_candidates,
        "media_tools": forge_media.media_tools_status(),
        "tensor_stage": topts["enabled"],
        "tensor_options": topts,
        "tensor_eligible_files": tensor_eligible_files,
        "tensor_eligible_bytes": tensor_eligible_bytes,
        "tensor_tools": forge_tensor_pack.tensor_tools_status(),
        "total_files": len(files),
        "empty_dirs": len(empty_dirs),
        "total_bytes": total_bytes,
        "compressible_files": compressible_files,
        "compressible_bytes": compressible_bytes,
        "incompressible_files": incompressible_files,
        "incompressible_bytes": incompressible_bytes,
        "categories": sorted(by_kind.values(), key=lambda r: -int(r["bytes"])),
        "items": sample_items,
        "items_truncated": len(files) > len(sample_items),
    }


def peek_vault(vault_path: Path | str) -> dict[str, Any]:
    """Read only the authenticated header & footer metadata without needing a passphrase."""
    vpath = Path(vault_path)
    if not vpath.is_file():
        raise VaultError(f"pack file does not exist: {vpath}")
    file_size = vpath.stat().st_size
    if file_size < HEADER_SIZE + FOOTER_SIZE + MANIFEST_PREFIX_SIZE + 16:
        raise VaultError("pack file truncated or invalid")

    with vpath.open("rb") as f:
        header = f.read(HEADER_SIZE)
        (
            magic,
            ver,
            cipher_id,
            prof_id,
            flags,
            mem_kib,
            iters,
            lanes,
            _salt,
            chunk_cnt,
        ) = struct.unpack(HEADER_FMT, header)
        if magic != MAGIC or ver != 1:
            raise VaultError("not a Forge Pack / Vault v1 file")
        if cipher_id not in CIPHER_NAMES:
            raise VaultError(f"unsupported cipher id: {cipher_id}")

        f.seek(file_size - FOOTER_SIZE)
        manifest_offset, fmagic = struct.unpack(FOOTER_FMT, f.read(FOOTER_SIZE))
        if (
            fmagic != FOOTER_MAGIC
            or manifest_offset < HEADER_SIZE
            or manifest_offset >= file_size - FOOTER_SIZE
        ):
            raise VaultAuthError("invalid pack footer")

    return {
        "path": str(vpath),
        "name": vpath.name,
        "version": ver,
        "encrypted": cipher_id != CIPHER_NONE,
        "cipher_id": cipher_id,
        "cipher": CIPHER_NAMES[cipher_id],
        "profile": PROFILE_NAMES.get(prof_id, "fast"),
        "has_dict": bool(flags & HEADER_FLAG_HAS_DICT),
        "has_media": bool(flags & HEADER_FLAG_HAS_MEDIA),
        "has_tensor": bool(flags & HEADER_FLAG_HAS_TENSOR),
        "unique_chunks": int(chunk_cnt),
        "vault_bytes": file_size,
        "kdf_mem_kib": int(mem_kib),
        "kdf_iters": int(iters),
        "kdf_lanes": int(lanes),
    }


def _stream_file_sha_and_size(fpath: Path) -> tuple[str, int]:
    """Compute `(sha256_hex, byte_size)` streaming in 1 MiB blocks."""
    hasher = hashlib.sha256()
    total = 0
    with fpath.open("rb") as fh:
        while True:
            piece = fh.read(1024 * 1024)
            if not piece:
                break
            hasher.update(piece)
            total += len(piece)
    return hasher.hexdigest(), total


def pack_sources(
    sources: Sequence[Path | str],
    out_vault: Path | str,
    passphrase: str | bytes | None = None,
    *,
    profile: str = "fast",
    cipher: str = "aes256gcm",
    kdf_mem_kib: int | None = None,
    kdf_iters: int | None = None,
    skip_incompressible: bool = False,
    media_stage: bool = False,
    media_options: dict[str, Any] | None = None,
    tensor_stage: bool = False,
    tensor_options: dict[str, Any] | None = None,
    progress_cb: Callable[[int, int, str], None] | None = None,
) -> VaultStats:
    """Compress, deduplicate, and optionally AEAD-encrypt files or folders into `.fpack`/`.fvlt`."""
    t0 = time.perf_counter()
    cfg = load_profiles()
    if profile not in cfg["profiles"]:
        raise VaultError(f"unknown profile: {profile!r}")
    mopts = forge_media.normalize_media_options(media_stage, media_options)
    try:
        topts = forge_tensor_pack.normalize_tensor_options(tensor_stage, tensor_options)
    except forge_tensor_pack.TensorPackError as exc:
        raise VaultError(str(exc)) from exc

    if passphrase is None:
        cipher = "none"
        encrypted = False
    elif len(passphrase) == 0:
        if cipher != "none":
            raise VaultError(
                "passphrase cannot be empty for an encrypted vault; "
                "pass cipher='none' (or passphrase=None) for an unencrypted pack"
            )
        encrypted = False
    else:
        if cipher == "none":
            raise VaultError("cannot supply a passphrase when cipher='none'")
        encrypted = True

    if cipher not in cfg["ciphers"]:
        raise VaultError(f"unknown cipher: {cipher!r}")

    prof_cfg = cfg["profiles"][profile]
    cipher_cfg = cfg["ciphers"][cipher]
    cipher_id = int(cipher_cfg["id"])
    nonce_len = int(cipher_cfg["nonce_bytes"])
    codec_map = {name: int(info["id"]) for name, info in cfg["codecs"].items()}
    codec_names = {int(info["id"]): name for name, info in cfg["codecs"].items()}

    all_files, empty_dirs = _collect_sources(sources)

    files: list[tuple[str, Path]] = []
    skipped_files = 0
    skipped_bytes = 0
    for rel, fpath in all_files:
        kind = _classify_path(fpath, cfg)
        if skip_incompressible and kind == "incompressible":
            skipped_files += 1
            try:
                skipped_bytes += int(fpath.stat().st_size)
            except OSError:
                pass
            continue
        files.append((rel, fpath))

    # Optional cross-file media pre-passes (MP4 render-version packet dedup & MKV fonts).
    mp4_plans: dict[str, tuple[bytes, dict[str, Any]]] = {}
    mkv_assets: dict[str, bytes] = {}
    mkv_spans: dict[str, list[tuple[int, int, str]]] = {}
    if mopts["enabled"] and not skip_incompressible:
        if mopts["video_dedup"]:
            mp4_candidates = [
                (rel, fp)
                for rel, fp in files
                if fp.suffix.lower() in forge_media.MP4_DEDUP_EXTS
            ]
            if len(mp4_candidates) >= 2:
                mp4_plans = forge_media.plan_mp4_packet_dedup(mp4_candidates)
        if mopts["mkv_fonts"]:
            mkv_candidates = [
                (rel, fp)
                for rel, fp in files
                if fp.suffix.lower() in forge_media.MKV_FONT_EXTS
            ]
            if len(mkv_candidates) >= 2:
                mkv_assets, mkv_spans = forge_media.plan_mkv_font_dedup(mkv_candidates)

    # Optional domain dictionary training (reads at most 64 KB per file, never whole files).
    dict_bytes = b""
    if prof_cfg.get("train_dict"):
        sample_parts: list[bytes] = []
        sample_total = 0
        for _, fpath in files:
            kind = _classify_path(fpath, cfg)
            if kind in {"code", "json", "logs", "docs"}:
                with fpath.open("rb") as sf:
                    chunk = sf.read(65536)
                if chunk:
                    sample_parts.append(chunk)
                    sample_total += len(chunk)
                    if sample_total >= 1_500_000:
                        break
        if sample_total >= 32768:
            dict_bytes = train_dict(
                b"".join(sample_parts), int(prof_cfg.get("dict_bytes", 65536))
            )

    salt = _random_bytes(16)
    if encrypted:
        assert passphrase is not None
        mem_kib = int(
            kdf_mem_kib if kdf_mem_kib is not None else cfg["kdf"]["default_mem_kib"]
        )
        iters = int(
            kdf_iters if kdf_iters is not None else cfg["kdf"]["default_iterations"]
        )
        lanes = 1
        manifest_key, chunk_key, dedup_key = _derive_keys(
            passphrase, salt, mem_kib, iters, lanes
        )
        aes_nonce_prefix = _random_bytes(4)
    else:
        mem_kib = 0
        iters = 0
        lanes = 0
        manifest_key = b""
        chunk_key = b""
        dedup_key = _plain_dedup_key(salt)
        aes_nonce_prefix = b""

    avg_kb = int(prof_cfg.get("chunk_avg_kb", 128))
    min_chunk = max(16384, (avg_kb * 1024) // 4)
    avg_chunk = avg_kb * 1024
    max_chunk = avg_chunk * 4

    seen_chunks: dict[bytes, int] = {}
    file_entries: list[dict[str, Any]] = []
    codec_counts: dict[str, int] = {}
    chunk_count = 0
    total_raw = 0
    total_refs = 0
    dedup_saved = 0
    bypassed_files = 0
    bypassed_bytes = 0
    media_files = 0
    media_saved_bytes = 0
    media_stage_counts: dict[str, int] = {}
    tensor_files = 0
    tensor_lossy_files = 0
    tensor_saved_bytes = 0
    tensor_stage_counts: dict[str, int] = {}
    manifest_media_assets: dict[str, dict[str, Any]] = {}
    mkv_asset_stored_bytes = 0
    mkv_replaced_total_bytes = 0

    out_path = Path(out_vault)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=".fvlt_pack_", suffix=".tmp", dir=out_path.parent
    )
    tmp_path = Path(tmp_name)
    total_file_count = len(files)

    try:
        with os.fdopen(tmp_fd, "wb") as f:
            # Reserve 48 bytes for the final authenticated header.
            f.write(b"\x00" * HEADER_SIZE)
            lib_native = try_get_lib()

            def _emit_chunks(
                chunk_list: list[bytes],
                target_codec: int,
                target_level: int,
                want_dict: bool,
                kind: str,
            ) -> tuple[list[int], bool, bool, int]:
                nonlocal chunk_count, total_refs, dedup_saved
                indices: list[int] = []
                all_raw = bool(chunk_list) and kind == "incompressible"
                bypassed = kind == "incompressible"
                stored_payload_bytes = 0
                for chunk in chunk_list:
                    total_refs += 1
                    cid = _keyed_chunk_id(dedup_key, chunk)
                    if cid in seen_chunks:
                        indices.append(seen_chunks[cid])
                        dedup_saved += len(chunk)
                        continue

                    chosen_codec = (
                        target_codec
                        if lib_native is not None
                        else fvp.map_portable_codec(target_codec)
                    )
                    if (
                        chosen_codec != CODEC_RAW
                        and kind == "default"
                        and len(chunk) >= 4096
                    ):
                        if entropy_probe(chunk) > 7.85:
                            chosen_codec = CODEC_RAW
                            bypassed = True

                    used_dict = want_dict and chosen_codec != CODEC_RAW
                    active_dict = dict_bytes if used_dict else b""
                    if chosen_codec == CODEC_RAW:
                        comp = compress_bytes(chunk, CODEC_RAW, 0)
                        used_dict = False
                    else:
                        comp = compress_bytes(
                            chunk, chosen_codec, target_level, active_dict
                        )
                        if len(comp) >= len(chunk) + 4:
                            chosen_codec = CODEC_RAW
                            used_dict = False
                            comp = compress_bytes(chunk, CODEC_RAW, 0)
                    if chosen_codec != CODEC_RAW:
                        all_raw = False

                    chunk_flags = CHUNK_FLAG_USED_DICT if used_dict else 0
                    chunk_idx = chunk_count
                    chunk_count += 1

                    aad = (
                        MAGIC
                        + cid
                        + struct.pack(
                            "<BBIQ",
                            chosen_codec,
                            chunk_flags,
                            len(chunk),
                            chunk_idx,
                        )
                    )
                    if encrypted:
                        if cipher_id == CIPHER_AES256GCM:
                            nonce = aes_nonce_prefix + struct.pack("<Q", chunk_idx)
                        else:
                            nonce = _random_bytes(nonce_len)
                        payload = _aead_encrypt(cipher_id, chunk_key, nonce, aad, comp)
                    else:
                        nonce = b""
                        payload = comp + blake3_hash(aad + comp)

                    f.write(
                        struct.pack(
                            CHUNK_HDR_FMT,
                            cid,
                            chosen_codec,
                            chunk_flags,
                            len(chunk),
                            len(nonce),
                            len(payload),
                        )
                    )
                    if nonce:
                        f.write(nonce)
                    f.write(payload)
                    stored_payload_bytes += len(comp)

                    seen_chunks[cid] = chunk_idx
                    indices.append(chunk_idx)
                    cname = codec_names.get(chosen_codec, str(chosen_codec))
                    codec_counts[cname] = codec_counts.get(cname, 0) + 1
                return indices, bypassed, all_raw, stored_payload_bytes

            asset_codec = (
                CODEC_ZSTD_MAX
                if profile == "max"
                else (CODEC_KRAKEN_HUFF8 if lib_native is not None else CODEC_ZSTD_FAST)
            )
            asset_level = (
                19 if profile == "max" else (2 if lib_native is not None else 3)
            )

            def _ensure_mkv_asset_stored(sha: str) -> None:
                nonlocal mkv_asset_stored_bytes
                if sha in manifest_media_assets:
                    return
                blob = mkv_assets[sha]
                a_chunks = fastcdc_split(blob, min_chunk, avg_chunk, max_chunk)
                a_indices, _, _, a_stored = _emit_chunks(
                    a_chunks, asset_codec, asset_level, False, "default"
                )
                manifest_media_assets[sha] = {
                    "size": len(blob),
                    "chunks": a_indices,
                }
                mkv_asset_stored_bytes += a_stored

            def _fastcdc_cut_win(window: bytes) -> int:
                if lib_native is not None:
                    return int(
                        lib_native.fv_fastcdc_cut(
                            window, len(window), min_chunk, avg_chunk, max_chunk
                        )
                    )
                return fvp.fastcdc_cut_pure(window, min_chunk, avg_chunk, max_chunk)

            for file_idx, (rel, fpath) in enumerate(files, start=1):
                if progress_cb is not None:
                    progress_cb(file_idx, max(total_file_count, 1), rel)
                st = fpath.stat()
                kind = _classify_path(fpath, cfg)
                ext = fpath.suffix.lower()
                route = prof_cfg["routing"].get(kind, prof_cfg["routing"]["default"])
                target_codec = codec_map[route["codec"]]
                target_level = int(route["level"])
                want_dict = (
                    bool(dict_bytes)
                    and kind in {"code", "json", "logs", "docs"}
                    and target_codec
                    in {
                        CODEC_SIMD_SELKIE,
                        CODEC_KRAKEN_HUFF8,
                        CODEC_KRAKEN_TANS8,
                        CODEC_ZSTD_FAST,
                        CODEC_ZSTD_MAX,
                    }
                )

                media_meta: dict[str, Any] | None = None
                chunks: list[bytes]
                f_sha: str
                f_size: int

                if mopts["enabled"] and rel in mp4_plans:
                    fmp1_payload, media_meta = mp4_plans.pop(rel)
                    f_sha, f_size = _stream_file_sha_and_size(fpath)
                    chunks = fastcdc_split(
                        fmp1_payload, min_chunk, avg_chunk, max_chunk
                    )
                    del fmp1_payload
                    media_files += 1
                    media_saved_bytes += max(0, f_size - int(media_meta["stored_size"]))
                    media_stage_counts["mp4_packet_dedup"] = (
                        media_stage_counts.get("mp4_packet_dedup", 0) + 1
                    )
                elif mopts["enabled"] and rel in mkv_spans:
                    spans = mkv_spans[rel]
                    try:
                        chunks, skel_total, f_sha, f_size = (
                            forge_media.stream_mkv_skeleton_chunks(
                                fpath,
                                spans,
                                _fastcdc_cut_win,
                                min_chunk,
                                max_chunk,
                            )
                        )
                        span_list: list[list[Any]] = [
                            [off, length, sha] for off, length, sha in spans
                        ]
                        chk_h = hashlib.sha256()
                        chk_n = forge_media.rebuild_mkv_stream(
                            chunks,
                            span_list,
                            mkv_assets.__getitem__,
                            chk_h.update,
                        )
                        if chk_n != f_size or chk_h.hexdigest() != f_sha:
                            raise forge_media.MediaStageError(
                                "MKV pack-time verify mismatch"
                            )
                    except forge_media.MediaStageError:
                        chunks, f_sha, f_size = _iter_file_chunks(
                            fpath, min_chunk, avg_chunk, max_chunk
                        )
                    else:
                        for _, _, sha in spans:
                            _ensure_mkv_asset_stored(sha)
                        media_meta = {
                            "stage": "mkv_font_dedup",
                            "stored_size": skel_total,
                            "spans": span_list,
                        }
                        media_files += 1
                        mkv_replaced_total_bytes += sum(
                            length for _, length, _ in spans
                        )
                        media_stage_counts["mkv_font_dedup"] = (
                            media_stage_counts.get("mkv_font_dedup", 0) + 1
                        )
                elif (
                    mopts["enabled"]
                    and mopts["jpeg"]
                    and ext in forge_media.JPEG_EXTS
                    and st.st_size <= 256 * 1024 * 1024
                ):
                    raw_bytes = fpath.read_bytes()
                    encoded = forge_media.encode_jpeg_jxl(raw_bytes)
                    if encoded is not None:
                        jxl_bytes, media_meta = encoded
                        f_sha = hashlib.sha256(raw_bytes).hexdigest()
                        f_size = len(raw_bytes)
                        chunks = fastcdc_split(
                            jxl_bytes, min_chunk, avg_chunk, max_chunk
                        )
                        media_files += 1
                        media_saved_bytes += max(0, f_size - len(jxl_bytes))
                        media_stage_counts["jxl_jpeg"] = (
                            media_stage_counts.get("jxl_jpeg", 0) + 1
                        )
                    else:
                        f_sha = hashlib.sha256(raw_bytes).hexdigest()
                        f_size = len(raw_bytes)
                        chunks = fastcdc_split(
                            raw_bytes, min_chunk, avg_chunk, max_chunk
                        )
                elif (
                    mopts["enabled"]
                    and mopts["png"]
                    and ext in forge_media.PNG_EXTS
                    and st.st_size <= 256 * 1024 * 1024
                ):
                    raw_bytes = fpath.read_bytes()
                    encoded = forge_media.encode_png_recipe(
                        raw_bytes, native_lib=lib_native
                    )
                    if encoded is not None:
                        envelope, media_meta = encoded
                        f_sha = hashlib.sha256(raw_bytes).hexdigest()
                        f_size = len(raw_bytes)
                        chunks = fastcdc_split(
                            envelope, min_chunk, avg_chunk, max_chunk
                        )
                        media_files += 1
                        media_saved_bytes += max(0, f_size - len(envelope))
                        media_stage_counts["png_recipe_jxl"] = (
                            media_stage_counts.get("png_recipe_jxl", 0) + 1
                        )
                    else:
                        f_sha = hashlib.sha256(raw_bytes).hexdigest()
                        f_size = len(raw_bytes)
                        chunks = fastcdc_split(
                            raw_bytes, min_chunk, avg_chunk, max_chunk
                        )
                elif (
                    topts["enabled"]
                    and ext in forge_tensor_pack.TENSOR_EXTS
                    and forge_tensor_pack.MIN_ARRAY_BYTES
                    <= st.st_size
                    <= 256 * 1024 * 1024
                ):
                    raw_bytes = fpath.read_bytes()
                    raw_chunks = fastcdc_split(
                        raw_bytes, min_chunk, avg_chunk, max_chunk
                    )
                    # Measure Pack's real existing stage on this file so TT is picked
                    # automatically ONLY when it strictly beats Pack's current stage.
                    pack_base = 0
                    for rc in raw_chunks:
                        c_b = compress_bytes(
                            rc,
                            target_codec,
                            target_level,
                            dict_bytes if want_dict else b"",
                        )
                        pack_base += min(len(c_b), len(rc))
                    encoded_tt = forge_tensor_pack.encode_file_bytes(
                        raw_bytes,
                        ext,
                        mode=str(topts["mode"]),
                        rel_tol=float(topts["rel_tol"]),
                        max_rank=int(topts["max_rank"]),
                        require_beat_baseline=True,
                        min_gain=float(topts["min_gain"]),
                        baseline_bytes=pack_base,
                    )
                    if encoded_tt is not None:
                        ftt_bytes, media_meta = encoded_tt
                        f_sha = str(media_meta["reconstructed_sha256"])
                        f_size = int(media_meta["orig_size"])
                        chunks = fastcdc_split(
                            ftt_bytes, min_chunk, avg_chunk, max_chunk
                        )
                        tensor_files += 1
                        if media_meta.get("lossy"):
                            tensor_lossy_files += 1
                        tensor_saved_bytes += max(0, pack_base - len(ftt_bytes))
                        t_key = "tt_lossy" if media_meta.get("lossy") else "tt_lossless"
                        tensor_stage_counts[t_key] = (
                            tensor_stage_counts.get(t_key, 0) + 1
                        )
                    else:
                        f_sha = hashlib.sha256(raw_bytes).hexdigest()
                        f_size = len(raw_bytes)
                        chunks = raw_chunks
                else:
                    chunks, f_sha, f_size = _iter_file_chunks(
                        fpath, min_chunk, avg_chunk, max_chunk
                    )

                total_raw += f_size
                emit_codec = CODEC_RAW if media_meta is not None else target_codec
                emit_dict = False if media_meta is not None else want_dict
                chunk_indices, file_bypassed, file_all_raw, _ = _emit_chunks(
                    chunks, emit_codec, target_level, emit_dict, kind
                )

                if media_meta is None and (file_bypassed or file_all_raw):
                    bypassed_files += 1
                    bypassed_bytes += f_size

                entry: dict[str, Any] = {
                    "path": rel,
                    "size": f_size,
                    "sha256": f_sha,
                    "mode": int(st.st_mode & 0o777),
                    "mtime_ns": int(st.st_mtime_ns),
                    "kind": kind,
                    "chunks": chunk_indices,
                }
                if media_meta is not None:
                    entry["media"] = media_meta
                file_entries.append(entry)

            if mkv_replaced_total_bytes > mkv_asset_stored_bytes:
                media_saved_bytes += mkv_replaced_total_bytes - mkv_asset_stored_bytes

            has_media = media_files > 0
            has_tensor = tensor_files > 0
            manifest_offset = f.tell()
            manifest_codec = (
                CODEC_ZSTD_FAST
                if (encrypted or lib_native is None)
                else CODEC_KRAKEN_HUFF8
            )
            flags = (
                (HEADER_FLAG_HAS_DICT if dict_bytes else 0)
                | (
                    HEADER_FLAG_MANIFEST_KRAKEN
                    if manifest_codec == CODEC_KRAKEN_HUFF8
                    else 0
                )
                | (HEADER_FLAG_HAS_MEDIA if has_media else 0)
                | (HEADER_FLAG_HAS_TENSOR if has_tensor else 0)
            )
            header = struct.pack(
                HEADER_FMT,
                MAGIC,
                1,
                cipher_id,
                PROFILE_IDS[profile],
                flags,
                mem_kib,
                iters,
                lanes,
                salt,
                chunk_count,
            )

            manifest_obj: dict[str, Any] = {
                "version": 1,
                "profile": profile,
                "cipher": cipher,
                "encrypted": encrypted,
                "total_raw_bytes": total_raw,
                "dedup_saved_bytes": dedup_saved,
                "bypassed_files": bypassed_files,
                "bypassed_bytes": bypassed_bytes,
                "skipped_files": skipped_files,
                "skipped_bytes": skipped_bytes,
                "dict_bytes": len(dict_bytes),
                "codec_counts": codec_counts,
                "empty_dirs": empty_dirs,
                "files": file_entries,
            }
            if has_media or has_tensor:
                manifest_obj["format_minor"] = 1
            if has_media:
                manifest_obj["media_stage"] = {
                    "enabled": True,
                    "files": media_files,
                    "saved_bytes": media_saved_bytes,
                    "stages": media_stage_counts,
                    "requires_djxl": bool(
                        media_stage_counts.get("jxl_jpeg")
                        or media_stage_counts.get("png_recipe_jxl")
                    ),
                }
                if manifest_media_assets:
                    manifest_obj["media_assets"] = manifest_media_assets
            if has_tensor:
                manifest_obj["tensor_stage"] = {
                    "enabled": True,
                    "mode": str(topts["mode"]),
                    "rel_tol": float(topts["rel_tol"]),
                    "files": tensor_files,
                    "lossy_files": tensor_lossy_files,
                    "saved_bytes": tensor_saved_bytes,
                    "stages": tensor_stage_counts,
                }

            manifest_json = json.dumps(manifest_obj, separators=(",", ":")).encode(
                "utf-8"
            )
            manifest_plain = (
                struct.pack("<I", len(manifest_json)) + manifest_json + dict_bytes
            )
            manifest_comp = compress_bytes(
                manifest_plain,
                manifest_codec,
                6 if manifest_codec == CODEC_ZSTD_FAST else 1,
            )

            if encrypted:
                manifest_nonce = _random_bytes(nonce_len)
                manifest_ct_len = len(manifest_comp) + 16
                manifest_aad = header + struct.pack(
                    "<QBI", manifest_offset, len(manifest_nonce), manifest_ct_len
                )
                manifest_payload = _aead_encrypt(
                    cipher_id, manifest_key, manifest_nonce, manifest_aad, manifest_comp
                )
            else:
                manifest_nonce = b""
                manifest_ct_len = len(manifest_comp) + 32
                manifest_aad = header + struct.pack(
                    "<QBI", manifest_offset, 0, manifest_ct_len
                )
                manifest_tag = blake3_hash(manifest_aad + manifest_comp)
                manifest_payload = manifest_comp + manifest_tag

            f.write(
                struct.pack(
                    MANIFEST_PREFIX_FMT, len(manifest_nonce), len(manifest_payload)
                )
            )
            if manifest_nonce:
                f.write(manifest_nonce)
            f.write(manifest_payload)
            f.write(struct.pack(FOOTER_FMT, manifest_offset, FOOTER_MAGIC))

            f.seek(0)
            f.write(header)
            f.flush()

        os.replace(tmp_path, out_path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    elapsed = time.perf_counter() - t0
    return VaultStats(
        files=len(files),
        raw_bytes=total_raw,
        vault_bytes=out_path.stat().st_size,
        unique_chunks=chunk_count,
        total_chunk_refs=total_refs,
        dedup_saved_bytes=dedup_saved,
        dict_bytes=len(dict_bytes),
        elapsed_sec=elapsed,
        codec_counts=codec_counts,
        cipher=cipher,
        profile=profile,
        encrypted=encrypted,
        bypassed_files=bypassed_files,
        bypassed_bytes=bypassed_bytes,
        skipped_files=skipped_files,
        skipped_bytes=skipped_bytes,
        media_stage=has_media,
        media_files=media_files,
        media_saved_bytes=media_saved_bytes,
        media_stage_counts=media_stage_counts,
        tensor_stage=has_tensor,
        tensor_files=tensor_files,
        tensor_lossy_files=tensor_lossy_files,
        tensor_saved_bytes=tensor_saved_bytes,
        tensor_stage_counts=tensor_stage_counts,
    )


def pack_path(
    source: Path | str,
    out_vault: Path | str,
    passphrase: str | bytes | None,
    *,
    profile: str = "fast",
    cipher: str = "aes256gcm",
    kdf_mem_kib: int | None = None,
    kdf_iters: int | None = None,
    skip_incompressible: bool = False,
    media_stage: bool = False,
    media_options: dict[str, Any] | None = None,
    tensor_stage: bool = False,
    tensor_options: dict[str, Any] | None = None,
) -> VaultStats:
    """Compress, deduplicate, and optionally AEAD-encrypt a file or directory tree."""
    return pack_sources(
        [source],
        out_vault,
        passphrase,
        profile=profile,
        cipher=cipher,
        kdf_mem_kib=kdf_mem_kib,
        kdf_iters=kdf_iters,
        skip_incompressible=skip_incompressible,
        media_stage=media_stage,
        media_options=media_options,
        tensor_stage=tensor_stage,
        tensor_options=tensor_options,
    )


def _open_and_auth_vault(
    vault_path: Path, passphrase: str | bytes | None
) -> tuple[bytes, int, int, bytes, bytes, dict[str, Any], bytes, int, int]:
    """Authenticate vault header & manifest. Raises VaultAuthError on wrong passphrase or tamper."""
    file_size = vault_path.stat().st_size
    if file_size < HEADER_SIZE + FOOTER_SIZE + MANIFEST_PREFIX_SIZE + 16:
        raise VaultError("vault file truncated or invalid")

    with vault_path.open("rb") as f:
        header = f.read(HEADER_SIZE)
        (
            magic,
            ver,
            cipher_id,
            prof_id,
            flags,
            mem_kib,
            iters,
            lanes,
            salt,
            chunk_cnt,
        ) = struct.unpack(HEADER_FMT, header)
        if magic != MAGIC or ver != 1:
            raise VaultError("not a Forge Vault v1 file")
        if cipher_id == CIPHER_NONE:
            expected_nonce_len = 0
            min_manifest_len = 32
        elif cipher_id == CIPHER_AES256GCM:
            expected_nonce_len = 12
            min_manifest_len = 16
        elif cipher_id == CIPHER_XCHACHA20:
            expected_nonce_len = 24
            min_manifest_len = 16
        else:
            raise VaultError(f"unsupported cipher id: {cipher_id}")
        _ = PROFILE_NAMES.get(prof_id, "fast")

        f.seek(file_size - FOOTER_SIZE)
        manifest_offset, fmagic = struct.unpack(FOOTER_FMT, f.read(FOOTER_SIZE))
        if (
            fmagic != FOOTER_MAGIC
            or manifest_offset < HEADER_SIZE
            or manifest_offset >= file_size - FOOTER_SIZE
        ):
            raise VaultAuthError("invalid vault footer")

        f.seek(manifest_offset)
        prefix = f.read(MANIFEST_PREFIX_SIZE)
        if len(prefix) != MANIFEST_PREFIX_SIZE:
            raise VaultAuthError("truncated manifest header")
        m_nlen, m_clen = struct.unpack(MANIFEST_PREFIX_FMT, prefix)
        if (
            m_nlen != expected_nonce_len
            or m_clen < min_manifest_len
            or manifest_offset + MANIFEST_PREFIX_SIZE + m_nlen + m_clen + FOOTER_SIZE
            != file_size
        ):
            raise VaultAuthError("manifest size or nonce mismatch")
        m_nonce = f.read(m_nlen) if m_nlen else b""
        m_ct = f.read(m_clen)

    manifest_aad = header + struct.pack("<QBI", manifest_offset, m_nlen, m_clen)
    if cipher_id == CIPHER_NONE:
        manifest_comp = m_ct[:-32]
        manifest_tag = m_ct[-32:]
        if blake3_hash(manifest_aad + manifest_comp) != manifest_tag:
            raise VaultAuthError("manifest integrity check failed (corrupted pack)")
        chunk_key = b""
        dedup_key = _plain_dedup_key(salt)
    else:
        if passphrase is None or len(passphrase) == 0:
            raise VaultAuthError("passphrase required for encrypted vault")
        manifest_key, chunk_key, dedup_key = _derive_keys(
            passphrase, salt, mem_kib, iters, lanes
        )
        manifest_comp = _aead_decrypt(
            cipher_id, manifest_key, m_nonce, manifest_aad, m_ct
        )

    # Read uncompressed manifest size ONLY AFTER authentication has succeeded!
    lib_opt = try_get_lib()
    m_plen = (
        int(lib_opt.fv_decompressed_size(manifest_comp, len(manifest_comp)))
        if lib_opt is not None
        else fvp.decompressed_size(manifest_comp)
    )
    if m_plen < 4 or m_plen > MAX_MANIFEST_PLAIN_BYTES:
        raise VaultAuthError("invalid manifest uncompressed size")

    manifest_codec = (
        CODEC_KRAKEN_HUFF8 if (flags & HEADER_FLAG_MANIFEST_KRAKEN) else CODEC_ZSTD_FAST
    )
    manifest_plain = decompress_bytes(manifest_comp, m_plen, manifest_codec)
    json_len = struct.unpack("<I", manifest_plain[:4])[0]
    if 4 + json_len > len(manifest_plain):
        raise VaultAuthError("malformed manifest JSON length")
    manifest = json.loads(manifest_plain[4 : 4 + json_len].decode("utf-8"))
    dict_bytes = manifest_plain[4 + json_len :]
    return (
        header,
        cipher_id,
        expected_nonce_len,
        chunk_key,
        dedup_key,
        manifest,
        dict_bytes,
        int(chunk_cnt),
        int(manifest_offset),
    )


def inspect_vault(
    vault_path: Path | str, passphrase: str | bytes | None = None
) -> dict[str, Any]:
    """Authenticate and return decrypted vault metadata without extracting files."""
    _, cipher_id, _, _, _, manifest, _, chunk_cnt, _ = _open_and_auth_vault(
        Path(vault_path), passphrase
    )
    return {
        "vault_bytes": Path(vault_path).stat().st_size,
        "unique_chunks": chunk_cnt,
        "encrypted": cipher_id != CIPHER_NONE,
        **manifest,
    }


def unpack_vault(
    vault_path: Path | str,
    dest_dir: Path | str | None,
    passphrase: str | bytes | None = None,
    *,
    verify_only: bool = False,
    max_cache_bytes: int = MAX_DECODE_CACHE_BYTES,
    only_paths: set[str] | None = None,
    progress_cb: Callable[[int, int, str], None] | None = None,
) -> VaultStats:
    """Authenticate, decrypt (if encrypted), decompress, and SHA-256 verify files in `.fpack`/`.fvlt`."""
    t0 = time.perf_counter()
    vpath = Path(vault_path)
    (
        _,
        cipher_id,
        expected_nonce_len,
        chunk_key,
        dedup_key,
        manifest,
        dict_bytes,
        chunk_cnt,
        manifest_offset,
    ) = _open_and_auth_vault(vpath, passphrase)
    encrypted = cipher_id != CIPHER_NONE
    min_chunk_len = 16 if encrypted else 36

    chunk_records: list[tuple[bytes, int, int, int, int, int, int]] = []
    with vpath.open("rb") as f:
        f.seek(HEADER_SIZE)
        for idx in range(chunk_cnt):
            hdr_bytes = f.read(CHUNK_HDR_SIZE)
            if len(hdr_bytes) != CHUNK_HDR_SIZE:
                raise VaultAuthError(f"truncated chunk header at {idx}")
            cid, codec_id, chunk_flags, raw_len, nlen, ct_len = struct.unpack(
                CHUNK_HDR_FMT, hdr_bytes
            )
            nonce_off = f.tell()
            if (
                nlen != expected_nonce_len
                or raw_len > MAX_CHUNK_RAW_BYTES
                or ct_len < min_chunk_len
                or nonce_off + nlen + ct_len > manifest_offset
            ):
                raise VaultAuthError(f"invalid chunk bounds at index {idx}")
            f.seek(nlen + ct_len, os.SEEK_CUR)
            chunk_records.append(
                (cid, codec_id, chunk_flags, raw_len, nonce_off, nlen, ct_len)
            )

        # Reject any unauthenticated smuggled bytes between the last chunk and manifest.
        if f.tell() != manifest_offset:
            raise VaultAuthError("unauthenticated gap between chunk store and manifest")

        all_entries = manifest.get("files")
        if not isinstance(all_entries, list):
            raise VaultAuthError("malformed manifest files list")
        entries_by_path: dict[str, dict[str, Any]] = {}
        for fe in all_entries:
            if (
                not isinstance(fe, dict)
                or not isinstance(fe.get("path"), str)
                or type(fe.get("size")) is not int
                or fe["size"] < 0
                or not isinstance(fe.get("chunks"), list)
            ):
                raise VaultAuthError("malformed file entry in manifest")
            entries_by_path[fe["path"]] = fe
        raw_assets = manifest.get("media_assets")
        if raw_assets is None:
            media_assets_spec: dict[str, dict[str, Any]] = {}
        elif isinstance(raw_assets, dict):
            media_assets_spec = raw_assets
        else:
            raise VaultAuthError("malformed manifest media_assets")
        selected_entries = (
            [fe for fe in all_entries if fe["path"] in only_paths]
            if only_paths is not None
            else all_entries
        )

        def _valid_ci(val: Any) -> bool:
            return type(val) is int and 0 <= val < chunk_cnt

        refcounts = [0] * chunk_cnt
        png_recipe_files = 0
        png_stored_files = 0  # level-0 recipes (stored blocks)
        for fe in selected_entries:
            for ci in fe["chunks"]:
                if not _valid_ci(ci):
                    raise VaultAuthError(f"invalid chunk index {ci}")
                refcounts[ci] += 1
            media = fe.get("media")
            if media is not None:
                if not isinstance(media, dict):
                    raise VaultAuthError(f"malformed media metadata for {fe['path']!r}")
                stage = media.get("stage")
                if stage == "png_recipe_jxl":
                    png_recipe_files += 1
                    recipe = media.get("recipe")
                    if isinstance(recipe, list) and recipe and recipe[0] == 0:
                        png_stored_files += 1
                elif stage == "mp4_packet_dedup":
                    ref_path = media.get("ref_path")
                    if not isinstance(ref_path, str) or not ref_path:
                        raise VaultAuthError("missing mp4_packet_dedup ref_path")
                    ref_fe = entries_by_path.get(ref_path)
                    if ref_fe is None or ref_fe.get("media") is not None:
                        raise VaultAuthError(
                            f"invalid mp4_packet_dedup ref_path {ref_path!r}"
                        )
                    for rci in ref_fe["chunks"]:
                        if not _valid_ci(rci):
                            raise VaultAuthError(f"invalid ref chunk index {rci}")
                        refcounts[rci] += 2
                elif stage == "mkv_font_dedup":
                    spans_val = media.get("spans")
                    if not isinstance(spans_val, list):
                        raise VaultAuthError("malformed mkv_font_dedup spans")
                    for sp in spans_val:
                        if not isinstance(sp, (list, tuple)) or len(sp) != 3:
                            raise VaultAuthError("malformed mkv_font_dedup span")
                        asha = str(sp[2])
                        aspec = media_assets_spec.get(asha)
                        if (
                            not isinstance(aspec, dict)
                            or type(aspec.get("size")) is not int
                            or aspec["size"] < 0
                            or not isinstance(aspec.get("chunks"), list)
                        ):
                            raise VaultAuthError(f"missing or malformed asset {asha!r}")
                        for aci in aspec["chunks"]:
                            if not _valid_ci(aci):
                                raise VaultAuthError(f"invalid asset chunk index {aci}")
                            refcounts[aci] += 2

        # PNG recipes re-deflate with classic zlib: refuse before writing
        # anything when there is none here (Windows' Python has zlib-ng)
        if png_recipe_files:
            why = forge_media.png_recipes_restorable(stored=png_stored_files > 0)
            if why:
                raise VaultError(
                    f"{why} ({png_recipe_files} PNG file(s) in this pack need it; "
                    "nothing was written.)"
                )

        # Bounded LRU cache for deduplicated chunks (protects tight laptop RAM).
        decoded_cache: OrderedDict[int, bytes] = OrderedDict()
        cache_bytes = 0
        authenticated_chunks: set[int] = set()
        decoded_assets: dict[str, bytes] = {}
        ref_offset_tables: dict[str, tuple[list[int], list[int]]] = {}

        def decode_chunk(ci: int) -> bytes:
            nonlocal cache_bytes
            if ci in decoded_cache:
                decoded_cache.move_to_end(ci)
                return decoded_cache[ci]
            cid, codec_id, chunk_flags, raw_len, nonce_off, nlen, ct_len = (
                chunk_records[ci]
            )
            f.seek(nonce_off)
            nonce = f.read(nlen) if nlen else b""
            ct = f.read(ct_len)
            aad = MAGIC + cid + struct.pack("<BBIQ", codec_id, chunk_flags, raw_len, ci)
            if encrypted:
                comp = _aead_decrypt(cipher_id, chunk_key, nonce, aad, ct)
            else:
                comp = ct[:-32]
                chunk_tag = ct[-32:]
                if blake3_hash(aad + comp) != chunk_tag:
                    raise VaultAuthError(
                        f"chunk {ci} BLAKE3 integrity mismatch (corrupted pack)"
                    )
            used_dict = bool(chunk_flags & CHUNK_FLAG_USED_DICT)
            raw_chunk = decompress_bytes(
                comp, raw_len, codec_id, dict_bytes if used_dict else b""
            )
            if not encrypted and _keyed_chunk_id(dedup_key, raw_chunk) != cid:
                raise VaultAuthError(
                    f"chunk {ci} BLAKE3 content mismatch (corrupted pack)"
                )
            authenticated_chunks.add(ci)
            if (
                refcounts[ci] > 1
                and max_cache_bytes > 0
                and len(raw_chunk) <= max_cache_bytes
            ):
                while cache_bytes + len(raw_chunk) > max_cache_bytes and decoded_cache:
                    _, evicted = decoded_cache.popitem(last=False)
                    cache_bytes -= len(evicted)
                decoded_cache[ci] = raw_chunk
                cache_bytes += len(raw_chunk)
            return raw_chunk

        def read_ref_range(ref_path: str, offset: int, length: int) -> bytes:
            if ref_path not in ref_offset_tables:
                rfe = entries_by_path[ref_path]
                ends: list[int] = []
                cids_list: list[int] = []
                acc = 0
                for rci in rfe["chunks"]:
                    acc += chunk_records[rci][3]
                    ends.append(acc)
                    cids_list.append(rci)
                ref_offset_tables[ref_path] = (ends, cids_list)
            ends, cids_list = ref_offset_tables[ref_path]
            if offset < 0 or length < 0 or not ends or offset + length > ends[-1]:
                raise VaultError("mp4_packet_dedup reference range out of bounds")
            out = bytearray()
            cur = offset
            rem = length
            idx = bisect.bisect_right(ends, cur)
            while rem > 0 and idx < len(ends):
                c_start = ends[idx - 1] if idx > 0 else 0
                raw_c = decode_chunk(cids_list[idx])
                in_off = cur - c_start
                take = min(rem, len(raw_c) - in_off)
                out.extend(raw_c[in_off : in_off + take])
                cur += take
                rem -= take
                idx += 1
            return bytes(out)

        def get_media_asset(sha: str) -> bytes:
            if sha in decoded_assets:
                return decoded_assets[sha]
            aspec = media_assets_spec.get(sha)
            if not isinstance(aspec, dict):
                raise VaultAuthError(f"missing media asset {sha!r}")
            parts = [decode_chunk(aci) for aci in aspec["chunks"]]
            blob = b"".join(parts)
            if (
                len(blob) != int(aspec["size"])
                or hashlib.sha256(blob).hexdigest() != sha
            ):
                raise VaultAuthError(f"media asset {sha[:12]} SHA-256 mismatch")
            decoded_assets[sha] = blob
            return blob

        out_root: Path | None = None
        if dest_dir is not None and not verify_only:
            out_root = Path(dest_dir)
            out_root.mkdir(parents=True, exist_ok=True)
            out_root = out_root.resolve()
            if only_paths is None:
                for ed in manifest.get("empty_dirs", []):
                    ed_rel = _safe_rel_path(ed)
                    cur = out_root
                    for part in ed_rel.parts:
                        nxt = cur / part
                        if nxt.is_symlink():
                            raise VaultError(
                                f"refusing to traverse symlink directory: {nxt}"
                            )
                        if not nxt.resolve().is_relative_to(out_root):
                            raise VaultError(
                                f"resolved directory escapes destination root: {nxt}"
                            )
                        nxt.mkdir(exist_ok=True)
                        cur = nxt

        total_raw = 0
        total_refs = 0
        total_selected = len(selected_entries)
        for idx, fe in enumerate(selected_entries, start=1):
            if progress_cb is not None:
                progress_cb(idx, max(total_selected, 1), str(fe["path"]))
            rel = _safe_rel_path(fe["path"])
            hasher = hashlib.sha256()
            target: Path | None = None
            tmp_file: Path | None = None
            out_handle = None

            if out_root is not None and not verify_only:
                target = _ensure_safe_target(out_root, rel)
                tfd, tname = tempfile.mkstemp(prefix=".fvlt_out_", dir=target.parent)
                tmp_file = Path(tname)
                out_handle = os.fdopen(tfd, "wb")

            try:
                written = 0
                expected_size = int(fe["size"])
                media = fe.get("media")
                if media is None:
                    for ci in fe["chunks"]:
                        total_refs += 1
                        raw_chunk = decode_chunk(ci)
                        refcounts[ci] -= 1
                        if refcounts[ci] == 0 and ci in decoded_cache:
                            cache_bytes -= len(decoded_cache.pop(ci))

                        if written + len(raw_chunk) > expected_size:
                            raise VaultAuthError(
                                f"decoded output exceeded declared size for {fe['path']}"
                            )
                        hasher.update(raw_chunk)
                        if out_handle is not None:
                            out_handle.write(raw_chunk)
                        written += len(raw_chunk)
                else:
                    stage = str(media.get("stage") or "")

                    def _emit_out(
                        piece: bytes,
                        _h: Any = hasher,
                        _fh: Any = out_handle,
                        _cap: int = expected_size,
                        _path: str = str(fe["path"]),
                    ) -> None:
                        nonlocal written
                        if written + len(piece) > _cap:
                            raise VaultAuthError(
                                f"media stage output exceeded declared size for {_path}"
                            )
                        _h.update(piece)
                        if _fh is not None:
                            _fh.write(piece)
                        written += len(piece)

                    try:
                        if stage == "jxl_jpeg":
                            stored_parts: list[bytes] = []
                            for ci in fe["chunks"]:
                                total_refs += 1
                                stored_parts.append(decode_chunk(ci))
                                refcounts[ci] -= 1
                                if refcounts[ci] == 0 and ci in decoded_cache:
                                    cache_bytes -= len(decoded_cache.pop(ci))
                            restored = forge_media.decode_jpeg_jxl(
                                b"".join(stored_parts),
                                media,
                                max_output_bytes=expected_size,
                            )
                            _emit_out(restored)
                        elif stage == "png_recipe_jxl":
                            stored_parts = []
                            for ci in fe["chunks"]:
                                total_refs += 1
                                stored_parts.append(decode_chunk(ci))
                                refcounts[ci] -= 1
                                if refcounts[ci] == 0 and ci in decoded_cache:
                                    cache_bytes -= len(decoded_cache.pop(ci))
                            restored = forge_media.decode_png_recipe(
                                b"".join(stored_parts),
                                media,
                                native_lib=try_get_lib(),
                            )
                            _emit_out(restored)
                        elif stage == "mp4_packet_dedup":
                            stored_parts = []
                            for ci in fe["chunks"]:
                                total_refs += 1
                                stored_parts.append(decode_chunk(ci))
                                refcounts[ci] -= 1
                                if refcounts[ci] == 0 and ci in decoded_cache:
                                    cache_bytes -= len(decoded_cache.pop(ci))
                            ref_path = str(media["ref_path"])
                            for piece in forge_media.iter_decode_mp4_packet_dedup(
                                b"".join(stored_parts),
                                lambda off, ln, rp=ref_path: read_ref_range(
                                    rp, off, ln
                                ),
                                media,
                            ):
                                _emit_out(piece)
                        elif stage == "mkv_font_dedup":

                            def _iter_skel(
                                _chunks: list[int] = fe["chunks"],
                            ) -> Any:
                                nonlocal total_refs, cache_bytes
                                for ci in _chunks:
                                    total_refs += 1
                                    chunk_b = decode_chunk(ci)
                                    refcounts[ci] -= 1
                                    if refcounts[ci] == 0 and ci in decoded_cache:
                                        cache_bytes -= len(decoded_cache.pop(ci))
                                    yield chunk_b

                            forge_media.rebuild_mkv_stream(
                                _iter_skel(),
                                media["spans"],
                                get_media_asset,
                                _emit_out,
                            )
                        elif stage == "tt_array":
                            stored_parts = []
                            for ci in fe["chunks"]:
                                total_refs += 1
                                stored_parts.append(decode_chunk(ci))
                                refcounts[ci] -= 1
                                if refcounts[ci] == 0 and ci in decoded_cache:
                                    cache_bytes -= len(decoded_cache.pop(ci))
                            restored = forge_tensor_pack.decode_ftt1(
                                b"".join(stored_parts),
                                max_output_bytes=expected_size,
                            )
                            _emit_out(restored)
                        else:
                            raise VaultError(f"unsupported media stage: {stage!r}")
                    except (
                        forge_media.MediaStageError,
                        forge_tensor_pack.TensorPackError,
                    ) as exc:
                        raise VaultError(
                            f"media stage decode failed for {fe['path']}: {exc}"
                        ) from exc

                if out_handle is not None:
                    out_handle.flush()
                    out_handle.close()
                    out_handle = None

                if written != int(fe["size"]) or hasher.hexdigest() != fe["sha256"]:
                    raise VaultAuthError(
                        f"SHA-256 verification failed for {fe['path']}"
                    )

                if tmp_file is not None and target is not None:
                    if os.name == "posix":
                        mode = int(fe.get("mode", 0o644)) & 0o777
                        os.chmod(tmp_file, mode)
                    mtime_ns = fe.get("mtime_ns")
                    if isinstance(mtime_ns, int) and mtime_ns > 0:
                        os.utime(tmp_file, ns=(mtime_ns, mtime_ns))
                    os.replace(tmp_file, target)
                    tmp_file = None
            finally:
                if out_handle is not None:
                    out_handle.close()
                if tmp_file is not None:
                    tmp_file.unlink(missing_ok=True)

            total_raw += written

        # Authenticate any unreferenced chunks when doing full verify/unpack.
        if only_paths is None:
            for ci in range(chunk_cnt):
                if ci not in authenticated_chunks:
                    _ = decode_chunk(ci)

    elapsed = time.perf_counter() - t0
    m_info = manifest.get("media_stage") or {}
    t_info = manifest.get("tensor_stage") or {}
    return VaultStats(
        files=len(selected_entries),
        raw_bytes=total_raw,
        vault_bytes=vpath.stat().st_size,
        unique_chunks=chunk_cnt,
        total_chunk_refs=total_refs,
        dedup_saved_bytes=int(manifest.get("dedup_saved_bytes", 0)),
        dict_bytes=len(dict_bytes),
        elapsed_sec=elapsed,
        codec_counts=dict(manifest.get("codec_counts", {})),
        cipher=str(manifest.get("cipher", CIPHER_NAMES.get(cipher_id, "aes256gcm"))),
        profile=str(manifest.get("profile", "fast")),
        encrypted=encrypted,
        bypassed_files=int(manifest.get("bypassed_files", 0)),
        bypassed_bytes=int(manifest.get("bypassed_bytes", 0)),
        skipped_files=int(manifest.get("skipped_files", 0)),
        skipped_bytes=int(manifest.get("skipped_bytes", 0)),
        media_stage=bool(m_info.get("enabled", False)),
        media_files=int(m_info.get("files", 0)),
        media_saved_bytes=int(m_info.get("saved_bytes", 0)),
        media_stage_counts=dict(m_info.get("stages", {})),
        tensor_stage=bool(t_info.get("enabled", False)),
        tensor_files=int(t_info.get("files", 0)),
        tensor_lossy_files=int(t_info.get("lossy_files", 0)),
        tensor_saved_bytes=int(t_info.get("saved_bytes", 0)),
        tensor_stage_counts=dict(t_info.get("stages", {})),
    )


def verify_vault(
    vault_path: Path | str, passphrase: str | bytes | None = None
) -> VaultStats:
    """Verify AEAD/BLAKE3 tags, decompression, and SHA-256 of every file without writing to disk."""
    return unpack_vault(vault_path, None, passphrase, verify_only=True)


def _get_passphrase(
    arg_pass: str | None, env_var: str = "FORGE_VAULT_PASSPHRASE"
) -> str:
    if arg_pass is not None:
        return arg_pass
    env = os.environ.get(env_var)
    if env is not None:
        return env
    return getpass.getpass("Vault passphrase: ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Forge Vault: fast-decode compressed & encrypted storage"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    pw_help = (
        "Passphrase (prefer FORGE_VAULT_PASSPHRASE env var or interactive prompt "
        "to avoid exposing secrets in shell history/process list)"
    )

    p_pack = sub.add_parser("pack", help="Compress and encrypt a file or directory")
    p_pack.add_argument("source", help="File or directory to pack (read-only)")
    p_pack.add_argument("output", help="Output .fvlt vault file")
    p_pack.add_argument(
        "--profile",
        default="fast",
        choices=list(PROFILE_IDS.keys()),
        help="Compression profile (default: fast)",
    )
    p_pack.add_argument(
        "--cipher",
        default="aes256gcm",
        choices=["aes256gcm", "xchacha20", "none"],
        help="Authenticated cipher, or 'none' for unencrypted pack (default: aes256gcm)",
    )
    p_pack.add_argument(
        "--skip-media",
        action="store_true",
        help="Exclude already-packed media/archive files instead of storing them raw",
    )
    p_pack.add_argument(
        "--media",
        action="store_true",
        help="Enable opt-in bit-exact media stage (JPEG XL repack, PNG recipe, MP4 packet dedup, MKV fonts)",
    )
    p_pack.add_argument(
        "--no-media-video-dedup",
        action="store_true",
        help="Disable MP4 render-version packet dedup when --media is active",
    )
    p_pack.add_argument(
        "--no-media-mkv-fonts",
        action="store_true",
        help="Disable MKV embedded attachment dedup when --media is active",
    )
    p_pack.add_argument("--passphrase", default=None, help=pw_help)

    p_unpack = sub.add_parser("unpack", help="Decrypt and decompress a vault")
    p_unpack.add_argument("vault", help="Input .fpack/.fvlt file")
    p_unpack.add_argument("dest", help="Output directory")
    p_unpack.add_argument("--passphrase", default=None, help=pw_help)

    p_verify = sub.add_parser("verify", help="Verify vault integrity and passphrase")
    p_verify.add_argument("vault", help="Input .fpack/.fvlt file")
    p_verify.add_argument("--passphrase", default=None, help=pw_help)

    p_info = sub.add_parser("info", help="Show decrypted vault metadata")
    p_info.add_argument("vault", help="Input .fpack/.fvlt file")
    p_info.add_argument("--passphrase", default=None, help=pw_help)

    args = parser.parse_args(argv)
    pw: str | None = None
    if args.cmd == "pack":
        if args.cipher != "none":
            pw = _get_passphrase(args.passphrase)
            if not pw:
                print(
                    "Vault error: passphrase cannot be empty for an encrypted vault "
                    "(use --cipher none for an unencrypted pack).",
                    file=sys.stderr,
                )
                return 2
    else:
        try:
            meta_peek = peek_vault(args.vault)
            if meta_peek["encrypted"]:
                pw = _get_passphrase(args.passphrase)
        except VaultError:
            pw = _get_passphrase(args.passphrase)

    try:
        if args.cmd == "pack":
            media_opts = (
                {
                    "jpeg": True,
                    "png": True,
                    "video_dedup": not args.no_media_video_dedup,
                    "mkv_fonts": not args.no_media_mkv_fonts,
                }
                if args.media
                else None
            )
            st = pack_path(
                args.source,
                args.output,
                pw,
                profile=args.profile,
                cipher=args.cipher,
                skip_incompressible=args.skip_media,
                media_stage=args.media,
                media_options=media_opts,
            )
            media_note = (
                f", media stage {st.media_files} files / saved {st.media_saved_bytes:,} B"
                if st.media_files
                else ""
            )
            print(
                f"Packed {st.files} files ({st.raw_bytes:,} B -> {st.vault_bytes:,} B, "
                f"{st.ratio:.2f}x, dedup saved {st.dedup_saved_bytes:,} B, "
                f"dict {st.dict_bytes:,} B{media_note}) in {st.elapsed_sec:.2f} s ({st.throughput_mbs:.1f} MB/s)"
            )
            return 0
        if args.cmd == "unpack":
            st = unpack_vault(args.vault, args.dest, pw)
            print(
                f"Unpacked {st.files} files ({st.raw_bytes:,} B verified SHA-256) "
                f"in {st.elapsed_sec:.2f} s ({st.throughput_mbs:.1f} MB/s)"
            )
            return 0
        if args.cmd == "verify":
            st = verify_vault(args.vault, pw)
            print(
                f"Verified OK: {st.files} files, {st.raw_bytes:,} B, "
                f"{st.unique_chunks} unique chunks in {st.elapsed_sec:.2f} s ({st.throughput_mbs:.1f} MB/s)"
            )
            return 0
        if args.cmd == "info":
            meta = inspect_vault(args.vault, pw)
            print(json.dumps({k: v for k, v in meta.items() if k != "files"}, indent=2))
            print(f"files: {len(meta['files'])}")
            return 0
    except VaultAuthError as exc:
        print(f"Authentication failed: {exc}", file=sys.stderr)
        return 2
    except VaultError as exc:
        print(f"Vault error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
