"""Classic zlib deflate, so Pack's PNG recipes come out the same on every computer.

Pack's `png_recipe_jxl` media stage (shared/forge_media.py) keeps a PNG as its
pixels plus the zlib settings that re-make its compressed image data byte for
byte. That only round-trips when the deflate here writes exactly the bytes the
packing computer's deflate wrote. Classic zlib (zlib.net, Mark Adler's) does:
1.2.12 to 1.4 write identical streams for every recipe setting (Relay task
1578 compared them; 1.2.11 differs at level 0, so it does not count). Python 3.14 for Windows is built with zlib-ng instead
(`zlib.ZLIB_VERSION` "1.3.1.zlib-ng"), whose streams are valid but different,
so there a PNG finds no recipe and a recipe packed elsewhere cannot be restored.

`classic()` returns a deflate that is classic, tried in this order:

1. Python's own zlib, when its version string is plain and it writes the
   golden streams below (a fingerprint over every deflate code path);
2. a classic zlib library loaded with ctypes and checked by the same
   fingerprint: `FORGE_ZLIB_CLASSIC` (a path), Forge's fetched copy (package
   `zlib-classic` in shared/forge_tools.json, fetched on first use where a
   build is listed: Windows), then the system's libz (not on Windows, where a
   DLL found on PATH could be anything).

When none is there it raises `ClassicZlibMissing`, whose words name the cause.

The ctypes path offers zlib output room in the same block sizes CPython's zlib
module does (32 KiB, 64 KiB, 256 KiB, ...): a level-0 stream's stored-block
sizes follow the room offered, so this keeps level 0 identical too. The
standalone unpacker (apps/pack/standalone/forge_unpack.py) carries a copy of
the ctypes part; shared/tests/test_forge_deflate.py keeps the two in step.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import os
import re
import sys
import threading
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

TOOL = "zlib-classic"
ENV_VAR = "FORGE_ZLIB_CLASSIC"

Z_OK = 0
Z_STREAM_END = 1
Z_STREAM_ERROR = -2
Z_BUF_ERROR = -5
Z_NO_FLUSH = 0
Z_FINISH = 4
Z_DEFLATED = 8

_KB = 1024
_MB = 1024 * _KB
# CPython's _BlocksOutputBuffer sizes (Include/internal/pycore_blocks_output_buffer.h);
# each compress() or flush() call starts again from the first.
OUTPUT_BLOCKS = (
    32 * _KB,
    64 * _KB,
    256 * _KB,
    1 * _MB,
    4 * _MB,
    8 * _MB,
    16 * _MB,
    16 * _MB,
    32 * _MB,
    32 * _MB,
    32 * _MB,
    32 * _MB,
    64 * _MB,
    64 * _MB,
    128 * _MB,
    128 * _MB,
)
OUTPUT_MAX_BLOCK = 256 * _MB
_UINT_MAX = 0xFFFFFFFF

# (level, memLevel, strategy, wbits) settings the fingerprint runs: stored
# (level 0), deflate_fast (1-3), deflate_slow (4-9), filtered, Huffman-only
# and RLE strategies, small and large memLevel (block size) and window sizes.
FINGERPRINT_SETTINGS: tuple[tuple[int, int, int, int], ...] = (
    (0, 8, 0, 15),
    (0, 1, 0, 9),
    (0, 5, 0, 11),
    (1, 8, 0, 15),
    (2, 1, 0, 9),
    (3, 9, 0, 15),
    (4, 8, 0, 15),
    (5, 3, 1, 12),
    (6, 8, 0, 15),
    (6, 8, 1, 15),
    (7, 9, 0, 14),
    (8, 8, 0, 15),
    (9, 9, 0, 15),
    (9, 2, 1, 10),
    (6, 8, 2, 15),
    (6, 8, 3, 15),
    (1, 1, 3, 9),
)
# sha256 over every FINGERPRINT_SETTINGS stream of fingerprint_sample(), each
# preceded by its length (4 bytes, little-endian), as classic zlib writes them
# (1.2.12, 1.2.13, 1.3, 1.3.1, 1.3.2 and 1.4 all give this; 1.2.11's stored
# blocks differ at level 0 with memLevel 3 or more, which (0, 5, 0, 11) catches;
# Relay task 1578).
GOLDEN_SHA256 = "03533435e4be5c9f3a342ba5a925404809ecbc1a3cd33c8756c5c015623d21d6"


class ClassicZlibMissing(RuntimeError):
    """No classic zlib deflate here; the message says why."""


class Compressor(Protocol):
    def compress(self, data: bytes, /) -> bytes: ...

    def flush(self, mode: int = ..., /) -> bytes: ...


class Classic:
    """One classic deflate: `compressobj()` takes zlib.compressobj's arguments."""

    def __init__(self, name: str, factory: Callable[..., Compressor]) -> None:
        self.name = name
        self._factory = factory

    def compressobj(
        self,
        level: int = -1,
        method: int = Z_DEFLATED,
        wbits: int = 15,
        memLevel: int = 8,  # noqa: N803 — zlib.compressobj's own name
        strategy: int = 0,
    ) -> Compressor:
        return self._factory(level, method, wbits, memLevel, strategy)

    def deflate(
        self, data: bytes, level: int, mem: int, strategy: int, wbits: int
    ) -> bytes:
        """`data` as one finished zlib stream, the way forge_media's recipes run it."""
        co = self.compressobj(level, Z_DEFLATED, wbits, mem, strategy)
        return co.compress(data) + co.flush()


# ----------------------------- ctypes zlib -----------------------------


class ZStream(ctypes.Structure):
    """zlib's z_stream (uLong is c_ulong: 4 bytes on Windows, 8 on Linux/macOS)."""

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


def bind(lib: Any) -> str:
    """Declare the zlib calls used here on a loaded library; its zlibVersion()."""
    zp = ctypes.POINTER(ZStream)
    lib.zlibVersion.restype = ctypes.c_char_p
    lib.zlibVersion.argtypes = []
    lib.deflateInit2_.restype = ctypes.c_int
    lib.deflateInit2_.argtypes = [
        zp,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    lib.deflate.restype = ctypes.c_int
    lib.deflate.argtypes = [zp, ctypes.c_int]
    lib.deflateEnd.restype = ctypes.c_int
    lib.deflateEnd.argtypes = [zp]
    return (lib.zlibVersion() or b"").decode("ascii", "replace")


class CtypesCompress:
    """zlib.compressobj over a ctypes-loaded zlib, giving output room as CPython does."""

    def __init__(
        self, lib: Any, level: int, method: int, wbits: int, mem: int, strategy: int
    ) -> None:
        self._lib = lib
        self._z = ZStream()
        self._open = False
        rc = lib.deflateInit2_(
            ctypes.byref(self._z),
            level,
            method,
            wbits,
            mem,
            strategy,
            lib.zlibVersion(),
            ctypes.sizeof(ZStream),
        )
        if rc != Z_OK:
            raise zlib.error(f"Error {rc} while creating compression object")
        self._open = True

    def _run(self, data: bytes, mode: int) -> bytes:
        if not self._open:
            raise zlib.error("compression object already finished")
        z = self._z
        keep = data  # bytes stay alive (and unmoved) while zlib reads them
        base = ctypes.cast(ctypes.c_char_p(keep), ctypes.c_void_p).value or 0
        left = len(keep)
        offset = 0
        blocks: list[Any] = []
        sizes = iter(OUTPUT_BLOCKS)

        def grow() -> None:
            size = next(sizes, OUTPUT_MAX_BLOCK)
            buf = ctypes.create_string_buffer(size)
            blocks.append(buf)
            z.next_out = ctypes.addressof(buf)
            z.avail_out = size

        grow()
        rc = Z_OK
        while True:
            take = min(left, _UINT_MAX)
            z.next_in = base + offset if take else None
            z.avail_in = take
            offset += take
            left -= take
            while True:
                if z.avail_out == 0:
                    grow()
                rc = self._lib.deflate(ctypes.byref(z), mode)
                if rc == Z_STREAM_ERROR:
                    raise zlib.error(f"Error {rc} while compressing data")
                if z.avail_out != 0:
                    break
            if left == 0:
                break
        if mode == Z_FINISH:
            if rc != Z_STREAM_END:
                raise zlib.error(f"Error {rc} while flushing")
            self._end()
        elif rc not in (Z_OK, Z_BUF_ERROR):
            raise zlib.error(f"Error {rc} while compressing data")
        used = len(blocks[-1]) - z.avail_out
        return b"".join(b.raw for b in blocks[:-1]) + blocks[-1].raw[:used]

    def compress(self, data: bytes, /) -> bytes:
        return self._run(bytes(data), Z_NO_FLUSH)

    def flush(self, mode: int = Z_FINISH, /) -> bytes:
        if mode != Z_FINISH:
            raise ValueError("only Z_FINISH flushes are supported here")
        return self._run(b"", Z_FINISH)

    def _end(self) -> None:
        if self._open:
            self._open = False
            self._lib.deflateEnd(ctypes.byref(self._z))

    def __del__(self) -> None:
        try:
            self._end()
        except Exception:  # noqa: BLE001 — interpreter shutdown
            pass


# ----------------------------- fingerprint -----------------------------


def fingerprint_sample() -> bytes:
    """About 60 KB that walk every deflate path: PNG-like rows, words, runs, noise."""
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


def fingerprint(factory: Callable[..., Compressor]) -> str:
    """The sha256 `factory` (zlib.compressobj-like) gives over FINGERPRINT_SETTINGS."""
    data = fingerprint_sample()
    h = hashlib.sha256()
    for level, mem, strategy, wbits in FINGERPRINT_SETTINGS:
        co = factory(level, Z_DEFLATED, wbits, mem, strategy)
        stream = co.compress(data) + co.flush()
        h.update(len(stream).to_bytes(4, "little"))
        h.update(stream)
    return h.hexdigest()


def python_zlib_is_classic() -> bool:
    """True when this Python's own zlib is classic zlib (plain version, golden streams)."""
    if getattr(zlib, "ZLIBNG_VERSION", None):
        return False
    if not re.fullmatch(r"\d+(\.\d+){1,3}", zlib.ZLIB_RUNTIME_VERSION):
        return False
    try:
        return fingerprint(zlib.compressobj) == GOLDEN_SHA256
    except (ValueError, zlib.error):
        return False


def load_library(path: str) -> Classic:
    """A Classic over the zlib library at `path`; ValueError when it is not classic."""
    try:
        lib = ctypes.CDLL(path)
        version = bind(lib)
    except (OSError, AttributeError) as exc:
        raise ValueError(f"{path} is not a zlib library ({exc})") from None

    def factory(
        level: int, method: int, wbits: int, mem: int, strategy: int
    ) -> CtypesCompress:
        return CtypesCompress(lib, level, method, wbits, mem, strategy)

    try:
        got = fingerprint(factory)
    except (ValueError, zlib.error) as exc:
        raise ValueError(f"{path} (zlib {version}) failed to deflate: {exc}") from None
    if got != GOLDEN_SHA256:
        raise ValueError(
            f"{path} (zlib {version}) does not write classic zlib's deflate bytes"
        )
    return Classic(f"zlib {version} ({Path(path).name})", factory)


# ----------------------------- finding one -----------------------------

_lock = threading.Lock()
_found: Classic | None = None
_python_checked = False
_why = ""
_rejected: dict[str, str] = {}  # library path -> why it is not classic


def _forge_tools() -> Any:
    try:
        import forge_tools  # noqa: PLC0415

        return forge_tools
    except Exception:  # noqa: BLE001 — optional when run without Forge's shared folder
        return None


def python_zlib_words() -> str:
    """This Python's zlib, in a few words, for messages."""
    ver = zlib.ZLIB_RUNTIME_VERSION
    ng = getattr(zlib, "ZLIBNG_VERSION", None)
    if ng or "ng" in ver.lower():
        return f"zlib-ng {ng}" if ng else f"zlib-ng ({ver})"
    return f"zlib {ver}"


def _system_library() -> str | None:
    if os.name == "nt":
        return None
    return ctypes.util.find_library("z")


def _load_once(path: str) -> Classic:
    """load_library(path), remembering a library that is not classic."""
    if path in _rejected:
        raise ValueError(_rejected[path])
    try:
        return load_library(path)
    except ValueError as exc:
        _rejected[path] = str(exc)
        raise


def classic(auto_fetch: bool = False) -> Classic:
    """A classic zlib deflate, or ClassicZlibMissing naming why there is none.

    auto_fetch lets Forge fetch its pinned classic zlib (one small download,
    Windows) when nothing else here is classic. Found ones are kept for the
    process; a failed fetch is retried only after forge_tools' wait.
    """
    global _found, _python_checked, _why
    with _lock:
        if _found is not None:
            return _found
        if not _python_checked:
            _python_checked = True
            if python_zlib_is_classic():
                _found = Classic(
                    f"Python's zlib {zlib.ZLIB_RUNTIME_VERSION}", zlib.compressobj
                )
                return _found
        reasons: list[str] = []
        env_path = os.environ.get(ENV_VAR)
        if env_path:
            try:
                _found = _load_once(env_path)
                return _found
            except ValueError as exc:
                reasons.append(f"{ENV_VAR}: {exc}")
        ft = _forge_tools()
        if ft is not None:
            path = ft.find(TOOL)
            if path is None and auto_fetch and ft.can_fetch(TOOL):
                try:
                    path = ft.ensure(TOOL)
                except Exception as exc:  # noqa: BLE001 — offline, disk full, ...
                    reasons.append(f"could not fetch Forge's classic zlib: {exc}")
            if path:
                try:
                    _found = _load_once(path)
                    return _found
                except ValueError as exc:
                    reasons.append(str(exc))
            elif not ft.can_fetch(TOOL):
                reasons.append(
                    "Forge has no classic zlib build to fetch for this system"
                )
            elif not auto_fetch and not reasons:
                reasons.append("Forge's classic zlib is not fetched yet")
        system = _system_library()
        if system:
            try:
                _found = _load_once(system)
                return _found
            except ValueError as exc:
                reasons.append(f"system {exc}")
        _why = (
            f"this Python's zlib is {python_zlib_words()}, which writes different "
            "deflate bytes than classic zlib"
            + (f", and {'; '.join(reasons)}" if reasons else "")
        )
        raise ClassicZlibMissing(_why)


def try_classic(auto_fetch: bool = False) -> Classic | None:
    """classic(), or None when there is none."""
    try:
        return classic(auto_fetch=auto_fetch)
    except ClassicZlibMissing:
        return None


def status() -> dict[str, Any]:
    """For a status page: is a classic deflate ready (never fetches)."""
    found = try_classic(auto_fetch=False)
    ft = _forge_tools()
    can_fetch = bool(ft is not None and ft.can_fetch(TOOL))
    return {
        "ready": found is not None,
        "source": found.name if found else None,
        "python_zlib": python_zlib_words(),
        "can_fetch": can_fetch,
        "why": "" if found else _why,
    }


def forget() -> None:
    """Drop what was found, so the next classic() looks again (tests, after a fetch)."""
    global _found, _python_checked, _why
    with _lock:
        _found = None
        _python_checked = False
        _why = ""
        _rejected.clear()


if __name__ == "__main__":
    if sys.argv[1:] == ["fingerprint"]:
        print(fingerprint(zlib.compressobj), zlib.ZLIB_RUNTIME_VERSION)
    else:
        print(status())
