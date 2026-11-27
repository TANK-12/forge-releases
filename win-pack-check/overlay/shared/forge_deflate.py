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
DEFLATE_SETTINGS = tuple(s for s in FINGERPRINT_SETTINGS if s[0] > 0)
STORED_SETTINGS = tuple(s for s in FINGERPRINT_SETTINGS if s[0] == 0)
# sha256 over the DEFLATE_SETTINGS (levels 1-9) and the STORED_SETTINGS
# (level 0) streams of fingerprint_sample(), each stream preceded by its length
# (4 bytes, little-endian), as classic zlib writes them: 1.2.12, 1.2.13, 1.3,
# 1.3.1, 1.3.2 and 1.4 all give both. 1.2.11 gives the first only: its stored
# blocks differ at level 0 with memLevel 3 or more, which (0, 5, 0, 11)
# catches, so there level-0 recipes are off and every other level works.
# zlib-ng gives the second only, which is no use (Relay task 1578).
GOLDEN_SHA256 = "e125b66bbad097f6c1625ad5ab69298c4e992a39621bf68b3ed6b4b9ac71674a"
GOLDEN_STORED_SHA256 = (
    "dbbd5bcc756422a45a1527256eb060212a1f43d4a97eec2a3f07eace719182c5"  # noqa: E501
)


class ClassicZlibMissing(RuntimeError):
    """No classic zlib deflate here; the message says why."""


class Compressor(Protocol):
    def compress(self, data: bytes, /) -> bytes: ...

    def flush(self, mode: int = ..., /) -> bytes: ...


class Classic:
    """One classic deflate: `compressobj()` takes zlib.compressobj's arguments.

    `stored` is False for a zlib whose level-0 (stored) blocks differ from
    1.2.12 and newer (1.2.11): it serves recipes of levels 1-9 only.
    """

    def __init__(
        self, name: str, factory: Callable[..., Compressor], stored: bool = True
    ) -> None:
        self.name = name
        self._factory = factory
        self.stored = stored

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


def fingerprint(
    factory: Callable[..., Compressor],
    settings: tuple[tuple[int, int, int, int], ...] = DEFLATE_SETTINGS,
) -> str:
    """The sha256 `factory` (zlib.compressobj-like) gives over `settings`."""
    data = fingerprint_sample()
    h = hashlib.sha256()
    for level, mem, strategy, wbits in settings:
        co = factory(level, Z_DEFLATED, wbits, mem, strategy)
        stream = co.compress(data) + co.flush()
        h.update(len(stream).to_bytes(4, "little"))
        h.update(stream)
    return h.hexdigest()


def judge(name: str, factory: Callable[..., Compressor]) -> Classic | None:
    """A Classic over `factory` when it writes classic zlib's bytes for levels
    1-9 (`stored` says whether level 0 matches too), else None."""
    try:
        if fingerprint(factory, DEFLATE_SETTINGS) != GOLDEN_SHA256:
            return None
        stored = fingerprint(factory, STORED_SETTINGS) == GOLDEN_STORED_SHA256
    except (ValueError, zlib.error):
        return None
    if not stored:
        name += ", whose level-0 stored blocks differ (level-0 recipes off)"
    return Classic(name, factory, stored)


def _python_plain_version() -> bool:
    return not getattr(zlib, "ZLIBNG_VERSION", None) and bool(
        re.fullmatch(r"\d+(\.\d+){1,3}", zlib.ZLIB_RUNTIME_VERSION)
    )


def python_classic() -> Classic | None:
    """This Python's own zlib as a Classic when it is classic (fully or for levels 1-9)."""
    if not _python_plain_version():
        return None
    return judge(f"Python's zlib {zlib.ZLIB_RUNTIME_VERSION}", zlib.compressobj)


def python_zlib_is_classic() -> bool:
    """True when this Python's own zlib is classic zlib at every level."""
    got = python_classic()
    return bool(got and got.stored)


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

    got = judge(f"zlib {version} ({Path(path).name})", factory)
    if got is None:
        raise ValueError(
            f"{path} (zlib {version}) does not write classic zlib's deflate bytes"
        )
    return got


# ----------------------------- finding one -----------------------------

_lock = threading.Lock()
_found: Classic | None = None
_UNCHECKED = Classic("unchecked", zlib.compressobj)
_python: Classic | None = _UNCHECKED
_why = ""
_rejected: dict[str, str] = {}  # library path -> why it is not classic


def _forge_tools() -> Any:
    try:
        import forge_tools  # noqa: PLC0415

        return forge_tools
    except Exception:  # noqa: BLE001 — optional when run without Forge's shared folder
        return None


def can_fetch() -> bool:
    """True when Forge has a classic zlib build to fetch for this system."""
    ft = _forge_tools()
    return bool(ft is not None and ft.can_fetch(TOOL))


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
        got = load_library(path)
    except ValueError as exc:
        _rejected[path] = str(exc)
        raise
    return got


def _search(
    reasons: list[str], fetch_error: str = "", fetched_path: str = ""
) -> Classic | None:
    """The best classic deflate here without fetching (call with _lock held):
    a full one first, else one for levels 1-9 only, else None (reasons say why)."""
    global _python
    if _python is _UNCHECKED:
        _python = python_classic()
    best = _python
    if best is not None and best.stored:
        return best
    paths: list[tuple[str, str]] = []
    env_path = os.environ.get(ENV_VAR)
    if env_path:
        paths.append((f"{ENV_VAR}: ", env_path))
    ft = _forge_tools()
    if ft is not None:
        fetched = ft.find(TOOL) or fetched_path
        if fetched:
            paths.append(("", fetched))
        elif fetch_error:
            reasons.append(f"could not fetch Forge's classic zlib: {fetch_error}")
        elif not ft.can_fetch(TOOL):
            reasons.append("Forge has no classic zlib build to fetch for this system")
        else:
            reasons.append("Forge's classic zlib is not fetched yet")
    system = _system_library()
    if system:
        paths.append(("system ", system))
    for label, path in paths:
        try:
            got = _load_once(path)
        except ValueError as exc:
            reasons.append(f"{label}{exc}")
            continue
        if got.stored:
            return got
        best = best or got
    return best


def classic(auto_fetch: bool = False) -> Classic:
    """A classic zlib deflate, or ClassicZlibMissing naming why there is none.

    auto_fetch lets Forge fetch its pinned classic zlib (one small download,
    Windows) when nothing here is classic; the download runs outside this
    module's lock, so status() never waits for it. What is found is kept for
    the process; a failed fetch is retried only after forge_tools' wait.
    """
    global _found, _why
    with _lock:
        if _found is not None:
            return _found
        got = _search([])
        if got is not None:
            _found = got
            return got
    fetch_error = fetched_path = ""
    ft = _forge_tools()
    if auto_fetch and ft is not None and ft.can_fetch(TOOL) and not ft.find(TOOL):
        try:
            fetched_path = ft.ensure(TOOL)  # forge_tools: one process fetches at a time
        except Exception as exc:  # noqa: BLE001 — offline, disk full, ...
            fetch_error = str(exc) or type(exc).__name__
    with _lock:
        if _found is not None:
            return _found
        reasons: list[str] = []
        got = _search(reasons, fetch_error, fetched_path)
        if got is not None:
            _found = got
            return got
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
    return {
        "ready": found is not None,
        "stored": bool(found and found.stored),
        "source": found.name if found else None,
        "python_zlib": python_zlib_words(),
        "can_fetch": can_fetch(),
        "why": "" if found else _why,
    }


def forget() -> None:
    """Drop what was found, so the next classic() looks again (tests, after a fetch)."""
    global _found, _python, _why
    with _lock:
        _found = None
        _python = _UNCHECKED
        _why = ""
        _rejected.clear()


if __name__ == "__main__":
    if sys.argv[1:] == ["fingerprint"]:
        print(
            fingerprint(zlib.compressobj, DEFLATE_SETTINGS),
            fingerprint(zlib.compressobj, STORED_SETTINGS),
            zlib.ZLIB_RUNTIME_VERSION,
        )
    else:
        print(status())
