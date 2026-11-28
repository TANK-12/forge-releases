"""Core helpers for Forge Pack (wraps shared/forge_vault.py)."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DEMO_PHOTOS_DIR = ROOT / "demo_photos"
SHARED_DIR = Path(os.environ.get("FORGE_SHARED_DIR") or ROOT.parent.parent / "shared")
if str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))

import forge_media  # noqa: E402
import forge_tensor_pack  # noqa: E402
import forge_vault as fv  # noqa: E402

DATA_DIR = Path(
    os.environ.get("PACK_DATA_DIR")
    or Path.home() / ".local" / "share" / "forge" / "pack"
)
OUT_DIR = Path(os.environ.get("PACK_OUT_DIR") or Path.home() / "Downloads" / "Packed")
UNPACK_DIR = Path(
    os.environ.get("PACK_UNPACK_DIR") or Path.home() / "Downloads" / "Unpacked"
)
RECENT_FILE = DATA_DIR / "recent.json"
SPOOL_DIR = DATA_DIR / "spool"
OPEN_SPOOL_DIR = DATA_DIR / "opened"
MOUNT_REGISTRY_CANDIDATES = (
    (
        Path(os.environ["FORGE_PACK_MOUNTS"])
        if os.environ.get("FORGE_PACK_MOUNTS")
        else None
    ),
    Path.home() / ".config" / "forge" / "pack-mounts.json",
    SHARED_DIR / "vault" / "mounts.json",
)

PROFILE_CARDS: list[dict[str, Any]] = [
    {
        "id": "fast",
        "label": "Fast (recommended)",
        "badge": "Kraken-Huff4 + Plane-AVX2",
        "summary": "Beats zstd -3 on code, logs and JSON while unpacking at 500 to 2,000 MB/s.",
        "decode_hint": "613 MB/s code · 833 MB/s BF16 weights · 1,974 MB/s logs",
    },
    {
        "id": "max",
        "label": "Max compression",
        "badge": "Zstd -19 long + Plane-AVX2",
        "summary": "Smallest Forge Pack output using Zstd -19 long plus AVX2 byte-plane splitting for model weights.",
        "decode_hint": "Smaller packs, slower packing; 745 MB/s on BF16 weights",
    },
    {
        "id": "ultra_fast",
        "label": "Ultra-fast",
        "badge": "Selkie-SIMD + Plane-AVX2",
        "summary": "Minimum CPU and maximum unpack speed (0.8 to 7.4 GB/s) for frequent access.",
        "decode_hint": "833 MB/s code · 3,111 MB/s logs · 7,378 MB/s FP32",
    },
    {
        "id": "balanced",
        "label": "Balanced",
        "badge": "Kraken-Huff4 + Zstd -3",
        "summary": "Pairs Kraken-Huff4 on code/JSON with Zstd -3 on logs and markdown docs.",
        "decode_hint": "Fast write + strong ratio + cross-file dedup",
    },
]

HONEST_LIMITS: list[dict[str, str]] = [
    {
        "title": "Slow archival packers still win ~8% on single non-duplicate folders",
        "detail": (
            "On a 33.3 MB mixed folder with zero duplicate files, solid 7-Zip (-mx=9) and "
            "xz -9 pack to 15.6 MB vs 16.9 MB for Pack Max (~8% smaller), because they merge "
            "small files into a huge slow LZMA2 stream. Pack trades that last ~8% for 15x to 100x "
            "faster unpacking, 3x to 5x less RAM, and cross-file deduplication."
        ),
    },
    {
        "title": "Photos, videos, and already-zipped files need the opt-in media stage to shrink",
        "detail": (
            "General lossless packers barely shrink PNG, JPG, WebP, MP4, MKV, or ZIP files "
            "(0% to 2.6%), so Auto-pick defaults to raw bypass (>4.6 GB/s) or exclusion. "
            "Turn on the opt-in v1.1 Bit-exact media stage for measured byte-exact wins: "
            "15.0% on JPEGs (lossless JPEG XL), 28.7% on classic-zlib PNGs (re-deflate recipe + "
            "JXL, plain fallback when a PNG misses), up to 49.4% on MP4 render-version pairs, "
            "and 1.67% on anime seasons with shared MKV fonts. Unpacking JXL stages needs djxl."
        ),
    },
    {
        "title": "Model weights: speed vs absolute smallest size",
        "detail": (
            "Plane-AVX2 beats zstd -19 --long on BF16 weights (1.50x at 833 MB/s vs 1.47x at "
            "143 MB/s, 5.8x faster decode), while xz -9 reaches 1.72x at 4.3 MB/s (~193x slower)."
        ),
    },
    {
        "title": "Why 8 EiB -> 250 KiB only happens for smooth formulas (where Tensor-Train really helps)",
        "detail": (
            "Rease's 8 EiB -> 251.63 KiB experiment sampled a smooth 6D physics formula on demand "
            "across a virtual 2^60 grid that never existed on disk. Real photos, videos, games, "
            "and documents have high entropy and do not shrink that way. Pack's opt-in Tensor-Train "
            "stage targets real stored numeric files (.npy, .npz, .wav, .pgm/.ppm): physics & PDE "
            "fields, lookup tables, smooth signals and renders, picking TT only when it beats "
            "Pack's existing codecs — bit-exact in lossless mode, or error-bounded in opt-in lossy mode."
        ),
    },
    {
        "title": "Pre-release format notice",
        "detail": (
            "The .fpack / .fvlt v1 container uses proven crypto (Argon2id + AES-256-GCM / "
            "XChaCha20-Poly1305 + BLAKE3), but keep backups of critical data until the format is "
            "frozen and fuzzed for public distribution."
        ),
    },
]

MEASURED_BENCHMARKS: list[dict[str, str]] = [
    {
        "workload": "Forge source code (8.0 MB)",
        "ours": "Kraken-Huff4 optimal: 3.84x @ 338-551 MB/s · Ultra: 592-913 MB/s",
        "baseline": "ZIP Deflate -6: 3.60x @ 181 MB/s (Win Explorer ~86 MB/s) · 7z -mx=9: 4.83x @ 19 MB/s",
    },
    {
        "workload": "Markdown docs (6.0 MB)",
        "ours": "Kraken-Huff4 optimal: 4.26x @ 474-555 MB/s · Ultra: 679-992 MB/s",
        "baseline": "ZIP Deflate -6: 3.90x @ 197 MB/s · zstd -3: 4.82x @ 544 MB/s",
    },
    {
        "workload": "Real PDFs (5.3 MB, books + reports)",
        "ours": "Kraken-Huff4: 1.47x (32.2% saved) @ 601 MB/s · Ultra: 1,232 MB/s",
        "baseline": "ZIP Deflate -6: 1.49x (32.8% saved) @ 188 MB/s (3.2x-6.5x slower)",
    },
    {
        "workload": "BF16 AI weights (8.0 MB)",
        "ours": "Plane-AVX2: 1.50x (33.3% saved) @ 250-833 MB/s",
        "baseline": "ZIP Deflate -6: 1.40x @ 89 MB/s · zstd -19 --long: 1.47x @ 143 MB/s",
    },
    {
        "workload": "Photos & renders (opt-in v1.1 media stage)",
        "ours": "Bit-exact: 15.0% JPG (JXL), 28.7% PNG hits (recipe+JXL), 49.4% AMV v1/v2, 1.7% MKV fonts",
        "baseline": "zstd -19 / xz -9: 0.02-0.41% on JPG/PNG/MP4; JXL decode needs djxl (libjxl BSD)",
    },
    {
        "workload": "EPUB / DOCX / PNG / MP4 (default bypass)",
        "ours": "Auto-pick raw bypass: 0-2% shrink @ 1,768-3,361 MB/s",
        "baseline": "Already compressed internally (ZIP/H.264/PNG) — skipping saves CPU",
    },
    {
        "workload": "Structured numeric arrays (opt-in Tensor-Train stage)",
        "ours": "Bit-exact: 11.2x 2D LUT, 23.8x 16-bit depth, 1.91x 2D PDE · Lossy (≤1e-3): 146x–388x (NOAA CO2 8.2x)",
        "baseline": "zstd -19: 1.06x–1.21x on 2D PDE/LUT/depth (2.77x CO2) · Photos/video/noise: 0% (auto-fallback)",
    },
    {
        "workload": "2-day mixed backup (66.7 MB)",
        "ours": "Encrypted Fast: 17.5 MB (3.81x, 133 MB RAM)",
        "baseline": "tar+zstd -3: 34.2 MB · 7z -mx=9: 15.6 MB (650 MB RAM, 21x slower write)",
    },
]


class PackAppError(Exception):
    """Plain user-facing error from Pack operations."""


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    UNPACK_DIR.mkdir(parents=True, exist_ok=True)


def clean_spools() -> None:
    for d in (SPOOL_DIR, OPEN_SPOOL_DIR):
        if d.is_dir():
            shutil.rmtree(d, ignore_errors=True)


def safe_filename(name: str, encrypted: bool = False) -> str:
    """Clean a user-supplied output filename and ensure a .fpack or .fvlt suffix."""
    cleaned = re.sub(r"[^A-Za-z0-9._ -]+", "_", name.strip()).strip(" .")
    if not cleaned:
        cleaned = "archive"
    low = cleaned.lower()
    if low.endswith(".fpack") or low.endswith(".fvlt"):
        return cleaned
    return (
        f"{cleaned}.fvlt" if encrypted and low.endswith("vault") else f"{cleaned}.fpack"
    )


def unique_out_path(folder: Path, filename: str, overwrite: bool = False) -> Path:
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise PackAppError(f"cannot create output folder {folder}: {exc}") from exc
    if not folder.is_dir():
        raise PackAppError(f"output folder is not a directory: {folder}")
    candidate = folder / filename
    if overwrite or not candidate.exists():
        return candidate
    stem = candidate.stem
    suffix = candidate.suffix
    for idx in range(2, 1000):
        alt = folder / f"{stem}-{idx}{suffix}"
        if not alt.exists():
            return alt
    raise PackAppError(f"too many files named {filename} in {folder}")


def unique_unpack_dir(base_dir: Path, pack_path: Path) -> Path:
    stem = re.sub(r"[^A-Za-z0-9._ -]+", "_", pack_path.stem).strip(" .") or "unpacked"
    target = base_dir / stem
    if not target.exists() or (target.is_dir() and not any(target.iterdir())):
        return target
    for idx in range(2, 1000):
        alt = base_dir / f"{stem}-{idx}"
        if not alt.exists():
            return alt
    raise PackAppError(f"could not pick an empty unpack folder under {base_dir}")


def validate_local_path(raw: str, *, expect_file: bool = False) -> Path:
    if not raw or not raw.strip():
        raise PackAppError("enter a file or folder path")
    try:
        p = Path(raw.strip()).expanduser()
    except RuntimeError as exc:
        raise PackAppError("that path could not be resolved") from exc
    if not p.is_absolute():
        raise PackAppError("path must be absolute")
    if not p.exists():
        raise PackAppError(f"path does not exist: {p}")
    if expect_file and not p.is_file():
        raise PackAppError(f"expected a file, not a folder: {p}")
    return p


def load_recent() -> list[dict[str, Any]]:
    if not RECENT_FILE.is_file():
        return []
    try:
        items = json.loads(RECENT_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict) or not item.get("path"):
            continue
        p = Path(str(item["path"]))
        row = dict(item)
        row["exists"] = p.is_file()
        if row["exists"]:
            try:
                row["vault_bytes"] = p.stat().st_size
            except OSError:
                pass
        out.append(row)
    return out[:30]


def record_recent(entry: dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    current = [r for r in load_recent() if r.get("path") != entry.get("path")]
    row = {
        **entry,
        "updated_at": dt.datetime.now().isoformat(timespec="seconds"),
    }
    row.pop("exists", None)
    updated = [row, *current][:30]
    tmp = RECENT_FILE.with_name(f".recent.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, RECENT_FILE)


def stats_to_dict(
    stats: fv.VaultStats, *, out_path: Path | None = None
) -> dict[str, Any]:
    saved_bytes = max(0, stats.raw_bytes - stats.vault_bytes)
    data: dict[str, Any] = {
        "files": stats.files,
        "raw_bytes": stats.raw_bytes,
        "vault_bytes": stats.vault_bytes,
        "saved_bytes": saved_bytes,
        "saved_pct": round(stats.saved_pct, 1),
        "ratio": round(stats.ratio, 2),
        "unique_chunks": stats.unique_chunks,
        "total_chunk_refs": stats.total_chunk_refs,
        "dedup_saved_bytes": stats.dedup_saved_bytes,
        "dict_bytes": stats.dict_bytes,
        "elapsed_sec": round(stats.elapsed_sec, 3),
        "throughput_mbs": round(stats.throughput_mbs, 1),
        "codec_counts": stats.codec_counts,
        "cipher": stats.cipher,
        "profile": stats.profile,
        "encrypted": stats.encrypted,
        "bypassed_files": stats.bypassed_files,
        "bypassed_bytes": stats.bypassed_bytes,
        "skipped_files": stats.skipped_files,
        "skipped_bytes": stats.skipped_bytes,
        "media_stage": stats.media_stage,
        "media_files": stats.media_files,
        "media_saved_bytes": stats.media_saved_bytes,
        "media_stage_counts": stats.media_stage_counts,
        "tensor_stage": stats.tensor_stage,
        "tensor_files": stats.tensor_files,
        "tensor_lossy_files": stats.tensor_lossy_files,
        "tensor_saved_bytes": stats.tensor_saved_bytes,
        "tensor_stage_counts": stats.tensor_stage_counts,
    }
    if out_path is not None:
        data["path"] = str(out_path)
        data["name"] = out_path.name
    return data


def mount_slot_status() -> dict[str, Any]:
    """Check whether task 1553's transparent on-disk mount backend has registered."""
    for path in MOUNT_REGISTRY_CANDIDATES:
        if path is None or not path.is_file():
            continue
        try:
            cfg = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(cfg, dict):
            mounts = cfg.get("mounts") if isinstance(cfg.get("mounts"), list) else []
            return {
                "available": True,
                "registry_path": str(path),
                "backend": str(cfg.get("backend") or "transparent-mount"),
                "version": str(cfg.get("version") or "0.1"),
                "mounts": mounts,
                "note": str(
                    cfg.get("note")
                    or "Transparent squeeze-on-disk mount backend detected."
                ),
            }
    squeezefs_py = SHARED_DIR / "forge_squeezefs.py"
    squeezefs_bin = SHARED_DIR / "vault" / "squeezefs_mount"
    if squeezefs_py.is_file() or squeezefs_bin.is_file():
        return {
            "available": True,
            "registry_path": str(
                Path.home() / ".config" / "forge" / "pack-mounts.json"
            ),
            "backend": "Forge SqueezeFS (FUSE3)",
            "version": "0.1",
            "mounts": [],
            "note": (
                "Forge SqueezeFS transparent FUSE3 backend is present "
                "(shared/forge_squeezefs.py). Add mount entries to pack-mounts.json "
                "to manage mounted folders here."
            ),
            "good_candidates": [
                "App folders, source trees, and game assets (compressible text/data)",
                "BF16 / FP32 AI model weights (Plane-AVX2 unpacks at 833+ MB/s)",
                "Old logs, JSON datasets, and uncompressed renders",
            ],
            "skip_candidates": [
                "Photos (JPG, PNG, WebP) and videos (MP4, MKV) — already compressed",
                "Existing ZIP, 7z, and GZ archives",
            ],
        }
    return {
        "available": False,
        "registry_path": str(Path.home() / ".config" / "forge" / "pack-mounts.json"),
        "backend": None,
        "mounts": [],
        "note": (
            "Reserved slot for transparent squeeze-on-disk mounts "
            "(pack on disk, unpack on read). Drop a mounts.json or pack-mounts.json "
            "descriptor once a transparent mount backend is enabled to light up controls here."
        ),
        "good_candidates": [
            "App folders, source trees, and game assets (compressible text/data)",
            "BF16 / FP32 AI model weights (Plane-AVX2 unpacks at 833+ MB/s)",
            "Old logs, JSON datasets, and uncompressed renders",
        ],
        "skip_candidates": [
            "Photos (JPG, PNG, WebP) and videos (MP4, MKV) — already compressed",
            "Existing ZIP, 7z, and GZ archives",
        ],
    }


def handler_status() -> dict[str, Any]:
    """Report Linux/Windows file-manager association status for .fpack and .fvlt."""
    if sys.platform.startswith("linux"):
        data_home = Path(
            os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
        )
        source_desktop = data_home / "applications" / "forge-open-pack.desktop"
        source_mime = data_home / "mime" / "packages" / "forge-types.xml"
        rel_desktop = data_home / "applications" / "local.forge.open-pack.desktop"
        rel_mime = data_home / "mime" / "packages" / "forge-release-types.xml"
        source_ready = source_desktop.is_file() and source_mime.is_file()
        rel_ready = rel_desktop.is_file() and rel_mime.is_file()
        desktop = source_desktop if source_ready else rel_desktop
        mime_xml = source_mime if source_ready else rel_mime
        default_pack = ""
        if shutil.which("gio"):
            try:
                res = subprocess.run(
                    ["gio", "mime", "application/x-forge-pack"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if res.returncode == 0 and res.stdout:
                    default_pack = res.stdout.splitlines()[0].strip()
            except (OSError, subprocess.SubprocessError):
                pass
        ready = source_ready or rel_ready
        return {
            "platform": "linux",
            "extensions": [".fpack", ".fvlt"],
            "registered": ready,
            "desktop_file": str(desktop),
            "mime_file": str(mime_xml),
            "default_handler": default_pack,
            "how": (
                "Double-clicking a .fpack or .fvlt file opens Forge Pack directly "
                "via forge.py --open-file pack %f (or forge --open-file in releases)."
            ),
        }
    if os.name == "nt":
        registered = False
        handler_cmd = ""
        try:
            import winreg  # type: ignore[import-not-found]

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Classes\Forge.Pack\shell\open\command",
            ) as key:
                handler_cmd = str(winreg.QueryValueEx(key, "")[0])
                registered = bool(handler_cmd)
        except OSError:
            registered = False
        return {
            "platform": "windows",
            "extensions": [".fpack", ".fvlt"],
            "registered": registered,
            "default_handler": handler_cmd,
            "how": (
                "The Forge Windows installer (Inno Setup) registers .fpack and .fvlt "
                "under HKCU\\Software\\Classes (no admin needed) to launch Forge Pack."
            ),
        }
    return {
        "platform": sys.platform,
        "extensions": [".fpack", ".fvlt"],
        "registered": False,
        "default_handler": "",
        "how": "File-manager registration is wired for Linux and Windows builds.",
    }


def register_handler() -> dict[str, Any]:
    """Install/refresh .fpack and .fvlt file-manager associations for this user."""
    if sys.platform.startswith("linux"):
        import importlib

        forge_root = ROOT.parent.parent
        data_home = Path(
            os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
        )
        try:
            mod = importlib.import_module("forge_open")
            mod.sync_launchers()
            return handler_status()
        except ImportError:
            pass
        if str(forge_root) not in sys.path:
            sys.path.insert(0, str(forge_root))
        try:
            inst = importlib.import_module("forge_installer")
            inst.sync_custom_file_handlers(forge_root, data_home)
            return handler_status()
        except ImportError as exc:
            raise PackAppError(
                "file-handler sync helper is not available in this build"
            ) from exc
    if os.name == "nt":
        import ctypes
        import winreg  # type: ignore[import-not-found]

        forge_root = ROOT.parent.parent
        portable = forge_root / "forge_portable.py"
        py = sys.executable
        if py.lower().endswith("python.exe"):
            pyw = Path(py).with_name("pythonw.exe")
            if pyw.is_file():
                py = str(pyw)
        cmd = f'"{py}" -B "{portable}" --open-file pack "%1"'
        icon = forge_root / "forge.ico"
        if not icon.is_file():
            icon = forge_root / "release" / "launch" / "forge.ico"
        for ext, prog_id, label, mime in (
            (".fpack", "Forge.Pack", "Forge Pack Archive", "application/x-forge-pack"),
            (
                ".fvlt",
                "Forge.Vault",
                "Forge Encrypted Vault",
                "application/x-forge-vault",
            ),
        ):
            with winreg.CreateKey(
                winreg.HKEY_CURRENT_USER, f"Software\\Classes\\{ext}"
            ) as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, prog_id)
                winreg.SetValueEx(k, "Content Type", 0, winreg.REG_SZ, mime)
            with winreg.CreateKey(
                winreg.HKEY_CURRENT_USER, f"Software\\Classes\\{prog_id}"
            ) as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, label)
            if icon.is_file():
                with winreg.CreateKey(
                    winreg.HKEY_CURRENT_USER,
                    f"Software\\Classes\\{prog_id}\\DefaultIcon",
                ) as k:
                    winreg.SetValueEx(k, "", 0, winreg.REG_SZ, f"{icon},0")
            with winreg.CreateKey(
                winreg.HKEY_CURRENT_USER,
                f"Software\\Classes\\{prog_id}\\shell\\open\\command",
            ) as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, cmd)
        try:
            shell32 = getattr(ctypes, "WinDLL")("shell32")  # noqa: B009
            shell32.SHChangeNotify(0x08000000, 0x0000, None, None)
        except Exception:  # noqa: BLE001 -- Explorer refresh is best-effort
            pass
        return handler_status()
    raise PackAppError(
        f"automatic file-handler registration is not supported on {sys.platform}"
    )


def showcase_info() -> dict[str, Any]:
    """Metadata about the bundled real-photo compression demo set."""
    photos = (
        sorted(p for p in DEMO_PHOTOS_DIR.iterdir() if p.is_file())
        if DEMO_PHOTOS_DIR.is_dir()
        else []
    )
    mt = forge_media.media_tools_status()
    return {
        "available": len(photos) > 0,
        "photo_count": len(photos),
        "raw_bytes": sum(p.stat().st_size for p in photos),
        "files": [p.name for p in photos],
        "jxl_ready": bool(mt.get("jpeg_ready") and mt.get("png_ready")),
        "can_fetch_jxl": bool(mt.get("can_fetch_jxl")),
        "jxl_hint": str(mt.get("jxl_hint") or "install libjxl (cjxl & djxl)"),
    }


def run_photo_showcase(progress_cb: Any = None) -> dict[str, Any]:
    """Pack the bundled real photo set on the spot, compare with ZIP, unpack, and verify SHA-256."""
    if not DEMO_PHOTOS_DIR.is_dir():
        raise PackAppError("bundled demo_photos folder is missing")
    photos = sorted(p for p in DEMO_PHOTOS_DIR.iterdir() if p.is_file())
    if not photos:
        raise PackAppError("no sample photos found in demo_photos")

    if progress_cb is not None:
        progress_cb(0.05, "Preparing JPEG XL lossless tools & sample photos...")
    # Auto-fetch static cjxl/djxl on platforms with a pinned build (Windows)
    cjxl_bin = forge_media.find_tool("cjxl", auto_fetch=True)
    djxl_bin = forge_media.find_tool("djxl", auto_fetch=True)
    jxl_active = bool(cjxl_bin and djxl_bin)

    orig_info: dict[str, tuple[int, str]] = {}
    for p in photos:
        data = p.read_bytes()
        orig_info[p.name] = (len(data), hashlib.sha256(data).hexdigest())
    raw_total = sum(sz for sz, _ in orig_info.values())

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_pack = unique_out_path(OUT_DIR, "photo-showcase-demo.fpack")

    with tempfile.TemporaryDirectory(prefix="pack-showcase-") as tmp_str:
        tmp = Path(tmp_str)
        if progress_cb is not None:
            progress_cb(0.15, "Measuring standard ZIP (Deflate -6) baseline...")
        zip_path = tmp / "baseline.zip"
        t_zip0 = time.perf_counter()
        with zipfile.ZipFile(
            zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as zf:
            for p in photos:
                zf.write(p, arcname=p.name)
        zip_ms = round((time.perf_counter() - t_zip0) * 1000.0, 1)
        zip_bytes = zip_path.stat().st_size
        zip_saved_pct = (
            round((1.0 - zip_bytes / raw_total) * 100.0, 1) if raw_total else 0.0
        )

        def _on_pack(done: int, total: int, rel: str) -> None:
            if progress_cb is not None:
                progress_cb(
                    0.2 + 0.5 * (done / max(total, 1)),
                    f"Packing photo {done}/{total} ({rel})...",
                )

        t_pack0 = time.perf_counter()
        stats = fv.pack_sources(
            [DEMO_PHOTOS_DIR],
            out_pack,
            None,
            profile="fast",
            media_stage=True,
            media_options={
                "jpeg": True,
                "png": True,
                "video_dedup": False,
                "mkv_fonts": False,
            },
            progress_cb=_on_pack,
        )
        pack_ms = round((time.perf_counter() - t_pack0) * 1000.0, 1)

        if progress_cb is not None:
            progress_cb(0.75, "Unpacking & verifying every byte via SHA-256...")
        meta = fv.inspect_vault(out_pack, None)
        unpack_tmp = tmp / "restored"
        t_unp0 = time.perf_counter()
        fv.unpack_vault(out_pack, unpack_tmp, None)
        unpack_ms = round((time.perf_counter() - t_unp0) * 1000.0, 1)

        meta_by_name = {fe["path"]: fe for fe in meta.get("files", [])}
        per_file: list[dict[str, Any]] = []
        all_exact = True
        for p in photos:
            orig_sz, orig_sha = orig_info[p.name]
            restored_file = unpack_tmp / p.name
            if not restored_file.is_file():
                raise PackAppError(f"showcase unpack missed {p.name}")
            restored_bytes = restored_file.read_bytes()
            restored_sha = hashlib.sha256(restored_bytes).hexdigest()
            exact = len(restored_bytes) == orig_sz and restored_sha == orig_sha
            all_exact = all_exact and exact
            fe = meta_by_name.get(p.name, {})
            media_dict = fe.get("media") if isinstance(fe.get("media"), dict) else None
            stored_sz = (
                int(media_dict["stored_size"])
                if media_dict and "stored_size" in media_dict
                else orig_sz
            )
            file_saved_pct = (
                round((1.0 - stored_sz / orig_sz) * 100.0, 1) if orig_sz else 0.0
            )
            per_file.append(
                {
                    "name": p.name,
                    "ext": p.suffix.lower().lstrip("."),
                    "stage": media_dict.get("stage") if media_dict else "raw_bypass",
                    "raw_bytes": orig_sz,
                    "stored_bytes": stored_sz,
                    "saved_pct": file_saved_pct,
                    "sha256": orig_sha,
                    "restored_sha256": restored_sha,
                    "bit_exact": exact,
                }
            )

    summary = stats_to_dict(stats, out_path=out_pack)
    record_recent(summary)
    mt = forge_media.media_tools_status()
    return {
        "pack_path": str(out_pack),
        "pack_name": out_pack.name,
        "photo_count": len(photos),
        "raw_bytes": raw_total,
        "zip_bytes": zip_bytes,
        "zip_saved_pct": zip_saved_pct,
        "zip_ms": zip_ms,
        "pack_bytes": stats.vault_bytes,
        "saved_bytes": max(0, raw_total - stats.vault_bytes),
        "saved_pct": round(stats.saved_pct, 1),
        "ratio": round(stats.ratio, 2),
        "pack_ms": pack_ms,
        "unpack_ms": unpack_ms,
        "all_bit_exact": all_exact,
        "jxl_used": jxl_active and stats.media_files > 0,
        "jxl_hint": str(mt.get("jxl_hint") or ""),
        # PNG recipes need classic zlib (Windows: a fetched zlib1.dll); why not
        "png_deflate_ready": bool((mt.get("png_deflate") or {}).get("ready")),
        "png_deflate_why": str((mt.get("png_deflate") or {}).get("why") or ""),
        "png_deflate_can_fetch": bool((mt.get("png_deflate") or {}).get("can_fetch")),
        "media_stage_counts": stats.media_stage_counts,
        "files": per_file,
    }


def run_tensor_showcase(progress_cb: Any = None) -> dict[str, Any]:
    """Run the live Tensor-Train structured-vs-noise demo and verify a real .fpack round-trip."""
    if progress_cb is not None:
        progress_cb(0.15, "Fitting Quantics Tensor-Train on a 2 MB 2D physics field...")
    demo = forge_tensor_pack.run_tensor_demo()

    # Also prove end-to-end Pack .fpack round-trip (lossless + opt-in lossy + noisy auto-fallback)
    if progress_cb is not None:
        progress_cb(
            0.65, "Packing & verifying a live .fpack with auto-pick fallback..."
        )
    import numpy as np  # noqa: PLC0415

    with tempfile.TemporaryDirectory(prefix="pack-tt-demo-") as tmp_str:
        tmp = Path(tmp_str)
        src = tmp / "corpus"
        src.mkdir()
        x = np.linspace(0.0, 1.0, 256, dtype=np.float64)
        xx, yy = np.meshgrid(x, x, indexing="ij")
        smooth = np.exp(-10.0 * ((xx - 0.4) ** 2 + (yy - 0.6) ** 2)) * np.cos(10.0 * xx)
        np.save(src / "smooth_field_256x256.npy", smooth)
        rng = np.random.default_rng(42)
        np.save(
            src / "random_noise_128x128.npy",
            rng.standard_normal((128, 128)).astype(np.float32),
        )

        fpack_ll = tmp / "tt-lossless.fpack"
        st_ll = fv.pack_sources(
            [src],
            fpack_ll,
            None,
            profile="fast",
            tensor_stage=True,
            tensor_options={"mode": "lossless", "max_rank": 24},
        )
        fv.verify_vault(fpack_ll, None)

        fpack_ls = tmp / "tt-lossy.fpack"
        st_ls = fv.pack_sources(
            [src],
            fpack_ls,
            None,
            profile="fast",
            tensor_stage=True,
            tensor_options={"mode": "lossy", "rel_tol": 1e-4, "max_rank": 24},
        )
        fv.verify_vault(fpack_ls, None)

    if progress_cb is not None:
        progress_cb(1.0, "Tensor-Train live check complete.")

    demo["fpack_check"] = {
        "raw_bytes": st_ll.raw_bytes,
        "lossless_vault_bytes": st_ll.vault_bytes,
        "lossless_tt_files": st_ll.tensor_files,
        "lossy_vault_bytes": st_ls.vault_bytes,
        "lossy_tt_files": st_ls.tensor_files,
        "verified": True,
    }
    return demo
