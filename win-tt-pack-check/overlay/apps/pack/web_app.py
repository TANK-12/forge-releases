"""Pack: fast-unpack compression and encrypted vaults (wraps shared/forge_vault.py)."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import uuid
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import pack_core as core

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
SHARED_DIR = Path(os.environ.get("FORGE_SHARED_DIR") or ROOT.parent.parent / "shared")
if str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))

import forge_media  # noqa: E402
import forge_tensor_pack  # noqa: E402
import forge_vault as fv  # noqa: E402
from forge_guard import LocalOnly  # noqa: E402
from forge_jobs import Job, JobStore, job_router, revalidate  # noqa: E402

app = FastAPI(title="Pack")
app.middleware("http")(revalidate)
app.add_middleware(LocalOnly)
STORE = JobStore()
app.include_router(job_router(STORE))

core.ensure_dirs()
core.clean_spools()


@app.exception_handler(core.PackAppError)
async def _pack_err(_request: Request, exc: core.PackAppError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(fv.VaultAuthError)
async def _auth_err(_request: Request, exc: fv.VaultAuthError) -> JSONResponse:
    return JSONResponse(status_code=401, content={"detail": str(exc)})


@app.exception_handler(fv.VaultError)
async def _vault_err(_request: Request, exc: fv.VaultError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


def _safe_rel_upload(rel: str, fallback: str) -> Path:
    raw = (rel or fallback or "file").replace("\\", "/").lstrip("/")
    parts = [
        re.sub(r"[:\x00]", "_", p) for p in raw.split("/") if p not in ("", ".", "..")
    ]
    parts = [p for p in parts if p not in ("", ".", "..")]
    if not parts:
        parts = ["file"]
    return Path(*parts)


def _prune_old_spools(folder: Path, keep: int = 3) -> None:
    if not folder.is_dir():
        return
    children = sorted(
        (p for p in folder.iterdir() if p.is_dir()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for stale in children[keep:]:
        shutil.rmtree(stale, ignore_errors=True)


@app.get("/api/state")
def get_state() -> dict[str, Any]:
    cfg = fv.load_profiles()
    return {
        "engine": fv.native_lib_status(),
        "profiles": core.PROFILE_CARDS,
        "ciphers": [
            {
                "id": "aes256gcm",
                "label": "AES-256-GCM (hardware VAES)",
                "notes": cfg["ciphers"]["aes256gcm"]["notes"],
            },
            {
                "id": "xchacha20",
                "label": "XChaCha20-Poly1305",
                "notes": cfg["ciphers"]["xchacha20"]["notes"],
            },
        ],
        "out_dir": str(core.OUT_DIR),
        "unpack_dir": str(core.UNPACK_DIR),
        "recent": core.load_recent(),
        "honest_limits": core.HONEST_LIMITS,
        "benchmarks": core.MEASURED_BENCHMARKS,
        "handler": core.handler_status(),
        "mount_slot": core.mount_slot_status(),
        "media_tools": forge_media.media_tools_status(),
        "tensor_tools": forge_tensor_pack.tensor_tools_status(),
        "showcase": core.showcase_info(),
    }


@app.post("/api/showcase")
def start_showcase() -> dict[str, Any]:
    """Run the live real-photo byte-for-byte compression showcase on the spot."""

    def work(job: Job) -> None:
        def on_prog(frac: float, msg: str) -> None:
            job.progress(frac)
            job.log(msg)

        job.result = core.run_photo_showcase(progress_cb=on_prog)

    job = STORE.start(Job("photo-showcase", "showcase"), work)
    return {"job": job.id}


@app.post("/api/tensor-demo")
def start_tensor_demo() -> dict[str, Any]:
    """Run the live Tensor-Train numeric compression demo (structured vs noisy data)."""

    def work(job: Job) -> None:
        def on_prog(frac: float, msg: str) -> None:
            job.progress(frac)
            job.log(msg)

        job.result = core.run_tensor_showcase(progress_cb=on_prog)

    job = STORE.start(Job("tensor-demo", "tensor-demo"), work)
    return {"job": job.id}


@app.post("/api/scan")
def scan_paths(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    raw_paths = body.get("paths") or []
    if not isinstance(raw_paths, list) or not raw_paths:
        raise core.PackAppError("select at least one file or folder")
    paths = [core.validate_local_path(str(p)) for p in raw_paths]
    profile = str(body.get("profile") or "fast")
    skip_media = bool(body.get("skip_incompressible", False))
    media_stage = bool(body.get("media_stage", False))
    raw_mopts = body.get("media_options")
    media_options = raw_mopts if isinstance(raw_mopts, dict) else None
    tensor_stage = bool(body.get("tensor_stage", False))
    raw_topts = body.get("tensor_options")
    tensor_options = raw_topts if isinstance(raw_topts, dict) else None
    result = fv.scan_sources(
        paths,
        profile=profile,
        skip_incompressible=skip_media,
        media_stage=media_stage,
        media_options=media_options,
        tensor_stage=tensor_stage,
        tensor_options=tensor_options,
    )
    default_name = paths[0].stem if len(paths) == 1 else f"{paths[0].name}-bundle"
    result["suggested_name"] = core.safe_filename(default_name)
    result["sources"] = [
        {"path": str(p), "name": p.name, "is_dir": p.is_dir()} for p in paths
    ]
    return result


@app.post("/api/upload")
async def upload_sources(
    files: list[UploadFile] = File(...),
    rel_paths: str = Form("[]"),
    profile: str = Form("fast"),
    skip_incompressible: bool = Form(False),
    media_stage: bool = Form(False),
    media_options: str = Form("{}"),
    tensor_stage: bool = Form(False),
    tensor_options: str = Form("{}"),
    prev_spool_id: str = Form(""),
) -> dict[str, Any]:
    """Accept dragged files or folder trees into Pack's temporary spool for packing."""
    if not files:
        raise core.PackAppError("no files uploaded")
    if re.fullmatch(r"[0-9a-f]{12}", prev_spool_id):
        shutil.rmtree(core.SPOOL_DIR / prev_spool_id, ignore_errors=True)
    _prune_old_spools(core.SPOOL_DIR, keep=3)
    try:
        rels = json.loads(rel_paths)
        if not isinstance(rels, list):
            rels = []
    except ValueError:
        rels = []

    spool_id = uuid.uuid4().hex[:12]
    spool = core.SPOOL_DIR / spool_id
    spool.mkdir(parents=True, exist_ok=True)
    spool_root = spool.resolve()
    written_paths: list[Path] = []
    try:
        for idx, up in enumerate(files):
            hint = str(rels[idx]) if idx < len(rels) and rels[idx] else ""
            rel = _safe_rel_upload(hint, up.filename or f"file_{idx}")
            dest = (spool_root / rel).resolve()
            if not dest.is_relative_to(spool_root):
                raise core.PackAppError(f"unsafe upload path rejected: {hint!r}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("wb") as fh:
                while True:
                    chunk = await up.read(1024 * 1024)
                    if not chunk:
                        break
                    fh.write(chunk)
            written_paths.append(dest)
    except BaseException:
        shutil.rmtree(spool, ignore_errors=True)
        raise

    # If a single file was uploaded with no subdirectories, scan that file; else scan spool root.
    if len(written_paths) == 1 and written_paths[0].parent == spool:
        scan_target: list[Path] = [written_paths[0]]
        suggested = written_paths[0].stem
    else:
        top_entries = sorted(spool.iterdir())
        if len(top_entries) == 1 and top_entries[0].is_dir():
            scan_target = [top_entries[0]]
            suggested = top_entries[0].name
        else:
            scan_target = [spool]
            suggested = f"pack-{len(written_paths)}-files"

    try:
        parsed_mopts = json.loads(media_options)
        mopts_dict = parsed_mopts if isinstance(parsed_mopts, dict) else None
    except ValueError:
        mopts_dict = None
    try:
        parsed_topts = json.loads(tensor_options)
        topts_dict = parsed_topts if isinstance(parsed_topts, dict) else None
    except ValueError:
        topts_dict = None

    scan = fv.scan_sources(
        scan_target,
        profile=profile,
        skip_incompressible=skip_incompressible,
        media_stage=media_stage,
        media_options=mopts_dict,
        tensor_stage=tensor_stage,
        tensor_options=topts_dict,
    )
    scan["spool_id"] = spool_id
    scan["spool_paths"] = [str(p) for p in scan_target]
    scan["suggested_name"] = core.safe_filename(suggested)
    return scan


@app.post("/api/pack")
def start_pack(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    raw_paths = body.get("paths") or []
    if not isinstance(raw_paths, list) or not raw_paths:
        raise core.PackAppError("add at least one file or folder to pack")
    sources = [core.validate_local_path(str(p)) for p in raw_paths]

    profile = str(body.get("profile") or "fast")
    password = str(body.get("password") or "")
    cipher = str(body.get("cipher") or "aes256gcm") if password else "none"
    skip_media = bool(body.get("skip_incompressible", False))
    media_stage = bool(body.get("media_stage", False))
    raw_mopts = body.get("media_options")
    media_options = raw_mopts if isinstance(raw_mopts, dict) else None
    tensor_stage = bool(body.get("tensor_stage", False))
    raw_topts = body.get("tensor_options")
    tensor_options = raw_topts if isinstance(raw_topts, dict) else None
    spool_id = str(body.get("spool_id") or "")
    spool_dir = (
        (core.SPOOL_DIR / spool_id) if re.fullmatch(r"[0-9a-f]{12}", spool_id) else None
    )

    out_dir_raw = str(body.get("out_dir") or "").strip()
    if out_dir_raw:
        try:
            out_dir = Path(out_dir_raw).expanduser()
        except RuntimeError as exc:
            raise core.PackAppError("invalid output folder") from exc
        if not out_dir.is_absolute():
            raise core.PackAppError("output folder must be an absolute path")
    else:
        out_dir = core.OUT_DIR

    default_stem = sources[0].stem if len(sources) == 1 else f"{sources[0].name}-bundle"
    out_name = core.safe_filename(
        str(body.get("out_name") or default_stem), encrypted=bool(password)
    )
    out_path = core.unique_out_path(out_dir, out_name)

    # Refuse writing the archive over any source file.
    resolved_out = out_path.resolve()
    for src in sources:
        if src.resolve() == resolved_out:
            raise core.PackAppError("output pack path cannot overwrite a source file")

    def work(job: Job) -> None:
        job.log("Scanning and packing files...")

        def on_prog(done: int, total: int, rel: str) -> None:
            job.progress(done / max(total, 1))
            job.log(f"Packing {done}/{total}: {rel}")

        stats = fv.pack_sources(
            sources,
            out_path,
            password if password else None,
            profile=profile,
            cipher=cipher,
            skip_incompressible=skip_media,
            media_stage=media_stage,
            media_options=media_options,
            tensor_stage=tensor_stage,
            tensor_options=tensor_options,
            progress_cb=on_prog,
        )
        summary = core.stats_to_dict(stats, out_path=out_path)
        summary["can_download"] = out_path.resolve().is_relative_to(
            core.OUT_DIR.resolve()
        )
        core.record_recent(summary)
        job.result = summary
        if spool_dir is not None and spool_dir.is_dir():
            shutil.rmtree(spool_dir, ignore_errors=True)

    job = STORE.start(Job(f"pack-{profile}", "pack"), work)
    return {"job": job.id, "out_path": str(out_path)}


@app.post("/api/open-upload")
async def upload_pack_to_open(file: UploadFile = File(...)) -> dict[str, Any]:
    """Save a browser-dropped .fpack/.fvlt into Pack's opened spool and peek its header."""
    name = Path(file.filename or "archive.fpack").name
    if not name.lower().endswith((".fpack", ".fvlt")):
        raise core.PackAppError("drop a .fpack or .fvlt pack file")
    _prune_old_spools(core.OPEN_SPOOL_DIR, keep=3)
    spool = core.OPEN_SPOOL_DIR / uuid.uuid4().hex[:12]
    spool.mkdir(parents=True, exist_ok=True)
    target = spool / re.sub(r"[^A-Za-z0-9._ -]+", "_", name)
    try:
        with target.open("wb") as fh:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
        return fv.peek_vault(target)
    except BaseException:
        shutil.rmtree(spool, ignore_errors=True)
        raise


@app.post("/api/peek")
def peek_pack(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    path = core.validate_local_path(str(body.get("path") or ""), expect_file=True)
    return fv.peek_vault(path)


@app.post("/api/inspect")
def inspect_pack(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    path = core.validate_local_path(str(body.get("path") or ""), expect_file=True)
    password = body.get("password")
    meta = fv.inspect_vault(path, str(password) if password else None)
    raw_bytes = int(meta.get("total_raw_bytes", 0))
    vault_bytes = int(meta.get("vault_bytes", 0))
    saved_bytes = max(0, raw_bytes - vault_bytes)
    saved_pct = (
        round(((1.0 - vault_bytes / raw_bytes) * 100.0), 1) if raw_bytes else 0.0
    )
    ratio = round(raw_bytes / vault_bytes, 2) if vault_bytes else 0.0
    files = meta.get("files", [])
    return {
        "path": str(path),
        "name": path.name,
        "encrypted": bool(meta.get("encrypted", True)),
        "cipher": meta.get("cipher", "aes256gcm"),
        "profile": meta.get("profile", "fast"),
        "vault_bytes": vault_bytes,
        "raw_bytes": raw_bytes,
        "saved_bytes": saved_bytes,
        "saved_pct": saved_pct,
        "ratio": ratio,
        "unique_chunks": int(meta.get("unique_chunks", 0)),
        "dedup_saved_bytes": int(meta.get("dedup_saved_bytes", 0)),
        "bypassed_files": int(meta.get("bypassed_files", 0)),
        "skipped_files": int(meta.get("skipped_files", 0)),
        "dict_bytes": int(meta.get("dict_bytes", 0)),
        "codec_counts": meta.get("codec_counts", {}),
        "media_stage": meta.get("media_stage"),
        "has_media": bool(meta.get("media_stage")),
        "tensor_stage": meta.get("tensor_stage"),
        "has_tensor": bool(meta.get("tensor_stage")),
        "empty_dirs": meta.get("empty_dirs", []),
        "file_count": len(files),
        "files": [
            {
                "path": fe["path"],
                "size": fe["size"],
                "kind": fe.get("kind", "default"),
                "sha256_short": str(fe.get("sha256", ""))[:12],
                "chunks": len(fe.get("chunks", [])),
                "media_stage": (
                    fe["media"].get("stage")
                    if isinstance(fe.get("media"), dict)
                    else None
                ),
                "tensor_mode": (
                    fe["media"].get("mode")
                    if isinstance(fe.get("media"), dict)
                    and fe["media"].get("stage") == "tt_array"
                    else None
                ),
                "tensor_rel_l2": (
                    fe["media"].get("measured_rel_l2")
                    if isinstance(fe.get("media"), dict)
                    and fe["media"].get("stage") == "tt_array"
                    else None
                ),
            }
            for fe in files
        ],
    }


@app.post("/api/verify")
def start_verify(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    path = core.validate_local_path(str(body.get("path") or ""), expect_file=True)
    password = body.get("password")

    def work(job: Job) -> None:
        job.log("Verifying integrity and SHA-256 checksums...")
        stats = fv.verify_vault(path, str(password) if password else None)
        res = core.stats_to_dict(stats, out_path=path)
        res["verified"] = True
        job.result = res

    job = STORE.start(Job("verify-pack", "verify"), work)
    return {"job": job.id}


@app.post("/api/unpack")
def start_unpack(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    path = core.validate_local_path(str(body.get("path") or ""), expect_file=True)
    password = body.get("password")
    dest_raw = str(body.get("dest_dir") or "").strip()
    if dest_raw:
        try:
            dest_dir = Path(dest_raw).expanduser()
        except RuntimeError as exc:
            raise core.PackAppError("invalid destination folder") from exc
        if not dest_dir.is_absolute():
            raise core.PackAppError("destination folder must be an absolute path")
    else:
        dest_dir = core.unique_unpack_dir(core.UNPACK_DIR, path)

    raw_only = body.get("only_paths")
    only_paths: set[str] | None = None
    if isinstance(raw_only, list) and raw_only:
        only_paths = {str(x) for x in raw_only if str(x).strip()}

    def work(job: Job) -> None:
        job.log("Unpacking and verifying SHA-256...")

        def on_prog(done: int, total: int, rel: str) -> None:
            job.progress(done / max(total, 1))
            job.log(f"Unpacking {done}/{total}: {rel}")

        stats = fv.unpack_vault(
            path,
            dest_dir,
            str(password) if password else None,
            only_paths=only_paths,
            progress_cb=on_prog,
        )
        res = core.stats_to_dict(stats, out_path=path)
        res["dest_dir"] = str(dest_dir)
        res["verified"] = True
        job.result = res

    job = STORE.start(Job("unpack-pack", "unpack"), work)
    return {"job": job.id, "dest_dir": str(dest_dir)}


@app.get("/api/download/{name}")
def download_pack(name: str) -> FileResponse:
    if "/" in name or "\\" in name or name in ("", ".", ".."):
        raise HTTPException(400, "invalid filename")
    base = core.OUT_DIR.resolve()
    target = (base / name).resolve()
    if not target.is_relative_to(base) or not target.is_file():
        raise HTTPException(404, "pack file not found")
    return FileResponse(target, filename=target.name)


@app.post("/api/handler/register")
def register_file_handler() -> dict[str, Any]:
    return core.register_handler()


@app.get("/api/mounts")
def get_mounts() -> dict[str, Any]:
    return core.mount_slot_status()


app.mount("/shared", StaticFiles(directory=SHARED_DIR), name="shared")
app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
