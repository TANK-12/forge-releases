"""Pack's exact PNG recipes on real Windows (Relay task 1578), run by Forge's own runtime.

    runtime\\python.exe pack_check.py --forge FORGE_DIR --work WORK --out OUT

Checks, on a Forge Windows download with task 1578's files laid over it:
1. this Python's zlib is zlib-ng (the cause);
2. offline, no classic zlib: Forge and the standalone unpacker refuse a
   Linux-made pack with PNG recipes before writing anything, naming the cause;
3. Forge fetches its pinned classic zlib1.dll and it passes the fingerprint;
4. that DLL writes the laptop's exact streams over the whole recipe grid
   (zlib_grid.py; Python's own zlib-ng is measured too, for the record);
5. the live photo demo saves about a third, 4/4 byte for byte;
6. a Linux-made .fpack restores byte for byte (Forge and the standalone).
Results: OUT/results.txt (PASS/FAIL/INFO lines); OUT/windows-made-demo.fpack.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
LINES: list[str] = []


def note(ok: bool, text: str) -> bool:
    line = f"{'PASS' if ok else 'FAIL'} {text}"
    print(line, flush=True)
    LINES.append(line)
    return ok


def info(text: str) -> None:
    line = f"INFO {text}"
    print(line, flush=True)
    LINES.append(line)


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--forge", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    forge, work, out = Path(a.forge), Path(a.work), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    tools = work / "tools"
    os.environ["FORGE_TOOLS_DIR"] = str(tools)
    os.environ["PACK_DATA_DIR"] = str(work / "PackData")
    os.environ["PACK_OUT_DIR"] = str(work / "Packed")
    os.environ["PACK_UNPACK_DIR"] = str(work / "Unpacked")
    sys.path[:0] = [str(forge / "apps" / "pack"), str(forge / "shared")]
    expected = json.loads((HERE / "linux-pack" / "expected.json").read_text())
    linux_pack = HERE / "linux-pack" / "linux-made-demo.fpack"
    note(sha(linux_pack) == expected["pack_sha256"], "Linux-made pack is the one made on the laptop")
    demo = forge / "apps" / "pack" / "demo_photos"
    note(
        {p.name: sha(p) for p in sorted(demo.iterdir())} == expected["files"],
        "the download's demo photos are the laptop's",
    )
    info(
        f"Python {sys.version.split()[0]}, zlib {zlib.ZLIB_VERSION} "
        f"(runtime {zlib.ZLIB_RUNTIME_VERSION}, zlib-ng {getattr(zlib, 'ZLIBNG_VERSION', None)})"
    )

    import forge_deflate as fd  # noqa: PLC0415
    import forge_media  # noqa: PLC0415
    import forge_tools  # noqa: PLC0415
    import forge_vault as fv  # noqa: PLC0415

    # 1. the cause
    note(not fd.python_zlib_is_classic(), f"this Python's zlib is not classic ({fd.python_zlib_words()})")
    st = fd.status()
    note(st["ready"] is False and st["can_fetch"] is True, f"before any fetch: {st}")

    # 2. offline: clear refusals, nothing written
    real_ensure = forge_tools.ensure

    def offline(name: str, *args, **kw):
        if name == fd.TOOL:
            raise forge_tools.FetchError(
                "could not fetch https://repo.msys2.org/... (simulated offline)"
            )
        return real_ensure(name, *args, **kw)

    forge_tools.ensure = offline
    fd.forget()
    dest = work / "refused-forge"
    try:
        fv.unpack_vault(linux_pack, dest)
        note(False, "Forge unpack refused without classic zlib (it unpacked)")
    except fv.VaultError as exc:
        words = str(exc)
        note(
            "needs classic zlib" in words
            and "zlib-ng" in words
            and "SHA-256" not in words
            and "nothing was written" in words
            and not dest.exists(),
            f"Forge unpack refused before writing, naming the cause: {words}",
        )
    showcase_offline = forge_media.encode_png_recipe((demo / "zenith-corona-shell.png").read_bytes())
    note(showcase_offline is None, "offline packing stores PNGs plainly (no recipe, no error)")
    forge_tools.ensure = real_ensure
    fd.forget()
    empty_tools = work / "empty-tools"
    empty_tools.mkdir(parents=True, exist_ok=True)
    sdest = work / "refused-standalone"
    env = dict(os.environ, FORGE_TOOLS_DIR=str(empty_tools), LOCALAPPDATA=str(work / "no-appdata"))
    r = subprocess.run(
        [sys.executable, str(forge / "apps" / "pack" / "standalone" / "forge_unpack.py"), "unpack", str(linux_pack), str(sdest)],
        capture_output=True, text=True, env=env, timeout=600,
    )  # fmt: skip
    msg = (r.stdout + r.stderr).strip().splitlines()[-1:] or [""]
    note(
        r.returncode != 0 and "classic zlib" in msg[0] and "Nothing was written" in msg[0] and not sdest.exists(),
        f"standalone unpacker refused before writing (exit {r.returncode}): {msg[0]}",
    )

    # 3. fetch the pinned classic zlib1.dll
    cl = fd.classic(auto_fetch=True)
    dll = forge_tools.find(fd.TOOL)
    note(bool(dll) and "zlib 1.3.2" in cl.name, f"fetched and fingerprint-checked: {cl.name} at {dll}")
    if dll:
        info(f"zlib1.dll sha256 {sha(Path(dll))}, {Path(dll).stat().st_size} bytes")
    path_dirs = forge_tools.path_dirs()
    note(not any("zlib-classic" in d for d in path_dirs), "the zlib folder is kept off PATH")

    # 4. the whole recipe grid against the laptop's
    grid = HERE / "zlib_grid.py"
    for lib, name in ((dll, "windows-dll"), ("python", "windows-python-zlib-ng")):
        r = subprocess.run(
            [sys.executable, str(grid), "digests", "--lib", str(lib), "--forge", str(forge), "--out", str(out / f"{name}.json")],
            capture_output=True, text=True, timeout=1500,
        )  # fmt: skip
        info(f"grid {name}: exit {r.returncode} {(r.stdout + r.stderr).strip()[-300:]}")
    r = subprocess.run(
        [sys.executable, str(grid), "compare", str(HERE / "laptop-python-zlib-1.3.2.json"), str(out / "windows-dll.json")],
        capture_output=True, text=True, timeout=600,
    )  # fmt: skip
    note(r.returncode == 0 and "all identical" in r.stdout, f"DLL == laptop over the recipe grid: {r.stdout.strip()[-200:]}")
    r = subprocess.run(
        [sys.executable, str(grid), "compare", str(HERE / "laptop-python-zlib-1.3.2.json"), str(out / "windows-python-zlib-ng.json")],
        capture_output=True, text=True, timeout=600,
    )  # fmt: skip
    info(f"for the record, this Python's zlib-ng vs the laptop: {r.stdout.strip()[-400:]}")

    # 5. the live photo demo
    import pack_core  # noqa: PLC0415

    res = pack_core.run_photo_showcase()
    counts = res.get("media_stage_counts") or {}
    note(
        res["all_bit_exact"] is True
        and res["photo_count"] == 4
        and counts.get("png_recipe_jxl") == 2
        and counts.get("jxl_jpeg") == 2
        and res["saved_pct"] >= 30,
        f"pack-showcase {res['saved_pct']}% saved (ZIP {res['zip_saved_pct']}%), stages {counts}, 4/4 bit-exact {res['all_bit_exact']}",
    )
    shutil.copy2(res["pack_path"], out / "windows-made-demo.fpack")
    info(f"windows-made-demo.fpack sha256 {sha(out / 'windows-made-demo.fpack')}")

    # 6. a Linux-made pack restores byte for byte
    dest = work / "linux-pack-forge"
    try:
        fv.unpack_vault(linux_pack, dest)
        got = {p.name: sha(p) for p in sorted(dest.iterdir())}
        note(got == expected["files"], f"Forge restores the Linux-made pack byte for byte ({len(got)} files)")
    except Exception as exc:  # noqa: BLE001
        note(False, f"Forge restores the Linux-made pack: {type(exc).__name__}: {exc}")
    djxl = forge_tools.find("djxl")
    sdest = work / "linux-pack-standalone"
    env = dict(os.environ, FORGE_DJXL=str(djxl or ""))
    r = subprocess.run(
        [sys.executable, str(forge / "apps" / "pack" / "standalone" / "forge_unpack.py"), "unpack", str(linux_pack), str(sdest)],
        capture_output=True, text=True, env=env, timeout=600,
    )  # fmt: skip
    got = {p.name: sha(p) for p in sorted(sdest.iterdir())} if sdest.is_dir() else {}
    note(
        r.returncode == 0 and got == expected["files"],
        f"standalone unpacker restores the Linux-made pack byte for byte (exit {r.returncode}, {len(got)} files) {(r.stdout + r.stderr).strip()[-200:]}",
    )
    fails = [line for line in LINES if line.startswith("FAIL")]
    (out / "results.txt").write_text("\n".join(LINES) + "\n", encoding="utf-8")
    print(f"{len(fails)} FAIL", flush=True)
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
