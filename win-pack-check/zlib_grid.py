"""Compare deflate streams of several zlib builds over Pack's whole recipe grid (Relay task 1578).

    python zlib_grid.py digests --lib python|PATH --forge FORGE_ROOT --out OUT.json
    python zlib_grid.py compare A.json B.json [C.json ...]

Inputs: the two demo PNGs' unfiltered-IDAT data (first 512 KiB) and
forge_deflate's fingerprint sample, each over level 0-9 x memLevel 1-9 x
strategy 0-3 x wbits 8-15 (2880 settings); plus the full streams of the
recipes find_zlib_recipe finds for the demo PNGs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import zlib
from pathlib import Path

PREFIX = 512 * 1024
GRID = [
    (lv, mem, st, wb)
    for st in range(4)
    for mem in range(1, 10)
    for lv in range(10)
    for wb in range(8, 16)
]


def png_filtered(data: bytes) -> bytes:
    pos, idat = 8, []
    while pos < len(data):
        n = int.from_bytes(data[pos : pos + 4], "big")
        typ = data[pos + 4 : pos + 8]
        if typ == b"IDAT":
            idat.append(data[pos + 8 : pos + 8 + n])
        pos += 12 + n
        if typ == b"IEND":
            break
    return zlib.decompress(b"".join(idat))


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("digests")
    d.add_argument("--lib", required=True)
    d.add_argument("--forge", required=True)
    d.add_argument("--out", required=True)
    c = sub.add_parser("compare")
    c.add_argument("files", nargs="+")
    a = ap.parse_args()
    if a.cmd == "compare":
        docs = [json.loads(Path(f).read_text()) for f in a.files]
        ref = docs[0]
        bad = 0
        for doc in docs[1:]:
            for key, want in ref["digests"].items():
                got = doc["digests"].get(key)
                if got is None:
                    print(f"MISSING {doc['lib']} {key}")
                    bad += 1
                    continue
                diff = [i for i, (x, y) in enumerate(zip(want, got)) if x != y]
                if len(want) != len(got) or diff:
                    bad += 1
                    print(f"DIFF {doc['lib']} vs {ref['lib']} {key}: {len(diff)} of {len(want)} differ, first {[GRID[i] for i in diff[:3]] if len(want) == len(GRID) else diff[:3]}")
            if ref["recipes"] != doc["recipes"]:
                bad += 1
                print(f"DIFF recipes {doc['lib']}: {doc['recipes']} vs {ref['recipes']}")
            print(f"{doc['lib']} vs {ref['lib']}: {sum(len(v) for v in ref['digests'].values())} streams compared")
        print("all identical" if bad == 0 else f"{bad} differences")
        return 1 if bad else 0

    shared = Path(a.forge) / "shared"
    sys.path.insert(0, str(shared))
    import forge_deflate as fd  # noqa: PLC0415

    cl = None
    if a.lib == "python":
        factory = zlib.compressobj
        name = f"python zlib {zlib.ZLIB_RUNTIME_VERSION}"
        cl = fd.Classic(name, zlib.compressobj)
    else:
        cl = fd.load_library(a.lib) if not a.lib.startswith("raw:") else None
        if cl is None:  # raw: skip the classic check (to measure a non-classic lib)
            import ctypes  # noqa: PLC0415

            lib = ctypes.CDLL(a.lib[4:])
            fd.bind(lib)

            def factory(*args, _lib=lib):
                return fd.CtypesCompress(_lib, *args)

            name = a.lib
            cl = fd.Classic(name, factory)
        else:
            factory = cl.compressobj
            name = cl.name
    demo = Path(a.forge) / "apps" / "pack" / "demo_photos"
    inputs: dict[str, bytes] = {"fingerprint_sample": fd.fingerprint_sample()}
    full: dict[str, bytes] = {}
    png_sha: dict[str, str] = {}
    for p in sorted(demo.glob("*.png")):
        raw = p.read_bytes()
        png_sha[p.name] = hashlib.sha256(raw).hexdigest()
        f = png_filtered(raw)
        full[p.name] = f
        inputs[p.name] = f[:PREFIX]
    t0 = time.perf_counter()
    digests: dict[str, list[str]] = {}
    for key, data in inputs.items():
        row = []
        for lv, mem, st, wb in GRID:
            try:
                co = factory(lv, zlib.DEFLATED, wb, mem, st)
                out = co.compress(data) + co.flush()
                row.append(hashlib.sha256(out).hexdigest()[:20])
            except (ValueError, zlib.error) as exc:  # zlib-ng may refuse some
                row.append(f"error:{exc}"[:40])
        digests[key] = row
    # the recipes the demo PNGs really use, on their full streams
    import forge_media  # noqa: PLC0415

    recipes: dict[str, list[int] | None] = {}
    for name_png, f in full.items():
        raw = (demo / name_png).read_bytes()
        parsed = forge_media.parse_png(raw)
        z = b"".join(b for t, b, _c in parsed[0] if t == b"IDAT")
        r = forge_media.find_zlib_recipe(f, z, cl) if cl else None
        recipes[name_png] = list(r) if r else None
        if r:
            lv, mem, st, wb = r
            co = factory(lv, zlib.DEFLATED, wb, mem, st)
            out = co.compress(f) + co.flush()
            digests[f"full:{name_png}"] = [hashlib.sha256(out).hexdigest()[:20], str(out == z)]
    doc = {
        "lib": name,
        "python": sys.version.split()[0],
        "python_zlib": zlib.ZLIB_RUNTIME_VERSION,
        "png_sha256": png_sha,
        "seconds": round(time.perf_counter() - t0, 1),
        "recipes": recipes,
        "digests": digests,
    }
    Path(a.out).write_text(json.dumps(doc))
    print(name, doc["seconds"], "s", recipes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
