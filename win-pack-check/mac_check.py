"""Apple's system zlib against classic zlib (Relay task 1578), run on GitHub's Macs.

Forge's Mac runtime (python-build-standalone) links /usr/lib/libz.1.dylib, so
Pack's PNG recipes there deflate with Apple's zlib. This checks it passes
forge_deflate's fingerprint and writes the laptop's exact bytes over the whole
recipe grid (zlib_grid.py). Results: printed PASS/FAIL/INFO lines.
"""

from __future__ import annotations

import argparse
import platform
import subprocess
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIBZ = "/usr/lib/libz.1.dylib"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--forge", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--lib", default=LIBZ)
    a = ap.parse_args()
    libz = a.lib
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(Path(a.forge) / "shared"))
    import forge_deflate as fd  # noqa: PLC0415

    print(f"INFO macOS {platform.mac_ver()[0]} {platform.machine()}, Python {sys.version.split()[0]} zlib {zlib.ZLIB_RUNTIME_VERSION}")
    print(f"INFO this runner Python's own zlib is classic: {fd.python_zlib_is_classic()}")
    fails = 0
    try:
        cl = fd.load_library(libz)
        print(f"PASS Apple's {libz} passes the classic fingerprint: {cl.name}")
    except ValueError as exc:
        fails += 1
        print(f"FAIL Apple's {libz} fingerprint: {exc}")
    grid = HERE / "zlib_grid.py"
    r = subprocess.run(
        [sys.executable, str(grid), "digests", "--lib", f"raw:{libz}", "--forge", a.forge, "--out", str(out / "mac-libz.json")],
        capture_output=True, text=True, timeout=1500,
    )  # fmt: skip
    print(f"INFO grid: exit {r.returncode} {(r.stdout + r.stderr).strip()[-300:]}")
    r = subprocess.run(
        [sys.executable, str(grid), "compare", str(HERE / "laptop-python-zlib-1.3.2.json"), str(out / "mac-libz.json")],
        capture_output=True, text=True, timeout=600,
    )  # fmt: skip
    ok = r.returncode == 0 and "all identical" in r.stdout
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'} Apple's libz == laptop over the recipe grid: {r.stdout.strip()[-600:]}")
    print(f"{fails} FAIL")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
