"""Windows runner verification of Pack's Tensor-Train stage (Relay task 1583)."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import sys
import time
import wave
from pathlib import Path

import numpy as np


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--forge", required=True)
    ap.add_argument("--fixtures", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    forge = Path(args.forge)
    fixtures = Path(args.fixtures)
    work = Path(args.work)
    out = Path(args.out)
    work.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)

    sys.path.insert(0, str(forge / "shared"))
    sys.path.insert(0, str(forge / "apps" / "pack"))
    import forge_tensor_pack as ftp  # noqa: E402
    import forge_vault as fv  # noqa: E402
    import pack_core  # noqa: E402

    lines: list[str] = []
    fails = 0

    def ok(msg: str) -> None:
        lines.append(f"PASS {msg}")
        print(f"PASS {msg}")

    def fail(msg: str) -> None:
        nonlocal fails
        fails += 1
        lines.append(f"FAIL {msg}")
        print(f"FAIL {msg}")

    st_tools = ftp.tensor_tools_status()
    if st_tools["ready"] and st_tools["numpy"] and st_tools["zstd_stdlib"]:
        ok(f"runtime numpy={st_tools['numpy_version']} zstd_stdlib=True")
    else:
        fail(f"runtime missing backend: {st_tools}")

    expected = json.loads((fixtures / "expected.json").read_text(encoding="utf-8"))
    standalone = forge / "apps" / "pack" / "standalone" / "forge_unpack.py"

    # 1. Unpack Linux-made lossless TT .fpack on Windows (forge_vault + standalone --pure-python)
    linux_ll = fixtures / "linux-tt-lossless.fpack"
    d_ll_v = work / "ll_vault"
    t0 = time.perf_counter()
    fv.unpack_vault(linux_ll, d_ll_v, None)
    ms_v = (time.perf_counter() - t0) * 1000.0
    mismatches = [
        fn for fn, want in expected["lossless_sha256"].items()
        if sha256_file(d_ll_v / fn) != want
    ]
    if not mismatches:
        ok(f"linux->win lossless forge_vault ({len(expected['lossless_sha256'])} files, {ms_v:.1f} ms)")
    else:
        fail(f"linux->win lossless forge_vault mismatches: {mismatches}")

    d_ll_sa = work / "ll_standalone"
    cp = subprocess.run(
        [sys.executable, "-B", str(standalone), "unpack", str(linux_ll), str(d_ll_sa), "--pure-python"],
        capture_output=True, text=True,
    )
    if cp.returncode == 0 and all(
        sha256_file(d_ll_sa / fn) == want for fn, want in expected["lossless_sha256"].items()
    ):
        ok("linux->win lossless standalone --pure-python (100% SHA-256 bit-exact)")
    else:
        fail(f"linux->win lossless standalone failed rc={cp.returncode} err={cp.stderr}")

    # 2. Unpack Linux-made lossy TT .fpack on Windows (must match Linux reconstructed bytes bit-for-bit!)
    linux_ls = fixtures / "linux-tt-lossy.fpack"
    d_ls_v = work / "ls_vault"
    fv.unpack_vault(linux_ls, d_ls_v, None)
    d_ls_sa = work / "ls_standalone"
    cp2 = subprocess.run(
        [sys.executable, "-B", str(standalone), "unpack", str(linux_ls), str(d_ls_sa), "--pure-python"],
        capture_output=True, text=True,
    )
    if (
        cp2.returncode == 0
        and all(sha256_file(d_ls_v / fn) == want for fn, want in expected["lossy_sha256"].items())
        and all(sha256_file(d_ls_sa / fn) == want for fn, want in expected["lossy_sha256"].items())
    ):
        ok("linux->win lossy deterministic SHA-256 bit-exact (vault + standalone --pure-python)")
    else:
        fail(f"linux->win lossy deterministic check failed rc={cp2.returncode} err={cp2.stderr}")

    # 3. Pack on Windows -> verify -> save artifacts for reverse Windows->Linux check
    win_ll = out / "win-tt-lossless.fpack"
    t0 = time.perf_counter()
    st_ll = fv.pack_sources(
        [d_ll_v], win_ll, None, profile="fast",
        tensor_stage=True, tensor_options={"mode": "lossless", "max_rank": 24},
    )
    ms_wll = (time.perf_counter() - t0) * 1000.0
    fv.verify_vault(win_ll, None)
    if st_ll.tensor_stage and st_ll.tensor_files >= 3 and st_ll.tensor_lossy_files == 0:
        ok(f"win pack lossless: {st_ll.raw_bytes:,} -> {st_ll.vault_bytes:,} B ({st_ll.tensor_files} TT files, {ms_wll:.1f} ms)")
    else:
        fail(f"win pack lossless unexpected stats: {st_ll}")

    win_ls = out / "win-tt-lossy.fpack"
    t0 = time.perf_counter()
    st_ls = fv.pack_sources(
        [d_ll_v], win_ls, None, profile="fast",
        tensor_stage=True, tensor_options={"mode": "lossy", "rel_tol": 1e-4, "max_rank": 24},
    )
    ms_wls = (time.perf_counter() - t0) * 1000.0
    fv.verify_vault(win_ls, None)
    if st_ls.tensor_stage and st_ls.tensor_lossy_files >= 3 and st_ls.vault_bytes < st_ll.vault_bytes:
        ok(f"win pack lossy (1e-4): {st_ls.raw_bytes:,} -> {st_ls.vault_bytes:,} B ({st_ls.tensor_lossy_files} TT files, {ms_wls:.1f} ms)")
    else:
        fail(f"win pack lossy unexpected stats: {st_ls}")

    # 4. Run Pack's live tensor demo on Windows
    demo = pack_core.run_tensor_showcase()
    f = demo["field"]
    if (
        f["lossless_bit_exact"]
        and f["lossy_verified"]
        and f["lossy_ratio"] > 50.0
        and not demo["negative_control"]["auto_picked_tt"]
        and demo["fpack_check"]["verified"]
    ):
        ok(
            f"win live demo: lossless={f['lossless_ratio']}x ({f['lossless_pack_ms']}ms), "
            f"lossy={f['lossy_ratio']}x (rel_l2={f['lossy_rel_l2']:.2e}, {f['lossy_unpack_ms']}ms), "
            f"noise_fallback=True"
        )
    else:
        fail(f"win live demo failed: {demo}")

    # 5. Also check critic regression: padded 1-byte uint8 standalone --pure-python + tiny float64
    u8_src = work / "u8_pad.npy"
    np.save(u8_src, np.clip(np.rint(np.linspace(0, 255, 65 * 65 * 3).reshape(65, 65, 3)), 0, 255).astype("|u1"))
    u8_pack = work / "u8_pad.fpack"
    fv.pack_sources([u8_src], u8_pack, None, profile="fast", tensor_stage=True, tensor_options={"mode": "lossless", "max_rank": 16, "min_gain": 0.0})
    u8_out = work / "u8_unp"
    cp3 = subprocess.run([sys.executable, "-B", str(standalone), "unpack", str(u8_pack), str(u8_out), "--pure-python"], capture_output=True, text=True)
    if cp3.returncode == 0 and (u8_out / "u8_pad.npy").read_bytes() == u8_src.read_bytes():
        ok("win critic regression: padded uint8 standalone --pure-python bit-exact")
    else:
        fail(f"win critic regression failed: rc={cp3.returncode} err={cp3.stderr}")

    (out / "win_demo.json").write_text(json.dumps(demo, indent=2) + "\n", encoding="utf-8")
    (out / "check_results.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
