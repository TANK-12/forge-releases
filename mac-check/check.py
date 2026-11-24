#!/usr/bin/env python3
"""Real-Mac checks of one Forge Mac download on a GitHub-hosted Mac runner
(Relay tasks 678 and 1391). Runs on the mac-check branch of the releases
repository only; the download page and main are untouched.

    python3 mac-check/check.py <target>      # macos-arm64 or macos-x64

mac-check/expected.json names, per target, the archive under test ("new")
and the Mac download people already have ("old"), each with its release tag,
asset name and SHA-256. Every archive is checksummed before it is unpacked,
so only the exact bytes that pass here can be published.

Steps, each a PASS, FAIL or INFO line in out/results.txt:
 1. download and checksum both archives;
 2. unpack the new one as a Safari download opened in Finder (quarantine
    flag, Archive Utility), Info.plist, the lowest macOS every Mach-O file
    allows against LSMinimumSystemVersion, signatures (Apple silicon refuses
    unsigned code, so there a bad one fails), and what Gatekeeper says;
 3. the update path a person follows: the old app in /Applications, opened
    with `open`, "On this computer" picked on its welcome page, a setting and
    a note saved through the apps' own APIs, quit, the whole app replaced by
    the new one, opened again: the place is remembered, the setting and the
    note are back, a real native window is on screen, an app's backend
    starts, Settings says how a Mac gets the next version, and a normal quit
    leaves no process behind;
 4. a fresh install's every-app smoke check with the flows that save things,
    in a new home folder, with every app in the bundle accounted for;
 5. the password-PDF and device-certificate code paths on the cryptography
    each Mac gets (Intel keeps 48.0.1, the newest with an Intel Mac wheel);
 6. for information: the quarantined app opened as a person double-clicks
    it, and an ad hoc hardened-runtime signature (the shape Developer ID
    signing would take) still starting a few apps.

The job fails when any line is FAIL.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

TARGET = sys.argv[1] if len(sys.argv) > 1 else ""
HERE = Path(__file__).resolve().parent
OUT = Path.cwd() / "out"
WORK = Path(os.environ.get("RUNNER_TEMP") or "/tmp") / "forge"
REPO = os.environ.get("GITHUB_REPOSITORY", "")
APP = Path("/Applications/Forge.app")
HUB = "http://127.0.0.1:8400"
MARK = f"Mac upgrade check {uuid.uuid4().hex[:8]}"
SCALE = 1.25
ARCH = os.uname().machine  # arm64 or x86_64


def note(kind: str, name: str, detail: str = "") -> None:
    line = f"{kind} {name}" + (f": {detail}" if detail else "")
    print(line, flush=True)
    with open(OUT / "results.txt", "a", encoding="utf-8") as f:
        f.write(line + "\n")


def verdict(ok: bool, name: str, detail: str = "", soft: bool = False) -> bool:
    note("PASS" if ok else ("INFO" if soft else "FAIL"), name, detail)
    return ok


def step(words: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {words}", flush=True)


def run(cmd: list[str], timeout: float = 600, **kw) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, **kw
        )
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        return subprocess.CompletedProcess(cmd, 124, out, f"timed out ({timeout} s)")


def one_line(text: str, limit: int = 300) -> str:
    return re.sub(r"\s+", " ", text or "").strip()[:limit]


# -- HTTP ----------------------------------------------------------------------


def http(
    url: str, body: dict | None = None, headers: dict | None = None, timeout=20
) -> tuple[int, str, str]:
    """(status, text, final url); status 0 when nothing answered."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=dict(headers or {}))
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), url
    except Exception as e:  # refused, reset, timed out
        return 0, str(e), url


def wait_for(fn, seconds: float, every: float = 2.0):
    end = time.monotonic() + seconds
    while True:
        got = fn()
        if got or time.monotonic() > end:
            return got
        time.sleep(every)


def hub_up() -> bool:
    return http(HUB + "/forge/ping", timeout=4)[0] == 200


def token() -> str:
    _, text, _ = http(HUB + "/hub/index.html")
    found = re.search(r'"token":\s*"([^"]+)"', text)
    return found.group(1) if found else ""


def bridge(tok: str, body: dict) -> tuple[int, str]:
    status, text, _ = http(HUB + "/forge/bridge", body, {"X-Forge": tok})
    return status, text


def app_url(tok: str, name: str) -> str:
    _, text, _ = http(f"{HUB}/hub/status.js?t={tok}")
    found = re.search(r"window\.FORGE_STATUS = (.*?);\n", text)
    try:
        return str(json.loads(found.group(1))[name]["url"]).rstrip("/") if found else ""
    except (KeyError, TypeError, ValueError):
        return ""


def started(tok: str, name: str, probe: str) -> str:
    """Start one app through the hub's bridge (as its tile does) and wait
    until its API answers; its base URL, or "" when it never did."""
    bridge(tok, {"start": name})
    url = wait_for(lambda: app_url(tok, name), 30)
    if not url:
        return ""
    return url if wait_for(lambda: http(url + probe)[0] == 200, 240, 3) else ""


# -- processes and windows ---------------------------------------------------


def forge_pids() -> list[int]:
    done = run(["pgrep", "-f", "Forge.app/Contents"], timeout=20)
    return [int(p) for p in done.stdout.split()]


def leftovers() -> str:
    return one_line(run(["pgrep", "-fl", "Forge.app/Contents"], timeout=20).stdout)


def stop_all() -> None:
    for sig in ("-TERM", "-KILL"):
        if not forge_pids():
            return
        run(["pkill", sig, "-f", "Forge.app/Contents"], timeout=20)
        wait_for(lambda: not forge_pids(), 20, 1)


WINDOWS = r"""
import json, sys
import Quartz
pids = {int(p) for p in sys.argv[1:]}
rows = []
for w in Quartz.CGWindowListCopyWindowInfo(Quartz.kCGWindowListOptionAll, 0) or []:
    if int(w.get("kCGWindowOwnerPID", -1)) not in pids:
        continue
    b = w.get("kCGWindowBounds") or {}
    rows.append({
        "owner": str(w.get("kCGWindowOwnerName", "")),
        "pid": int(w.get("kCGWindowOwnerPID", -1)),
        "layer": int(w.get("kCGWindowLayer", 0)),
        "onscreen": bool(w.get("kCGWindowIsOnscreen", False)),
        "width": int(b.get("Width", 0)),
        "height": int(b.get("Height", 0)),
    })
print(json.dumps(rows))
"""


def native_windows() -> list[dict]:
    """On-screen, normal-layer windows owned by Forge's processes, read from
    the window server with the app's own Python (pyobjc's Quartz ships for
    pywebview)."""
    python = APP / "Contents/Resources/forge/runtime/bin/python3"
    pids = [str(p) for p in forge_pids()]
    if not pids:
        return []
    done = run([str(python), "-I", "-c", WINDOWS, *pids], timeout=60)
    try:
        rows = json.loads(done.stdout or "[]")
    except ValueError:
        return []
    return [
        r
        for r in rows
        if r["onscreen"]
        and r["layer"] == 0
        and r["width"] >= 400
        and r["height"] >= 300
    ]


def screenshot(name: str) -> None:
    run(["screencapture", "-x", str(OUT / f"{name}.png")], timeout=30)


def open_app(label: str) -> bool:
    step(f"open {label}")
    done = run(["open", str(APP)], timeout=60)
    if done.returncode:
        note("INFO", f"{label} open", one_line(done.stderr))
    return bool(wait_for(hub_up, 240, 2))


def quit_app(label: str, graded: bool) -> None:
    """A normal Mac quit (Forge > Quit, the same Apple event), then: no hub,
    no Forge process left."""
    step(f"quit {label}")
    done = run(["osascript", "-e", 'tell application "Forge" to quit'], timeout=60)
    gone = wait_for(lambda: not hub_up() and not forge_pids(), 45, 1)
    how = "Quit (Apple event)"
    if not gone:
        note("INFO", f"{label} quit event", one_line(done.stderr or done.stdout))
        tok = token()
        if tok:
            bridge(tok, {"forge": "quit"})  # the hub's own Quit
        gone = wait_for(lambda: not hub_up() and not forge_pids(), 45, 1)
        how = "the hub's Quit"
    left = leftovers()
    verdict(
        bool(gone),
        f"{label} quits with nothing left running",
        how if gone else f"still running: {left}",
        soft=not graded,
    )
    stop_all()


# -- 1. the archives -----------------------------------------------------------


def fetch(entry: dict, dest: Path) -> Path:
    """One release asset (a draft's too) to dest, checksummed before use."""
    dest.mkdir(parents=True, exist_ok=True)
    file = dest / entry["asset"]
    query = (
        f'.[] | select(.tag_name == "{entry["tag"]}") | .assets[]'
        f' | select(.name == "{entry["asset"]}") | .id'
    )
    found = run(
        ["gh", "api", "--paginate", f"repos/{REPO}/releases", "--jq", query],
        timeout=120,
    )
    ids = found.stdout.split()
    if not ids:
        note("FAIL", f"download {entry['asset']}", f"not in {entry['tag']}")
        raise SystemExit(1)
    with open(file, "wb") as f:
        got = subprocess.run(
            [
                "gh",
                "api",
                "-H",
                "Accept: application/octet-stream",
                f"repos/{REPO}/releases/assets/{ids[0]}",
            ],
            stdout=f,
            timeout=1800,
        )
    sha = hashlib.sha256()
    with open(file, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            sha.update(block)
    ok = got.returncode == 0 and sha.hexdigest() == entry["sha256"]
    verdict(
        ok,
        f"checksum {entry['asset']}",
        f"{file.stat().st_size} bytes, sha256 {sha.hexdigest()}"
        + ("" if ok else f", expected {entry['sha256']}"),
    )
    if not ok:
        raise SystemExit(1)
    return file


def quarantine(path: Path) -> None:
    flag = f"0083;{int(time.time()):x};Safari;{uuid.uuid4()}".upper()
    run(["xattr", "-w", "com.apple.quarantine", flag, str(path)], timeout=30)


def unpack_like_finder(archive: Path) -> Path:
    quarantine(archive)
    run(["open", "-a", "Archive Utility", str(archive)], timeout=60)
    app = archive.parent / "Forge/Forge.app"
    wait_for(lambda: (app / "Contents/MacOS/Forge").exists(), 600, 2)
    # Archive Utility quits by itself when it has written everything
    wait_for(
        lambda: run(["pgrep", "-x", "Archive Utility"], timeout=10).returncode != 0,
        900,
        3,
    )
    listed = run(["tar", "-tzf", str(archive)], timeout=600).stdout.splitlines()
    files = sum(1 for n in listed if not n.endswith("/"))
    there = sum(1 for p in (archive.parent / "Forge").rglob("*") if not p.is_dir())
    if verdict(
        app.is_dir() and there >= files,
        "unpacks with Archive Utility (a Finder double-click)",
        f"{there} of {files} files",
    ):
        return app
    shutil.rmtree(archive.parent / "Forge", ignore_errors=True)
    run(["tar", "-xzf", str(archive), "-C", str(archive.parent)], timeout=900)
    return app


# -- 2. the app's files --------------------------------------------------------

MACHO = {
    bytes.fromhex(m)
    for m in ("feedface", "feedfacf", "cefaedfe", "cffaedfe", "cafebabe", "bebafeca")
}


def min_macos(loads: str) -> list[str]:
    """The lowest macOS each `otool -l` listing says it needs.

    Only LC_BUILD_VERSION's minos and LC_VERSION_MIN_MACOSX's version count;
    a linked library's "current version 62460.40.78" is not a macOS version.
    """
    found = []
    for block in re.split(r"^Load command \d+$", loads, flags=re.M):
        cmd = re.search(r"^\s*cmd (\S+)", block, flags=re.M)
        key = {"LC_BUILD_VERSION": "minos", "LC_VERSION_MIN_MACOSX": "version"}.get(
            cmd.group(1) if cmd else ""
        )
        if key:
            found += re.findall(rf"^\s*{key} (\d+(?:\.\d+)*)\s*$", block, flags=re.M)
    return found


def version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", text)[:3])


def file_checks(app: Path) -> None:
    plist = app / "Contents/Info.plist"
    verdict(
        run(["plutil", "-lint", str(plist)], timeout=30).returncode == 0, "Info.plist"
    )
    raw = run(["plutil", "-convert", "json", "-o", "-", str(plist)], timeout=30)
    info = json.loads(raw.stdout or "{}")
    floor = str(info.get("LSMinimumSystemVersion") or "")
    note(
        "INFO",
        "Info.plist",
        f"version {info.get('CFBundleShortVersionString')},"
        f" LSMinimumSystemVersion {floor or 'not set'},"
        f" LSArchitecturePriority {info.get('LSArchitecturePriority')}",
    )
    total, unsigned, newest, newest_file = 0, [], (0,), ""
    arch = "arm64" if ARCH == "arm64" else "x86_64"
    for path in app.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        with open(path, "rb") as f:
            if f.read(4) not in MACHO:
                continue
        if path.suffix == ".class":
            continue
        total += 1
        if run(["codesign", "-v", "--arch", arch, str(path)], timeout=60).returncode:
            unsigned.append(str(path.relative_to(app)))
        loads = run(["otool", "-arch", arch, "-l", str(path)], timeout=60).stdout
        for found in min_macos(loads):
            if version_tuple(found) > newest:
                newest, newest_file = version_tuple(found), str(path.relative_to(app))
    (OUT / "macho-unsigned.txt").write_text("\n".join(unsigned) + "\n")
    verdict(
        not unsigned,
        f"every Mach-O file has a valid signature for {arch}",
        f"{total} files, {len(unsigned)} without (macho-unsigned.txt)",
        # Apple silicon kills unsigned code; an Intel Mac runs it
        soft=ARCH != "arm64",
    )
    shown = ".".join(map(str, newest))
    verdict(
        bool(floor) and newest <= version_tuple(floor),
        "no Mach-O file needs a newer macOS than Info.plist promises",
        f"newest needs {shown} ({newest_file}), plist says {floor}",
    )
    spctl = run(["spctl", "-a", "-vv", "-t", "exec", str(app)], timeout=120)
    note(
        "INFO",
        "Gatekeeper on the downloaded app",
        one_line(spctl.stderr + spctl.stdout),
    )
    check = run(["codesign", "-dv", str(app)], timeout=60)
    note("INFO", "app signature", one_line(check.stderr or check.stdout))


# -- 3. the update path --------------------------------------------------------


def install(app: Path) -> None:
    if APP.exists():
        shutil.rmtree(APP)  # a whole new app, never merged over the old one
    run(["ditto", str(app), str(APP)], timeout=900)
    # the README's step for an unsigned app (Finder keeps the flag on a copy)
    run(["xattr", "-dr", "com.apple.quarantine", str(APP)], timeout=300)


def save_things(label: str) -> None:
    tok = token()
    _, text, _ = http(f"{HUB}/forge/place?t={tok}")
    state = json.loads(text or "{}")
    if state.get("mode") != "ready":
        status, text = http(
            HUB + "/forge/place",
            {"do": "use", "path": state.get("computer", "")},
            {"X-Forge": tok},
        )[:2]
        verdict(
            status == 200 and '"ok": true' in text,
            f"{label} welcome: On this computer",
            f"{state.get('computer')} -> HTTP {status} {one_line(text, 160)}",
        )
    settings = started(tok, "settings", "/api/settings")
    if verdict(bool(settings), f"{label} Settings starts", settings):
        http(settings + "/api/settings", {"text_scale": SCALE})
        _, text, _ = http(settings + "/api/settings")
        got = (json.loads(text or "{}").get("settings") or {}).get("text_scale")
        verdict(got == SCALE, f"{label} text size saved", f"text_scale {got}")
    notes = started(tok, "notes", "/api/notes")
    if verdict(bool(notes), f"{label} Notes starts", notes):
        status, text, _ = http(
            notes + "/api/notes", {"notebook": "", "text": f"# {MARK}\nKept."}
        )
        made = json.loads(text or "{}") if status == 200 else {}
        (OUT / "note-id.txt").write_text(str(made.get("id", "")))
        verdict(bool(made.get("id")), f"{label} note saved", f"id {made.get('id')}")


def things_kept(label: str, tok: str) -> None:
    settings = started(tok, "settings", "/api/settings")
    if verdict(bool(settings), f"{label} Settings backend starts", settings):
        _, text, _ = http(settings + "/api/settings")
        got = (json.loads(text or "{}").get("settings") or {}).get("text_scale")
        verdict(got == SCALE, f"{label} keeps the text size", f"text_scale {got}")
    notes = started(tok, "notes", "/api/notes")
    if verdict(bool(notes), f"{label} Notes backend starts", notes):
        made = (OUT / "note-id.txt").read_text().strip()
        _, text, _ = http(f"{notes}/api/note?id={urllib.parse.quote(made)}")
        _, listing, _ = http(notes + "/api/notes")
        verdict(
            MARK in text and made in listing,
            f"{label} keeps the note",
            f"id {made}: {one_line(text, 120)}",
        )


def update_path(old: Path, new: Path, version: str) -> None:
    install(old)
    if not verdict(open_app("old app"), "old app opens", "hub answered"):
        return
    save_things("old app")
    quit_app("old app", graded=False)
    install(new)
    if not verdict(open_app("new app"), "new app opens over the old one's data"):
        return
    _, ping, _ = http(HUB + "/forge/ping")
    verdict(f'"version": "{version}"' in ping, "new app's version", one_line(ping))
    _, _, where = http(HUB + "/hub/index.html")
    verdict(
        where.endswith("/hub/index.html"),
        "new app remembers the place (no welcome page)",
        where,
    )
    shown = wait_for(native_windows, 90, 3)
    screenshot("new-app-open")
    verdict(
        bool(shown),
        "a native Forge window is on screen",
        json.dumps(shown or []) + " (new-app-open.png)",
    )
    tok = token()
    _, text, _ = http(f"{HUB}/forge/update?t={tok}")
    (OUT / "update-state.json").write_text(text)
    verdict(
        "does not update itself" in text and "download page" in text,
        "Settings, Updates says to get the next version from the download page",
    )
    things_kept("new app", tok)
    screenshot("new-app-apps-open")
    quit_app("new app", graded=True)


# -- 4. a fresh install's every-app smoke ------------------------------------


def every_app() -> None:
    home = WORK / "home-fresh"
    home.mkdir(parents=True, exist_ok=True)
    step("every-app smoke (fresh home)")
    log = OUT / "smoke.log"
    with open(log, "w") as f:
        code = subprocess.run(
            [
                str(APP / "Contents/MacOS/Forge"),
                "--smoke",
                "--smoke-writes",
                "--window",
                "none",
                "--report",
                str(OUT / "smoke.json"),
            ],
            env={**os.environ, "HOME": str(home)},
            stdout=f,
            stderr=subprocess.STDOUT,
            timeout=2400,
        ).returncode
    stop_all()
    try:
        report = json.loads((OUT / "smoke.json").read_text())
    except (OSError, ValueError):
        report = {"results": []}
    rows = report.get("results") or []
    failed = [r for r in rows if not r.get("ok")]
    verdict(
        bool(code == 0 and rows and not failed),
        "every-app smoke with saving flows",
        f"{len(rows) - len(failed)} of {len(rows)} checks passed, exit {code}"
        + (f"; failed: {[r['check'] for r in failed][:12]}" if failed else ""),
    )
    shipped = sorted(
        p.parent.name
        for p in (APP / "Contents/Resources/forge/apps").glob("*/forge_app.json")
    )
    checked = {
        m.group(1) for r in rows if (m := re.fullmatch(r"app (\S+)", r["check"]))
    }
    logs = log.read_text(errors="replace")
    for extra in (home / "Library/Logs/Forge").glob("*.log"):
        logs += extra.read_text(errors="replace")
    skipped = set(re.findall(r"skip app (\S+): not for this computer", logs))
    missing = [n for n in shipped if n not in checked and n not in skipped]
    verdict(
        not missing,
        "every app in the bundle was smoke-checked",
        f"{len(shipped)} apps, {len(checked)} checked, {len(skipped)} not for this"
        f" computer {sorted(skipped)}, missing {missing}",
    )


# -- 5. the cryptography swap --------------------------------------------------

CRYPTO = r"""
import io, json, subprocess
import pypdf
from pypdf._crypt_providers import crypt_provider
import forge_devices
out = {"provider": list(crypt_provider)}
try:
    import cryptography
    out["cryptography"] = cryptography.__version__
except ImportError:
    out["cryptography"] = None
w = pypdf.PdfWriter()
w.add_blank_page(200, 200)
w.encrypt("pw-1391", algorithm="AES-256")
buf = io.BytesIO()
w.write(buf)
r = pypdf.PdfReader(io.BytesIO(buf.getvalue()))
out["pdf_locked"] = bool(r.is_encrypted)
out["pdf_wrong_password"] = int(r.decrypt("wrong"))
r = pypdf.PdfReader(io.BytesIO(buf.getvalue()))
out["pdf_opened"] = int(r.decrypt("pw-1391")) > 0 and len(r.pages) == 1
cert, key = forge_devices.ensure_cert()
text = subprocess.run(["openssl", "x509", "-in", str(cert), "-noout", "-text"],
                      capture_output=True, text=True).stdout
out["cert_p256"] = "prime256v1" in text or "P-256" in text
out["key_private"] = oct(key.stat().st_mode & 0o777)
print(json.dumps(out))
"""


def crypto_paths() -> None:
    forge = APP / "Contents/Resources/forge"
    folder = WORK / "devices-check"
    shutil.rmtree(folder, ignore_errors=True)
    done = run(
        [str(forge / "runtime/bin/python3"), "-c", CRYPTO],
        timeout=120,
        env={
            **os.environ,
            "PYTHONPATH": f"{forge / 'shared'}:{forge}",
            "FORGE_DEVICES_DIR": str(folder),
        },
    )
    try:
        got = json.loads(done.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        got = {}
    (OUT / "crypto.json").write_text(json.dumps(got, indent=2) + one_line(done.stderr))
    want = "48.0.1" if TARGET == "macos-x64" else "50.0.2"
    verdict(
        got.get("cryptography") == want,
        "the cryptography this Mac's download pins",
        f"{got.get('cryptography')} (pinned {want})",
    )
    verdict(
        bool(
            got.get("provider", [""])[0] == "cryptography"
            and got.get("pdf_locked")
            and got.get("pdf_wrong_password") == 0
            and got.get("pdf_opened")
        ),
        "password PDFs lock and open",
        json.dumps(got),
    )
    verdict(
        bool(got.get("cert_p256")) and got.get("key_private") == "0o600",
        "Devices makes its P-256 certificate",
        one_line(done.stderr, 200),
    )


# -- 6. for information --------------------------------------------------------


def quarantined_open(app: Path) -> None:
    """What a person who skips the README's step sees: the downloaded,
    still-flagged app double-clicked."""
    step("quarantined open")
    copy = WORK / "q/Forge.app"
    run(["ditto", str(app), str(copy)], timeout=900)
    quarantine(copy)
    done = run(["open", str(copy)], timeout=60)
    time.sleep(15)
    screenshot("quarantined-open")
    note(
        "INFO",
        "quarantined app opened directly",
        f"open exit {done.returncode}; Forge "
        + ("started (Gatekeeper let it)" if hub_up() else "did not start")
        + " (quarantined-open.png)",
    )
    stop_all()
    run(["pkill", "-f", "CoreServicesUIAgent"], timeout=10)


ENTITLEMENTS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>
<key>com.apple.security.cs.disable-library-validation</key><true/>
</dict></plist>
"""


def hardened_signature() -> None:
    step("ad hoc hardened signature")
    signed = WORK / "signed/Forge.app"
    run(["ditto", str(APP), str(signed)], timeout=900)
    ent = WORK / "ent.plist"
    ent.write_text(ENTITLEMENTS)
    sign = ["codesign", "--force", "-s", "-", "--options", "runtime"]
    for path in signed.rglob("*"):
        if path.is_file() and not path.is_symlink():
            with open(path, "rb") as f:
                if f.read(4) in MACHO:
                    run([*sign, "--entitlements", str(ent), str(path)], timeout=60)
    run([*sign, "--entitlements", str(ent), str(signed)], timeout=300)
    strict = run(
        ["codesign", "--verify", "--deep", "--strict", str(signed)], timeout=600
    )
    home = WORK / "home-signed"
    home.mkdir(parents=True, exist_ok=True)
    smoke = run(
        [
            str(signed / "Contents/MacOS/Forge"),
            "--smoke",
            "--window",
            "none",
            "--apps",
            "notes,office,files,pdf,devices",
            "--report",
            str(OUT / "smoke-hardened.json"),
        ],
        timeout=900,
        env={**os.environ, "HOME": str(home)},
    )
    stop_all()
    note(
        "INFO",
        "ad hoc hardened-runtime signature (Developer ID's shape)",
        f"verify exit {strict.returncode}, smoke of 5 apps exit {smoke.returncode}",
    )


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    plan = json.loads((HERE / "expected.json").read_text())[TARGET]
    product = run(["sw_vers"], timeout=20).stdout
    note(
        "INFO",
        "runner",
        f"{TARGET} on {one_line(product)}, {ARCH},"
        f" Gatekeeper {one_line(run(['spctl', '--status'], timeout=20).stdout)}",
    )
    new = fetch(plan["new"], WORK / "new")
    old = fetch(plan["old"], WORK / "old")
    run(["tar", "-xzf", str(old), "-C", str(old.parent)], timeout=900)
    app = unpack_like_finder(new)
    file_checks(app)
    stop_all()
    update_path(old.parent / "Forge/Forge.app", app, plan["new"]["version"])
    stop_all()
    install(app)
    crypto_paths()
    every_app()
    quarantined_open(app)
    hardened_signature()
    for log in (Path.home() / "Library/Logs/Forge").glob("*.log"):
        shutil.copy(log, OUT / f"user-{log.name}")
    lines = (OUT / "results.txt").read_text().splitlines()
    fails = [line for line in lines if line.startswith("FAIL")]
    note("INFO", "done", f"{len(fails)} failed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
