"""Outside programs Forge apps run (yt-dlp, ffmpeg, ffprobe), found or fetched.

A program on PATH is used as it is. Otherwise, on a system that
forge_tools.json names a build for, Forge fetches that build once (pinned by
sha256 through forge_fetch) into its own tools folder and uses it from there,
so a person on Windows never has to install yt-dlp or ffmpeg by hand. A
system with no build gets the install words from the json instead.

find() never fetches (status checks stay quick); ensure() fetches when
needed. path_dirs() lists the folders the fetched programs sit in: the
launcher adds them to the end of every app's PATH, so an app that runs a bare
"ffmpeg" finds the fetched copy once it is there, and a copy the person
installed themselves still wins.

Adding a program is one entry in forge_tools.json; nothing here names one.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path
from collections.abc import Callable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import forge_fetch  # noqa: E402
import forge_platform  # noqa: E402

REGISTRY = HERE / "forge_tools.json"
FetchError = forge_fetch.FetchError

# a failed first-use fetch is not tried again for this long: an offline
# computer would otherwise wait on the download for every file or request
RETRY_SECONDS = 300
_failed: dict[tuple[str, str], tuple[float, str]] = {}
# another Forge app fetching the same package: wait this long for it at most
LOCK_WAIT_SECONDS = 1800


class ToolMissing(FetchError):
    """The program is not here and cannot be fetched for this system."""


def registry() -> dict:
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


def tools_dir(env=None) -> Path:
    """Where fetched programs live: FORGE_TOOLS_DIR, else "tools" in Forge's
    cache folder (FORGE_CACHE, which a release always sets), else the cache
    folder a release would use on this system."""
    env = os.environ if env is None else env
    if env.get("FORGE_TOOLS_DIR"):
        return Path(env["FORGE_TOOLS_DIR"])
    if env.get("FORGE_CACHE"):
        return Path(env["FORGE_CACHE"]) / "tools"
    home = Path.home()
    if sys.platform == "win32":
        local = env.get("LOCALAPPDATA") or str(home / "AppData" / "Local")
        return Path(local) / "Forge" / "Cache" / "tools"
    if sys.platform == "darwin":
        return home / "Library" / "Caches" / "Forge" / "tools"
    cache = env.get("XDG_CACHE_HOME") or str(home / ".cache")
    return Path(cache) / "forge" / "tools"


def _package_of(program: str, reg: dict, system: str) -> tuple[str, dict] | None:
    """(package id, this system's build) of the package holding `program`."""
    for pid, pkg in reg.get("packages", {}).items():
        build = pkg.get("systems", {}).get(system)
        if build and program in build.get("programs", {}):
            return pid, {"version": pkg["version"], "name": pkg["label"], **build}
    return None


def _place(pid: str, build: dict, program: str, root: Path) -> Path:
    return root / pid / build["programs"][program]


def _is_fetched(pid: str, build: dict, root: Path) -> bool:
    folder = root / pid
    if "file" in build:
        stamp = folder / f"{build['file']}.version"
    else:
        stamp = folder / ".version"
    return stamp.is_file() and stamp.read_text().strip() == build["version"]


def _inside(path: str, root: Path) -> bool:
    """True when `path` is in Forge's tools folder (compared without case on
    Windows, where C:\\Users and c:\\users are one folder)."""
    a = os.path.normcase(os.path.abspath(path))
    b = os.path.normcase(os.path.abspath(root))
    return a == b or a.startswith(b.rstrip(os.sep) + os.sep)


def find(program: str, env=None, system: str | None = None) -> str | None:
    """The program to run: the one on PATH, else Forge's fetched copy when it
    is there and of the pinned version, else None. Never fetches."""
    root = tools_dir(env)
    on_path = shutil.which(program)
    # the launcher puts the tools folder on PATH, so a copy found there is
    # Forge's own: it only counts when its version stamp is the pinned one
    # (an old yt-dlp left behind by an earlier Forge must be replaced)
    if on_path and not _inside(on_path, root):
        return on_path
    got = _package_of(program, registry(), system or forge_fetch.this_system())
    if not got:
        return None
    pid, build = got
    exe = _place(pid, build, program, root)
    if _is_fetched(pid, build, root) and exe.is_file():
        return str(exe)
    return None


def can_fetch(program: str, system: str | None = None) -> bool:
    """True when Forge has a build of `program` for this system to fetch."""
    return (
        _package_of(program, registry(), system or forge_fetch.this_system())
        is not None
    )


def forget_failure(program: str, env=None) -> None:
    """Drop the remembered failed fetch of `program`, so the next ensure()
    tries again at once (a person asked, not a loop)."""
    got = _package_of(program, registry(), forge_fetch.this_system())
    if got:
        _failed.pop((got[0], str(tools_dir(env))), None)


def ensure(
    program: str,
    env=None,
    system: str | None = None,
    get: Callable[[str], bytes] | None = None,
    say: Callable[[str], None] | None = None,
) -> str:
    """The program to run, fetched into Forge's tools folder the first time
    when it is not on PATH. Raises ToolMissing with the install words when
    this system has no build, FetchError when the fetch fails."""
    found = find(program, env, system)
    if found:
        return found
    got = _package_of(program, registry(), system or forge_fetch.this_system())
    if not got:
        raise ToolMissing(f"{program} is not installed ({install_hint(program)})")
    pid, build = got
    root = tools_dir(env)
    key = (pid, str(root))
    last = _failed.get(key)
    if last and time.time() - last[0] < RETRY_SECONDS:
        raise FetchError(last[1])
    try:
        with _Claim(root / f".{pid}.lock"):
            _fetch(pid, build, root, get, say)
    except FetchError as e:
        _failed[key] = (time.time(), str(e))
        raise
    except OSError as e:  # a full disk, or Windows holding a file open
        msg = f"could not set up {build['name']} in {root}: {e.strerror or e}"
        _failed[key] = (time.time(), msg)
        raise FetchError(msg) from None
    _failed.pop(key, None)
    exe = _place(pid, build, program, root)
    if not exe.is_file():
        raise FetchError(f"{program} was not in the {build['name']} download")
    if build.get("library"):  # loaded in-process (ctypes), not put on PATH
        return str(exe)
    if os.name != "nt":
        exe.chmod(exe.stat().st_mode | 0o755)
    # a bare "ffmpeg" in this app, and yt-dlp looking for ffmpeg, now find it
    # even where the launcher did not add the folder (an app run on its own)
    have = os.environ.get("PATH", "").split(os.pathsep)
    if str(exe.parent) not in have:
        os.environ["PATH"] = os.pathsep.join([*have, str(exe.parent)])
    return str(exe)


def _fetch(pid: str, build: dict, root: Path, get, say) -> None:
    folder = root / pid
    if _is_fetched(pid, build, root):  # another app fetched it meanwhile
        return
    if "file" in build:
        forge_fetch.pinned_file(build, folder / build["file"], get=get, say=say)
    else:
        forge_fetch.pinned_archive(build, folder, get=get, say=say)


class _Claim:
    """A lock shared by every Forge app (each its own process): only one
    fetches a package at a time, the others wait and then find it there.
    It is an operating system lock on the claim file, so it goes with its
    holder's process (a closed or crashed app frees it at once) and two
    waiters can never both take it. The file itself stays, empty."""

    def __init__(self, path: Path):
        self.path = path
        self._fh = None

    def __enter__(self) -> _Claim:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.time() + LOCK_WAIT_SECONDS
        while True:
            fh = open(self.path, "a+b")
            if forge_platform.try_lock(fh):
                self._fh = fh
                return self
            fh.close()
            if time.time() > deadline:
                raise FetchError(
                    "another Forge app is still fetching it; try again later"
                ) from None
            time.sleep(0.5)

    def __exit__(self, *exc) -> None:
        if self._fh is not None:
            forge_platform.unlock(self._fh)
            self._fh.close()
            self._fh = None


def download_bytes(program: str, system: str | None = None) -> int:
    """How big the first-use fetch of `program` is (0 when there is none)."""
    got = _package_of(program, registry(), system or forge_fetch.this_system())
    return int(got[1].get("bytes", 0)) if got else 0


def path_dirs(env=None, system: str | None = None) -> list[str]:
    """The folders this system's fetched programs sit in (whether fetched yet
    or not), for the end of an app's PATH."""
    system = system or forge_fetch.this_system()
    root = tools_dir(env)
    out: list[str] = []
    for pid, pkg in registry().get("packages", {}).items():
        build = pkg.get("systems", {}).get(system)
        if (build or {}).get("library"):  # loaded in-process, never run
            continue
        for rel in (build or {}).get("programs", {}).values():
            folder = str((root / pid / rel).parent)
            if folder not in out:
                out.append(folder)
    return out


def with_path(env: dict, system: str | None = None) -> dict:
    """`env` with path_dirs() added to the end of its PATH."""
    dirs = path_dirs(env, system)
    have = env.get("PATH", "").split(os.pathsep) if env.get("PATH") else []
    env["PATH"] = os.pathsep.join(have + [d for d in dirs if d not in have])
    return env


def install_hint(program: str, system: str | None = None) -> str:
    """How a person gets `program` on this system: "Forge fetches it on first
    use" when there is a build here, else the install words from the json."""
    system = system or forge_fetch.this_system()
    if can_fetch(program, system):
        return "Forge fetches it the first time it is needed"
    words = registry().get("install", {}).get(program, {})
    return words.get(system.split("-")[0]) or f"install {program}"


def status(programs: list[str], env=None, system: str | None = None) -> dict:
    """{program: {"found": path or None, "fetchable": bool, "hint": str}}
    for a settings or status page."""
    return {
        p: {
            "found": find(p, env, system),
            "fetchable": can_fetch(p, system),
            "hint": install_hint(p, system),
        }
        for p in programs
    }
