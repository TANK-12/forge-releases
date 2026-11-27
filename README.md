# win-pack-check (test-only branch)

Checks Forge Pack's exact PNG recipes on GitHub's Windows runner (Relay task 1578):
Windows' Python 3.14 is built with zlib-ng, so Pack re-deflates PNG recipes with a
pinned classic zlib1.dll instead. `win-pack-check/pack-check.ps1` unzips the Forge
Windows download named in `win-pack-check/tag.txt`, lays the fixed files from
`win-pack-check/overlay/` over it and runs `pack_check.py` with Forge's own runtime.
Results are in the `win-pack-check` artifact (`results.txt`). Nothing here touches
`main`, `win-check` or the download page.
