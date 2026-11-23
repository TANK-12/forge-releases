# Real-Windows checks of one Forge Windows release (Relay task 1155): the zip unpacked
# as Explorer does, Forge's own --smoke of every app, then the setup run silently for
# this user and --smoke of the installed copy. Results: out/results.txt (PASS/FAIL/INFO).
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$tag = (Get-Content win-check/tag.txt -TotalCount 1).Trim()
$out = Join-Path $PWD 'out'
New-Item -ItemType Directory -Force $out | Out-Null
$res = Join-Path $out 'results.txt'
function Note($t) { $t | Tee-Object -FilePath $res -Append }
$os = (Get-CimInstance Win32_OperatingSystem)
Note "INFO release $tag, $($os.Caption) $($os.Version), $([math]::Round($os.TotalVisibleMemorySize/1MB,1)) GB RAM"
$work = Join-Path $env:RUNNER_TEMP 'forge'
New-Item -ItemType Directory -Force $work | Out-Null
Set-Location $work
# one release object per line (a draft has no tag yet, so look it up in the list)
$ready = $false
for ($attempt = 0; $attempt -lt 60; $attempt++) {
  $rel = gh api --paginate "repos/$env:GITHUB_REPOSITORY/releases?per_page=100" --jq '.[]' | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.tag_name -eq $tag } | Select-Object -First 1
  $ready = $true
  foreach ($pattern in @('*-windows-x64.zip', 'Forge-Setup-*.exe', 'Forge-Web-Setup-*.exe', 'SHA256SUMS')) {
    if (-not ($rel.assets | Where-Object { $_.name -like $pattern -and $_.state -eq 'uploaded' })) { $ready = $false }
  }
  if ($ready) { break }
  Note "INFO waiting for completed draft uploads ($attempt)"
  Start-Sleep 20
}
if (-not $ready) { Note "FAIL draft assets did not finish uploading"; exit 1 }
if (-not $rel) { Note "FAIL download (no release $tag)"; exit 1 }
foreach ($pat in @('*-windows-x64.zip', 'Forge-Setup-*.exe', 'Forge-Web-Setup-*.exe', 'SHA256SUMS')) {
  $a = $rel.assets | Where-Object { $_.name -like $pat } | Select-Object -First 1
  if (-not $a) { Note "FAIL download (no $pat in $tag)"; exit 1 }
  Invoke-WebRequest -Headers @{Authorization = "Bearer $env:GH_TOKEN"; Accept = 'application/octet-stream'} -Uri $a.url -OutFile $a.name
  Note "INFO $($a.name) $((Get-Item $a.name).Length) bytes, sha256 $((Get-FileHash $a.name).Hash.ToLower())"
}
foreach ($line in Get-Content 'SHA256SUMS') {
  if ($line -match '^([0-9a-f]{64})  (.+)$' -and (Test-Path $Matches[2])) {
    $expected = $Matches[1]; $file = $Matches[2]
    if ((Get-FileHash $file).Hash.ToLower() -eq $expected) { Note "PASS checksum $file" }
    else { Note "FAIL checksum $file"; exit 1 }
  }
}
$zip = (Get-ChildItem '*-windows-x64.zip')[0].FullName
$setup = (Get-ChildItem 'Forge-Setup-*.exe')[0].FullName
# 1. unzip as Explorer does (Mark of the Web on the zip first)
Set-Content -Path "$zip`:Zone.Identifier" -Value "[ZoneTransfer]`r`nZoneId=3"
Expand-Archive -Path $zip -DestinationPath (Join-Path $work 'zip') -Force
$z = Get-ChildItem (Join-Path $work 'zip') -Recurse -Filter 'forge-console.cmd' | Select-Object -First 1
if ($z) { Note "PASS unzip ($($z.DirectoryName))" } else { Note "FAIL unzip (no forge-console.cmd)"; exit 1 }
function Smoke($name, $dir, $data) {
  $env:PYTHONDONTWRITEBYTECODE = '1'
  $p = Start-Process -FilePath (Join-Path $dir 'runtime\python.exe') -ArgumentList @('-B', "`"$(Join-Path $dir 'forge_portable.py')`"", '--smoke', '--data', "`"$data`"", '--report', "`"$out\$name-report.json`"") -WorkingDirectory $dir -NoNewWindow -PassThru -RedirectStandardOutput "$out\$name.log" -RedirectStandardError "$out\$name.err"
  if (-not $p.WaitForExit(2400000)) { $p.Kill($true); Note "FAIL $name (timed out after 40 min)"; return }
  $tail = (Get-Content "$out\$name.log" -Tail 3) -join ' | '
  if ($p.ExitCode -eq 0) { Note "PASS $name ($tail)" } else { Note "FAIL $name (exit $($p.ExitCode); $tail)" }
}
# 2. every app's smoke check from the unzipped copy
Smoke 'smoke-zip' $z.DirectoryName (Join-Path $work 'data-zip')
$sentinels = @((Join-Path $env:APPDATA 'Forge\release-check-sentinel.txt'), (Join-Path $env:LOCALAPPDATA 'Forge\release-check-sentinel.txt'))
foreach ($file in $sentinels) { New-Item -ItemType Directory -Force (Split-Path $file) | Out-Null; Set-Content $file 'preserve-existing-data-1381' }
function CheckData($label) {
  foreach ($file in $sentinels) {
    if ((Test-Path $file) -and (Get-Content $file -Raw).Trim() -eq 'preserve-existing-data-1381') { Note "PASS $label preserves $file" }
    else { Note "FAIL $label lost existing data: $file" }
  }
}
# 3. the setup, silent, for this user only, then smoke the installed copy
$dest = Join-Path $env:LOCALAPPDATA 'Programs\ForgeCheck'
$i = Start-Process -FilePath $setup -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/DIR=`"$dest`"", "/LOG=`"$out\setup.log`"") -PassThru -Wait
if ($i.ExitCode -eq 0 -and (Test-Path (Join-Path $dest 'forge_portable.py'))) { Note "PASS setup (exit 0, $dest)" } else { Note "FAIL setup (exit $($i.ExitCode))"; exit 1 }
$lnk = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Forge.lnk") | Where-Object { Test-Path $_ }
Note "INFO start menu shortcut: $(if ($lnk) { 'present' } else { 'missing' })"
CheckData 'full setup'
Smoke 'smoke-installed' $dest (Join-Path $work 'data-installed')
$u = Get-ChildItem $dest -Filter 'unins*.exe' | Select-Object -First 1
if ($u) {
  $x = Start-Process -FilePath $u.FullName -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') -PassThru -Wait
  Start-Sleep 5
  if (-not (Test-Path (Join-Path $dest 'forge_portable.py'))) { Note "PASS uninstall (exit $($x.ExitCode))" } else { Note "FAIL uninstall (files left, exit $($x.ExitCode))" }
} else { Note "FAIL uninstall (no unins*.exe)" }
CheckData 'uninstall'
$web = (Get-ChildItem 'Forge-Web-Setup-*.exe')[0].FullName
$webdest = Join-Path $env:LOCALAPPDATA 'Programs\ForgeWebCheck'
$i = Start-Process -FilePath $web -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/DIR=`"$webdest`"", "/LOG=`"$out\web-setup.log`"") -PassThru -Wait
if ($i.ExitCode -eq 0 -and (Test-Path (Join-Path $webdest 'forge_portable.py'))) { Note "PASS web setup (exit 0)" }
else { Note "FAIL web setup (exit $($i.ExitCode))"; exit 1 }
CheckData 'web setup'
Smoke 'smoke-web-installed' $webdest (Join-Path $work 'data-web-installed')
if (Select-String -Path $res -Pattern '^FAIL' -Quiet) { exit 1 }
