# Pack's exact PNG recipes on real Windows (Relay task 1578): the Forge Windows zip named in
# tag.txt, unzipped as Explorer does, task 1578's files from overlay\ laid over it, then
# pack_check.py run by Forge's own runtime. Results: out/results.txt (PASS/FAIL/INFO).
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$here = Join-Path $PWD 'win-pack-check'
$tag = (Get-Content (Join-Path $here 'tag.txt') -TotalCount 1).Trim()
$out = Join-Path $PWD 'out'
New-Item -ItemType Directory -Force $out | Out-Null
$res = Join-Path $out 'results.txt'
function Note($t) { $t | Tee-Object -FilePath $res -Append }
$os = Get-CimInstance Win32_OperatingSystem
Note "INFO release $tag, $($os.Caption) $($os.Version)"
$work = Join-Path $env:RUNNER_TEMP 'forge'
New-Item -ItemType Directory -Force $work | Out-Null
Set-Location $work
$rel = gh api --paginate "repos/$env:GITHUB_REPOSITORY/releases?per_page=100" --jq '.[]' | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.tag_name -eq $tag } | Select-Object -First 1
if (-not $rel) { Note "FAIL download (no release $tag)"; exit 1 }
foreach ($pat in @('*-windows-x64.zip', 'SHA256SUMS')) {
  $a = $rel.assets | Where-Object { $_.name -like $pat } | Select-Object -First 1
  if (-not $a) { Note "FAIL download (no $pat in $tag)"; exit 1 }
  Invoke-WebRequest -Headers @{Authorization = "Bearer $env:GH_TOKEN"; Accept = 'application/octet-stream'} -Uri $a.url -OutFile $a.name
  Note "INFO $($a.name) $((Get-Item $a.name).Length) bytes, sha256 $((Get-FileHash $a.name).Hash.ToLower())"
}
$zip = (Get-ChildItem '*-windows-x64.zip')[0]
$want = (Get-Content 'SHA256SUMS' | Where-Object { $_ -match "  $([regex]::Escape($zip.Name))$" }) -replace '  .*$', ''
if ((Get-FileHash $zip.FullName).Hash.ToLower() -eq $want) { Note "PASS checksum $($zip.Name)" } else { Note "FAIL checksum $($zip.Name)"; exit 1 }
Set-Content -Path "$($zip.FullName):Zone.Identifier" -Value "[ZoneTransfer]`r`nZoneId=3"
Expand-Archive -Path $zip.FullName -DestinationPath (Join-Path $work 'zip') -Force
$forge = (Get-ChildItem (Join-Path $work 'zip') -Recurse -Filter 'forge-console.cmd' | Select-Object -First 1).DirectoryName
if (-not $forge) { Note "FAIL unzip (no forge-console.cmd)"; exit 1 }
Note "PASS unzip ($forge)"
$overlay = Join-Path $here 'overlay'
Get-ChildItem $overlay -Recurse -File | ForEach-Object {
  $rel = $_.FullName.Substring($overlay.Length + 1)
  $dst = Join-Path $forge $rel
  New-Item -ItemType Directory -Force (Split-Path $dst) | Out-Null
  Copy-Item $_.FullName $dst -Force
  Note "INFO overlay $rel sha256 $((Get-FileHash $dst).Hash.ToLower().Substring(0, 16))"
}
$env:PYTHONDONTWRITEBYTECODE = '1'
& (Join-Path $forge 'runtime\python.exe') -B (Join-Path $here 'pack_check.py') --forge $forge --work (Join-Path $work 'pc') --out (Join-Path $out 'pc') 2>&1 | Tee-Object -FilePath (Join-Path $out 'pack_check.log')
$code = $LASTEXITCODE
if (Test-Path (Join-Path $out 'pc\results.txt')) { Get-Content (Join-Path $out 'pc\results.txt') | Add-Content $res }
Note "INFO pack_check exit $code"
exit $code
