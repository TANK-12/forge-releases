$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$here = Join-Path $PWD 'win-tt-pack-check'
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
if (-not $rel) { Note "FAIL download ($tag release not found)"; exit 1 }
foreach ($pat in @('*-windows-x64.zip', 'SHA256SUMS')) {
  $a = $rel.assets | Where-Object { $_.name -like $pat } | Select-Object -First 1
  if (-not $a) { Note "FAIL download (no $pat in $tag)"; exit 1 }
  Invoke-WebRequest -Headers @{Authorization = "Bearer $env:GH_TOKEN"; Accept = 'application/octet-stream'} -Uri $a.url -OutFile $a.name
  Note "INFO $($a.name) $((Get-Item $a.name).Length) bytes"
}
$zip = (Get-ChildItem '*-windows-x64.zip')[0]
$want = (Get-Content 'SHA256SUMS' | Where-Object { $_ -match "  $([regex]::Escape($zip.Name))$" }) -replace '  .*$', ''
if ((Get-FileHash $zip.FullName).Hash.ToLower() -eq $want) { Note "PASS checksum $($zip.Name)" } else { Note "FAIL checksum $($zip.Name)"; exit 1 }
Expand-Archive -Path $zip.FullName -DestinationPath (Join-Path $work 'zip') -Force
$forge = (Get-ChildItem (Join-Path $work 'zip') -Recurse -Filter 'forge-console.cmd' | Select-Object -First 1).DirectoryName
if (-not $forge) { Note "FAIL unzip (no forge-console.cmd)"; exit 1 }
Note "PASS unzip ($forge)"
$overlay = Join-Path $here 'overlay'
Get-ChildItem $overlay -Recurse -File | ForEach-Object {
  $relp = $_.FullName.Substring($overlay.Length + 1)
  $dst = Join-Path $forge $relp
  New-Item -ItemType Directory -Force (Split-Path $dst) | Out-Null
  Copy-Item $_.FullName $dst -Force
  Note "INFO overlay $relp"
}
$env:PYTHONDONTWRITEBYTECODE = '1'
& (Join-Path $forge 'runtime\python.exe') -B (Join-Path $here 'tt_win_check.py') --forge $forge --fixtures (Join-Path $here 'fixtures') --work (Join-Path $work 'tt') --out $out 2>&1 | Tee-Object -FilePath (Join-Path $out 'tt_win_check.log')
$code = $LASTEXITCODE
if (Test-Path (Join-Path $out 'check_results.txt')) { Get-Content (Join-Path $out 'check_results.txt') | Add-Content $res }
Note "INFO tt_win_check exit $code"
exit $code
