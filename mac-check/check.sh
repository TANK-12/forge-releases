#!/bin/bash
# Real-Mac checks of one Forge Mac download: unpack it the way Finder does,
# what Gatekeeper says, the README's quarantine step, every app's smoke
# check, the window, a read-only .dmg and an ad hoc hardened signature.
# Results: out/results.txt (PASS/FAIL/INFO lines) plus logs and screenshots.
set -u
target=$1
tag=$(cat mac-check/tag.txt)
out=$PWD/out
mkdir -p "$out"
res=$out/results.txt
note() { echo "$*" | tee -a "$res"; }
limit() { perl -e 'alarm shift; exec @ARGV' "$@"; }
check() {
    name=$1
    shift
    if "$@" >"$out/$name.log" 2>&1; then note "PASS $name"; else note "FAIL $name (exit $?)"; fi
}
wait_port() {
    for _ in $(seq 1 "$2"); do
        curl -s -o /dev/null "http://127.0.0.1:$1/" && return 0
        sleep 1
    done
    return 1
}
stop_forge() {
    pkill -f "[f]orge_portable.py" || true
    for _ in $(seq 1 30); do pgrep -f "[f]orge_portable.py|[u]vicorn" >/dev/null || return 0; sleep 1; done
    note "INFO still running after stop: $(pgrep -fl '[f]orge_portable.py|[u]vicorn' | head -5)"
    pkill -9 -f "[f]orge_portable.py|[u]vicorn" || true
}
note "INFO target $target, release $tag, $(sw_vers -productName) $(sw_vers -productVersion), $(uname -m)"
note "INFO gatekeeper: $(spctl --status 2>&1)"
work=$RUNNER_TEMP/forge
mkdir -p "$work"
cd "$work"
gh release download "$tag" -R "$GITHUB_REPOSITORY" -p "forge-*-$target.tar.gz" || { note "FAIL download"; exit 1; }
tarball=$(ls forge-*-"$target".tar.gz)
note "INFO $tarball $(stat -f %z "$tarball") bytes"
# what Safari puts on a download
xattr -w com.apple.quarantine "0083;$(printf %x "$(date +%s)");Safari;$(uuidgen)" "$tarball"

# 1. unpack with Archive Utility, as a double-click in Finder does
open -a "Archive Utility" "$tarball"
for _ in $(seq 1 300); do [ -x Forge/Forge.app/Contents/MacOS/Forge ] && break; sleep 1; done
sleep 20  # let it finish writing
if [ -d Forge/Forge.app ]; then
    note "PASS unpack-archive-utility"
else
    note "FAIL unpack-archive-utility, falling back to tar"
    tar -xzf "$tarball"
    xattr -r -w com.apple.quarantine "0083;$(printf %x "$(date +%s)");Safari;$(uuidgen)" Forge
fi
app=$work/Forge/Forge.app
note "INFO quarantine on the app's launcher: $(xattr -p com.apple.quarantine "$app/Contents/MacOS/Forge" 2>&1)"
note "INFO quarantine on runtime python: $(xattr -p com.apple.quarantine "$app/Contents/Resources/forge/runtime/bin/python3" 2>&1)"
check plist plutil -lint "$app/Contents/Info.plist"
ls -la "$app/Contents" "$app/Contents/MacOS" >"$out/layout.log" 2>&1

# 2. signatures of every Mach-O file (Apple silicon kills an unsigned one)
total=0 bad=0
while IFS= read -r -d '' f; do
    if file -b "$f" | grep -q "Mach-O"; then
        total=$((total + 1))
        codesign -v "$f" >/dev/null 2>&1 || { bad=$((bad + 1)); echo "$f" >>"$out/macho-unsigned.log"; }
        lipo -archs "$f" >>"$out/macho-archs.log" 2>&1
    fi
done < <(find "$app" -type f -print0)
note "INFO Mach-O files: $total, without a valid signature: $bad"
sort "$out/macho-archs.log" | uniq -c >"$out/macho-archs-count.log"
spctl -a -vv -t exec "$app" >"$out/spctl.log" 2>&1
note "INFO spctl on the app: $(tr '\n' ' ' <"$out/spctl.log")"
if command -v syspolicy_check >/dev/null; then
    syspolicy_check distribution "$app" >"$out/syspolicy-distribution.log" 2>&1
    note "INFO syspolicy_check distribution exit $? (log: syspolicy-distribution.log)"
fi

# 3. drag to Applications (Finder keeps the quarantine flag), then start it still quarantined
ditto "$app" /Applications/Forge.app
open /Applications/Forge.app
if wait_port 8400 90; then note "PASS gui-open-quarantined (hub answered)"; else note "FAIL gui-open-quarantined (no hub in 90 s)"; fi
sleep 15
screencapture -x "$out/1-quarantined-open.png" || note "INFO screencapture failed"
stop_forge

# 4. the README's step, then every app's smoke check
xattr -dr com.apple.quarantine /Applications/Forge.app
note "INFO quarantine left after xattr -dr: $(xattr -lr /Applications/Forge.app 2>/dev/null | grep -c quarantine)"
mkdir -p "$work/home-smoke"
check smoke env HOME="$work/home-smoke" limit 2400 /Applications/Forge.app/Contents/MacOS/Forge --smoke --report "$out/smoke.json"
tail -5 "$out/smoke.log" | sed 's/^/INFO smoke: /' >>"$res"

# 5. open it as a user does: the window, the hub, the welcome page
open /Applications/Forge.app
if wait_port 8400 90; then note "PASS gui-open"; else note "FAIL gui-open (no hub in 90 s)"; fi
sleep 25
screencapture -x "$out/2-open.png" || true
osascript -e 'tell application "System Events" to get name of every process whose background only is false' >"$out/gui-processes.log" 2>&1
note "INFO visible processes: $(cat "$out/gui-processes.log")"
pgrep -fl "[f]orge_portable|[w]ebview|[C]hrome" >"$out/gui-ps.log" 2>&1
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8400/ >"$out/hub-code.log"
note "INFO hub / answered $(cat "$out/hub-code.log")"
osascript -e 'tell application "System Events" to keystroke "q" using command down' >/dev/null 2>&1
sleep 10
if pgrep -f "[f]orge_portable.py" >/dev/null; then note "INFO still running 10 s after Cmd-Q"; else note "PASS quit-with-cmd-q (no Forge process left)"; fi
pgrep -fl "[u]vicorn" >"$out/after-quit-backends.log" && note "FAIL backends left after quit" || note "PASS no backends left after quit"
stop_forge
cp ~/Library/Logs/Forge/*.log "$out/" 2>/dev/null || true

# 6. a read-only .dmg with an Applications link, started from the mounted image
mkdir -p "$work/dmgsrc"
ditto /Applications/Forge.app "$work/dmgsrc/Forge.app"
ln -s /Applications "$work/dmgsrc/Applications"
check dmg-create hdiutil create -volname Forge -srcfolder "$work/dmgsrc" -format UDZO -ov "$work/Forge.dmg"
note "INFO dmg $(stat -f %z "$work/Forge.dmg" 2>/dev/null) bytes"
mnt=$(hdiutil attach -nobrowse -readonly "$work/Forge.dmg" | awk -F'\t' '/\/Volumes\//{print $NF}')
note "INFO dmg mounted at $mnt"
mkdir -p "$work/home-dmg"
check smoke-from-dmg env HOME="$work/home-dmg" limit 900 "$mnt/Forge.app/Contents/MacOS/Forge" --smoke --apps notes,office,files --report "$out/smoke-dmg.json"
hdiutil detach "$mnt" >/dev/null 2>&1 || true

# 7. ad hoc signature with the hardened runtime and Forge's entitlements
cat >"$work/ent.plist" <<'P'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>
<key>com.apple.security.cs.disable-library-validation</key><true/>
</dict></plist>
P
signed=$work/signed/Forge.app
mkdir -p "$work/signed"
ditto /Applications/Forge.app "$signed"
find "$signed" -type f -print0 | while IFS= read -r -d '' f; do
    file -b "$f" | grep -q Mach-O && codesign --force -s - --options runtime --entitlements "$work/ent.plist" "$f" >>"$out/sign.log" 2>&1
done
check sign-app codesign --force -s - --options runtime --entitlements "$work/ent.plist" "$signed"
check sign-verify codesign --verify --deep --strict --verbose=2 "$signed"
mkdir -p "$work/home-signed"
check smoke-hardened env HOME="$work/home-signed" limit 900 "$signed/Contents/MacOS/Forge" --smoke --apps notes,office,files,media,convert --report "$out/smoke-hardened.json"
note "INFO done"
