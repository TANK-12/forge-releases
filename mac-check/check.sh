#!/bin/bash
# Real-Mac checks of one Forge Mac download: unpack it the way Finder does,
# what Gatekeeper says, the README's quarantine step, every app's smoke
# check, the window, a read-only .dmg and an ad hoc hardened signature.
# Results: out/results.txt (PASS/FAIL/INFO lines) plus logs and screenshots.
set -u
target=$1
# tag.txt: one line per target, "<target> <release tag>"
tag=$(awk -v t="$target" '$1 == t {print $2}' mac-check/tag.txt)
out=$PWD/out
mkdir -p "$out"
res=$out/results.txt
note() { echo "$*" | tee -a "$res"; }
step() { echo "[$(date -u +%H:%M:%S)] $*"; }
limit() { perl -e 'alarm shift; exec @ARGV' "$@"; }
check() {
    name=$1
    shift
    if "$@" >"$out/$name.log" 2>&1; then note "PASS $name"; else note "FAIL $name (exit $?)"; fi
}
wait_port() {
    for _ in $(seq 1 "$2"); do
        curl -s --max-time 3 -o /dev/null "http://127.0.0.1:$1/" && return 0
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
if ! gh release download "$tag" -R "$GITHUB_REPOSITORY" -p "forge-*-$target.tar.gz"; then
    # a draft has no tag yet: find it in the list of releases
    asset=$(gh api --paginate "repos/$GITHUB_REPOSITORY/releases" --jq ".[] | select(.tag_name == \"$tag\") | .assets[] | select(.name | endswith(\"-$target.tar.gz\")) | \"\(.id) \(.name)\"" | head -1)
    [ -n "$asset" ] || { note "FAIL download (no $target asset in $tag)"; exit 1; }
    gh api -H "Accept: application/octet-stream" "repos/$GITHUB_REPOSITORY/releases/assets/${asset%% *}" >"${asset#* }" || { note "FAIL download"; exit 1; }
fi
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
icon=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIconFile" "$app/Contents/Info.plist" 2>/dev/null)
if [ -n "$icon" ]; then
    check icon-iconutil iconutil -c iconset -o "$out/forge.iconset" "$app/Contents/Resources/$icon.icns"
    limit 60 sips -s format png "$app/Contents/Resources/$icon.icns" --out "$out/icon-from-icns.png" >/dev/null 2>&1 || true
else
    note "INFO no CFBundleIconFile"
fi
ls -la "$app/Contents" "$app/Contents/MacOS" >"$out/layout.log" 2>&1

# 2. signatures of every Mach-O file (Apple silicon kills an unsigned one)
total=0 bad=0
while IFS= read -r -d '' f; do
    if file -b "$f" | grep -q "Mach-O"; then
        total=$((total + 1))
        # only this Mac's own CPU half of a universal file is ever loaded
        codesign -v --arch "$(uname -m)" "$f" >/dev/null 2>&1 || { bad=$((bad + 1)); echo "$f" >>"$out/macho-unsigned.log"; }
        codesign -v "$f" >/dev/null 2>&1 || echo "$f" >>"$out/macho-unsigned-any-arch.log"
        lipo -archs "$f" >>"$out/macho-archs.log" 2>&1
    fi
done < <(find "$app" -type f -print0)
note "INFO Mach-O files: $total, without a valid signature for $(uname -m): $bad, for some CPU: $(wc -l <"$out/macho-unsigned-any-arch.log" 2>/dev/null || echo 0)"
sort "$out/macho-archs.log" | uniq -c >"$out/macho-archs-count.log"
spctl -a -vv -t exec "$app" >"$out/spctl.log" 2>&1
note "INFO spctl on the app: $(tr '\n' ' ' <"$out/spctl.log")"
if command -v syspolicy_check >/dev/null; then
    syspolicy_check distribution "$app" >"$out/syspolicy-distribution.log" 2>&1
    note "INFO syspolicy_check distribution exit $? (log: syspolicy-distribution.log)"
fi

# 3. drag to Applications (Finder keeps the quarantine flag)
step "copy to /Applications"
limit 600 ditto "$app" /Applications/Forge.app || note "FAIL ditto to /Applications (exit $?)"

# 4. the README's step, then every app's smoke check
step "xattr -dr"
limit 120 xattr -dr com.apple.quarantine /Applications/Forge.app
note "INFO quarantine left after xattr -dr: $(xattr -lr /Applications/Forge.app 2>/dev/null | grep -c quarantine)"
mkdir -p "$work/home-smoke"
step "smoke"
check smoke limit 1500 env HOME="$work/home-smoke" /Applications/Forge.app/Contents/MacOS/Forge --smoke --window none --report "$out/smoke.json"
tail -8 "$out/smoke.log" | sed 's/^/INFO smoke: /' >>"$res"
stop_forge

# 5. open it as a user does: the window, the hub, the welcome page
step "gui open"
limit 60 open /Applications/Forge.app || note "INFO open exit $?"
if wait_port 8400 90; then note "PASS gui-open"; else note "FAIL gui-open (no hub in 90 s)"; fi
sleep 25
limit 30 screencapture -x "$out/2-open.png" || note "INFO screencapture failed"
limit 30 osascript -e 'tell application "System Events" to get name of every process whose background only is false' >"$out/gui-processes.log" 2>&1
note "INFO visible processes: $(cat "$out/gui-processes.log")"
pgrep -fl "[f]orge_portable|[w]ebview|[C]hrome" >"$out/gui-ps.log" 2>&1
note "INFO hub / answered $(curl -s --max-time 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:8400/)"
# backends start only when an app is opened (the welcome page opens none)
before=$(pgrep -f "[u]vicorn" | wc -l | tr -d ' ')
note "INFO backends running before quit: $before"
limit 30 osascript -e 'tell application "Forge" to quit' >"$out/quit.log" 2>&1
sleep 10
if pgrep -f "[f]orge_portable.py" >/dev/null; then note "INFO still running 10 s after quit"; else note "PASS quit (no Forge process left)"; fi
if pgrep -fl "[u]vicorn" >"$out/after-quit-backends.log"; then
    note "FAIL backends left after quit"
elif [ "$before" -gt 0 ]; then
    note "PASS no backends left after quit"
else
    note "INFO backends after quit: not tested (none was running)"
fi
stop_forge
cp ~/Library/Logs/Forge/*.log "$out/" 2>/dev/null || true

# 5b. what a quarantined copy does when opened (Gatekeeper's answer)
step "quarantined open"
limit 600 ditto "$app" "$work/q/Forge.app"
limit 60 open "$work/q/Forge.app" >"$out/open-quarantined.log" 2>&1
note "INFO open on the quarantined copy: exit $? $(tr '\n' ' ' <"$out/open-quarantined.log")"
sleep 12
limit 30 screencapture -x "$out/1-quarantined-open.png" || true
if wait_port 8400 20; then note "INFO quarantined copy started anyway (Gatekeeper off or approved)"; else note "INFO quarantined copy did not start (as expected unsigned)"; fi
stop_forge
pkill -f "[C]oreServicesUIAgent" || true

# 6. a read-only .dmg with an Applications link, started from the mounted image
mkdir -p "$work/dmgsrc"
limit 600 ditto /Applications/Forge.app "$work/dmgsrc/Forge.app"
ln -s /Applications "$work/dmgsrc/Applications"
step "dmg"
check dmg-create limit 900 hdiutil create -volname Forge -srcfolder "$work/dmgsrc" -format UDZO -ov "$work/Forge.dmg"
note "INFO dmg $(stat -f %z "$work/Forge.dmg" 2>/dev/null) bytes"
mnt=$(limit 300 hdiutil attach -nobrowse -readonly "$work/Forge.dmg" | awk -F'\t' '/\/Volumes\//{print $NF}')
note "INFO dmg mounted at $mnt"
mkdir -p "$work/home-dmg"
check smoke-from-dmg limit 600 env HOME="$work/home-dmg" "$mnt/Forge.app/Contents/MacOS/Forge" --smoke --window none --apps notes,office,files --report "$out/smoke-dmg.json"
limit 120 hdiutil detach "$mnt" >/dev/null 2>&1 || true

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
limit 600 ditto /Applications/Forge.app "$signed"
find "$signed" -type f -print0 | while IFS= read -r -d '' f; do
    file -b "$f" | grep -q Mach-O && limit 60 codesign --force -s - --options runtime --entitlements "$work/ent.plist" "$f" >>"$out/sign.log" 2>&1
done
check sign-app limit 300 codesign --force -s - --options runtime --entitlements "$work/ent.plist" "$signed"
check sign-verify limit 300 codesign --verify --deep --strict --verbose=2 "$signed"
mkdir -p "$work/home-signed"
step "hardened"
check smoke-hardened limit 600 env HOME="$work/home-signed" "$signed/Contents/MacOS/Forge" --smoke --window none --apps notes,office,files,media,convert --report "$out/smoke-hardened.json"
note "INFO done"
# the job fails when any step did, so a green run means every PASS held
! grep -q "^FAIL" "$res"
