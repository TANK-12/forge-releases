# Forge downloads

![Forge](https://openzenith.app/store/media/cosmos/1-card.webp)

Free apps for your own computer, in one window: games, creative tools, readers and study helpers. No account, and most work offline.

Website: https://openzenith.app/

Issues: [report a problem here](https://github.com/TANK-12/forge-releases/issues/new) (say your Forge version and system).

This repository holds only built files: the installers (release v0.2.7) and the update packs Forge downloads (the rolling 'packs' release, with a list signed by the owner's key). The download page is https://tank-12.github.io/forge-releases/.

## Windows 10 and 11

- [Forge-Web-Setup-0.2.7.exe](https://github.com/TANK-12/forge-releases/releases/download/v0.2.7/Forge-Web-Setup-0.2.7.exe) (3 MB): Small setup: downloads only the apps you pick
- [Forge-Setup-0.2.7.exe](https://github.com/TANK-12/forge-releases/releases/download/v0.2.7/Forge-Setup-0.2.7.exe) (169 MB): Full setup: everything in one file, installs offline

## Linux (x64)

- [forge-get-0.2.7-linux-x64.sh](https://github.com/TANK-12/forge-releases/releases/download/v0.2.7/forge-get-0.2.7-linux-x64.sh) (13 kB): Small installer script: downloads only the apps you pick
- [forge-0.2.7-linux-x64.tar.gz](https://github.com/TANK-12/forge-releases/releases/download/v0.2.7/forge-0.2.7-linux-x64.tar.gz) (246 MB): Full download: unpack, then run ./Forge/forge --install

## Android 8.0 or newer

- [forge.apk](https://github.com/TANK-12/forge-android/releases/download/v0.2/forge.apk): A phone app for Android that looks good upright or sideways and links to Forge on your computer once you sign in. Android · first build, not yet tested on a phone The APK comes from GitHub Releases. Android asks once to allow installs from your browser.

## Updates

Forge looks for updates only when you press Check for updates in Settings, Updates; it never looks at the update list by itself. From there (or right-click an app) it updates one app or all of Forge, downloads only what changed and puts the old files back if anything fails. Your settings and saves are kept apart from the program and are never touched by an update.

If an app turns out to be unsafe or broken, the signed update list can mark it withdrawn. The next time you check for updates, Forge stops that app, takes out its program files and tells you why. Your own files and saves in it are never touched, and a Forge that never checks for updates is never changed.
