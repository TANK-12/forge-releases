# Forge downloads

![Forge](https://openzenith.app/assets/hub-home.webp)

Free apps for your own computer, in one window: files and storage, office work, creative tools, readers and study helpers. No account, and most work offline.

Website: https://openzenith.app/

Issues: [report a problem here](https://github.com/TANK-12/forge-releases/issues/new) (say your Forge version and system).

This repository holds only built files: the installers (release v0.3.1) and the update packs Forge downloads (the rolling 'packs' release, with a list signed by the owner's key). The download page is https://tank-12.github.io/forge-releases/.

## Windows 10 and 11

- [Forge-Web-Setup-0.3.1.exe](https://github.com/TANK-12/forge-releases/releases/download/v0.3.1/Forge-Web-Setup-0.3.1.exe) (3 MB): Small setup: downloads only the apps you pick
- [Forge-Setup-0.3.1.exe](https://github.com/TANK-12/forge-releases/releases/download/v0.3.1/Forge-Setup-0.3.1.exe) (177 MB): Full setup: everything in one file, installs offline

## Linux (x64)

- [forge-get-0.3.1-linux-x64.sh](https://github.com/TANK-12/forge-releases/releases/download/v0.3.1/forge-get-0.3.1-linux-x64.sh) (9 kB): Small installer script: downloads only the apps you pick
- [forge-0.3.1-linux-x64.tar.gz](https://github.com/TANK-12/forge-releases/releases/download/v0.3.1/forge-0.3.1-linux-x64.tar.gz) (254 MB): Full download: unpack, then run ./Forge/forge --install

## macOS 13 or newer

The Mac downloads are built and checked on Linux only and have not been tried on a real Mac yet.

- [forge-0.3.1-macos-arm64.tar.gz](https://github.com/TANK-12/forge-releases/releases/download/v0.3.1/forge-0.3.1-macos-arm64.tar.gz) (240 MB): For Apple silicon Macs (M1 and newer): unpack, then drag Forge.app into Applications
- [forge-0.3.1-macos-x64.tar.gz](https://github.com/TANK-12/forge-releases/releases/download/v0.3.1/forge-0.3.1-macos-x64.tar.gz) (242 MB): For Intel Macs: unpack, then drag Forge.app into Applications

## Android 8.0 or newer

- [forge.apk](https://github.com/TANK-12/forge-android/releases/download/v0.3/forge.apk): Open a few Forge apps on your phone over your home Wi-Fi, in the Forge app for Android or in the phone's own browser. Phones · the Android app or the phone's browser, not yet tried on a real phone The APK comes from GitHub Releases; Android asks once to allow installs from your browser. In the app, pair with the address, check code and pairing code Devices shows: it trusts only your computer's own certificate and keeps no password. Checked in an Android emulator only.

## Phones

There is nothing to download for a phone. On the computer, open Devices, Phones and switch on Phone link; then open the address it shows in the phone's browser, type the pairing code and add the page to the home screen. The phone and the computer must be on the same Wi-Fi. The phone's browser first warns that the connection is not private, because the computer makes its own certificate: check the address is the one Devices shows, then go on to it. Not yet tried on a real phone.

## Updates

Forge looks for updates only when you press Check for updates in Settings, Updates; it never looks at the update list by itself. From there (or right-click an app) it updates one app or all of Forge, downloads only what changed and puts the old files back if anything fails. Your settings and saves are kept apart from the program and are never touched by an update.

If an app turns out to be unsafe or broken, the signed update list can mark it withdrawn. The next time you check for updates, Forge stops that app, takes out its program files and tells you why. Your own files and saves in it are never touched, and a Forge that never checks for updates is never changed.
