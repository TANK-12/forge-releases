# Forge downloads

![Forge](https://openzenith.app/assets/hub-home.webp)

## What Forge is

Forge is a free program that puts lots of small, useful apps in one window on your own computer: files, notes and office work, PDFs, music and video, creative tools, games, readers and study helpers.

It all runs on your computer, not on a website. There is no account to make, nothing you do is uploaded, and most apps keep working with the internet off.

Apps that use AI run it on your computer too, so your words stay with you; the few that use cloud AI say so.

Download it once for Windows or Linux. Forge updates itself only when you ask, and one click undoes an update you don't like.

Website: https://openzenith.app/

Issues: [report a problem here](https://github.com/TANK-12/forge-releases/issues/new) (say your Forge version and system).

This repository holds only built files: the installers (release v0.4.7) and the update packs Forge downloads (the rolling 'Update packs' releases, with a list signed by the owner's key). The download page is https://tank-12.github.io/forge-releases/.

## Windows 10 and 11

- [Forge-Web-Setup-0.4.7.exe](https://github.com/TANK-12/forge-releases/releases/download/v0.4.7/Forge-Web-Setup-0.4.7.exe) (3 MB): Small setup: downloads only the apps you pick
- [Forge-Setup-0.4.7.exe](https://github.com/TANK-12/forge-releases/releases/download/v0.4.7/Forge-Setup-0.4.7.exe) (199 MB): Full setup: everything in one file, installs offline

## Linux (x64)

- [Forge-0.4.7-x86_64.AppImage](https://github.com/TANK-12/forge-releases/releases/download/v0.4.7/Forge-0.4.7-x86_64.AppImage) (259 MB): Double-click to install: Forge goes into your apps menu, with the AI tools ticked
- [forge-get-0.4.7-linux-x64.sh](https://github.com/TANK-12/forge-releases/releases/download/v0.4.7/forge-get-0.4.7-linux-x64.sh) (12 kB): Small installer script: downloads only the apps you pick
- [forge-0.4.7-linux-x64.tar.gz](https://github.com/TANK-12/forge-releases/releases/download/v0.4.7/forge-0.4.7-linux-x64.tar.gz) (274 MB): Full download: unpack, then run ./Forge/forge --install

## macOS 13 or newer

The Mac downloads are checked on GitHub Mac machines (macOS 15 and 26, Apple silicon and Intel): installing, every app starting, and a new version keeping settings and saves. Nobody has tried them on their own Mac yet, macOS 13 and 14 have not been checked at all, and they are not signed by Apple.

- [forge-0.4.7-macos-arm64.tar.gz](https://github.com/TANK-12/forge-releases/releases/download/v0.4.7/forge-0.4.7-macos-arm64.tar.gz) (255 MB): For Apple silicon Macs (M1 and newer): unpack, then drag Forge.app into Applications
- [forge-0.4.7-macos-x64.tar.gz](https://github.com/TANK-12/forge-releases/releases/download/v0.4.7/forge-0.4.7-macos-x64.tar.gz) (261 MB): For Intel Macs: unpack, then drag Forge.app into Applications

## Android 8.0 or newer

- [forge.apk](https://github.com/TANK-12/forge-android/releases/latest/download/forge.apk): Open a few Forge apps on your phone over your home Wi-Fi, in the Forge app for Android or in the phone's own browser. Phones · the Android app or the phone's browser, not yet tried on a real phone The APK comes from GitHub Releases; Android asks once to allow installs from your browser. In the app, pair with the address, check code and pairing code Devices shows: it trusts only your computer's own certificate and keeps no password. Checked in an Android emulator only.

## Phones

Or skip the app and use the phone's browser. On the computer, open Devices, Phones and switch on Phone link; then open the address it shows in the phone's browser, type the pairing code and add the page to the home screen. The phone and the computer must be on the same Wi-Fi. The phone's browser first warns that the connection is not private, because the computer makes its own certificate: check the address is the one Devices shows, then go on to it. Not yet tried on a real phone.
## Installing on Linux

Linux: double-click the .AppImage (if nothing happens, right-click it, Properties, and allow it to run as a program). It asks once, with the AI tools Claude Code, Codex and Gemini ticked, then installs Forge in your home folder and apps menu and opens it. No password is needed. Or paste this one line in a terminal, which does the same. For Forge alone, without the AI tools, add `-s -- --no-ai-tools` after `sh`.

```sh
curl -fsSL https://openzenith.app/install.sh | sh
```

A system without curl (a new Ubuntu or Mint):

```sh
wget -qO- https://openzenith.app/install.sh | sh
```


## Updates

Forge looks for updates only when you press Look for updates in Settings, Updates; it never looks at the update list by itself. From there (or right-click an app) it updates one app or all of Forge: it shows what will change before anything does, downloads only what changed and puts the old files back if anything fails. It keeps the last few versions, so Go back undoes an update in one click. Your settings and saves are kept apart from the program and are never touched by an update. A Mac does not update Forge by itself: download the new version from this page and replace Forge.app in Applications. Your settings and saves are kept apart from the app, in your Library folder, and stay as they are.

If an app turns out to be unsafe or broken, the signed update list can mark it withdrawn. The next time you check for updates, Forge stops that app, takes out its program files and tells you why. Your own files and saves in it are never touched, and a Forge that never checks for updates is never changed.
