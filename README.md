# Forge downloads

![Forge](https://openzenith.app/assets/hub-home.webp)

## What Forge is

Forge is a free program that puts lots of small, useful apps in one window on your own computer: files, notes and office work, PDFs, music and video, creative tools, games, readers and study helpers.

It all runs on your computer, not on a website. There is no account to make, nothing you do is uploaded, and most apps keep working with the internet off.

Apps that use AI run it on your computer too, so your words stay with you; the few that use cloud AI say so.

Download it once for Windows or Linux. Forge updates itself only when you ask, and one click undoes an update you don't like.

Website: https://openzenith.app/

Issues: [report a problem here](https://github.com/TANK-12/forge-releases/issues/new) (say your Forge version and system).

This repository holds only built files: the installers (release v0.4.0) and the update packs Forge downloads (the rolling 'Update packs' releases, with a list signed by the owner's key). The download page is https://tank-12.github.io/forge-releases/.

## Windows 10 and 11

- [Forge-Web-Setup-0.4.0.exe](https://github.com/TANK-12/forge-releases/releases/download/v0.4.0/Forge-Web-Setup-0.4.0.exe) (3 MB): Small setup: downloads only the apps you pick
- [Forge-Setup-0.4.0.exe](https://github.com/TANK-12/forge-releases/releases/download/v0.4.0/Forge-Setup-0.4.0.exe) (199 MB): Full setup: everything in one file, installs offline

## Linux (x64)

- [forge-get-0.4.0-linux-x64.sh](https://github.com/TANK-12/forge-releases/releases/download/v0.4.0/forge-get-0.4.0-linux-x64.sh) (11 kB): Small installer script: downloads only the apps you pick
- [forge-0.4.0-linux-x64.tar.gz](https://github.com/TANK-12/forge-releases/releases/download/v0.4.0/forge-0.4.0-linux-x64.tar.gz) (277 MB): Full download: unpack, then run ./Forge/forge --install

## Android 8.0 or newer

- [forge.apk](https://github.com/TANK-12/forge-android/releases/download/v0.3/forge.apk): Open a few Forge apps on your phone over your home Wi-Fi, in the Forge app for Android or in the phone's own browser. Phones · the Android app or the phone's browser, not yet tried on a real phone The APK comes from GitHub Releases; Android asks once to allow installs from your browser. In the app, pair with the address, check code and pairing code Devices shows: it trusts only your computer's own certificate and keeps no password. Checked in an Android emulator only.

## Phones

Or skip the app and use the phone's browser. On the computer, open Devices, Phones and switch on Phone link; then open the address it shows in the phone's browser, type the pairing code and add the page to the home screen. The phone and the computer must be on the same Wi-Fi. The phone's browser first warns that the connection is not private, because the computer makes its own certificate: check the address is the one Devices shows, then go on to it. Not yet tried on a real phone.

## Updates

Forge looks for updates only when you press Look for updates in Settings, Updates; it never looks at the update list by itself. From there (or right-click an app) it updates one app or all of Forge: it shows what will change before anything does, downloads only what changed and puts the old files back if anything fails. It keeps the last few versions, so Go back undoes an update in one click. Your settings and saves are kept apart from the program and are never touched by an update.

If an app turns out to be unsafe or broken, the signed update list can mark it withdrawn. The next time you check for updates, Forge stops that app, takes out its program files and tells you why. Your own files and saves in it are never touched, and a Forge that never checks for updates is never changed.
