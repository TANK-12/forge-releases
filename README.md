# Forge downloads

One window for many small local apps: games, creative tools, readers and research helpers, each its own little web server.

This repository holds only built files: the installers (release v0.2.1) and the update packs Forge downloads (the rolling 'packs' release, with a list signed by the owner's key). The download page is https://tank-12.github.io/forge-releases/.

## Windows 10 and 11

- [Forge-Web-Setup-0.2.1.exe](https://github.com/TANK-12/forge-releases/releases/download/v0.2.1/Forge-Web-Setup-0.2.1.exe) (3 MB): Small setup: downloads only the apps you pick
- [Forge-Setup-0.2.1.exe](https://github.com/TANK-12/forge-releases/releases/download/v0.2.1/Forge-Setup-0.2.1.exe) (140 MB): Full setup: everything in one file, installs offline

## Linux (x64)

- [forge-get-0.2.1-linux-x64.sh](https://github.com/TANK-12/forge-releases/releases/download/v0.2.1/forge-get-0.2.1-linux-x64.sh) (12 kB): Small installer script: downloads only the apps you pick
- [forge-0.2.1-linux-x64.tar.gz](https://github.com/TANK-12/forge-releases/releases/download/v0.2.1/forge-0.2.1-linux-x64.tar.gz) (211 MB): Full download: unpack, then run ./Forge/forge --install

## Updates

Forge checks this page's release for updates: Settings, Updates (or right-click an app) updates one app or all of Forge, downloads only what changed and puts the old files back if anything fails. Your settings and saves are kept apart from the program and are never touched by an update.

An app can be withdrawn: each Forge that checks for updates takes that app's program files out. That cannot reach a copy that never goes online or a copy taken out of Forge.
