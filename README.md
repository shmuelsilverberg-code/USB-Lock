# Otzaria USB Lock

A small tool to prepare a USB drive for safe distribution of Otzaria:
formats it to NTFS and locks write access so only your own account can
write to it. Every other computer can read/run from it but not write to
it, blocking the main way flash-drive malware spreads.

## Get the exe (no Windows machine needed)

Push this folder to a GitHub repo (or just `otzaria/otzaria` if you'd
rather keep it inside the main project). The included GitHub Actions
workflow (`.github/workflows/build-exe.yml`) builds the `.exe` on a
Windows runner automatically and attaches it under the run's **Artifacts**.
You can also trigger it manually from the Actions tab ("Run workflow").

## Build it yourself on Windows

Requires Python 3.10+ from python.org (check "Add to PATH" during install).

```
build.bat
```

The finished file is `dist\Otzaria-USB-Lock.exe`. That's the only file
end users need - double-click it, approve the UAC prompt, done.

## Using the tool

1. Plug in the USB drive.
2. Run `Otzaria-USB-Lock.exe` (approve the admin prompt - it's needed to
   format the drive and set its permissions).
3. Pick the drive from the list.
4. If it isn't already NTFS, click **Format to NTFS** (this erases the
   drive - you'll be asked to retype the drive letter and the word
   ERASE/מחק to confirm).
5. Click **Open drive to copy files** and copy the Otzaria installer on.
6. Click **Lock drive for distribution**.

To add or update files later, plug the drive back into this same PC -
your account still has full access. **Reset to normal permissions**
undoes the lock if you ever need to hand full write access back.

## Limits worth knowing

- Blocks the main infection path (malware writing itself to any
  writable drive it finds) - not a guarantee against every attack.
- A local administrator on another PC can still override the lock.
- Only tested by code review, not on a real Windows machine yet - try
  it on a spare/cheap USB drive before relying on it for distribution.
