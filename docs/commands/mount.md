# mount

Category: system

Summary: Export the SD card to the host as a USB drive

Usage:

```
mount
```

Manual:

```
DESCRIPTION
    Exports the microSD card to the connected PC as a USB mass-storage
    drive, so you can copy files off/onto it over the same USB cable.
    While mounted the host owns the filesystem, so the on-device file
    commands (ls/cat/rm/get/put, pcap, wireguard, download) are paused
    until 'unmount'. Safely eject on the host, then run 'unmount'.

EXAMPLE
    root@espjack# mount
    SD exported over USB (30436 MB). It should appear as a drive on the host.
    Local file commands are paused until 'unmount'.
```
