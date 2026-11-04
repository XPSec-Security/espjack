# unmount

Category: system

Summary: Stop exporting the SD card and reclaim it

Usage:

```
unmount
```

Manual:

```
DESCRIPTION
    Stops exporting the SD card over USB and re-reads it, so the
    firmware regains access and sees any changes the host made. Eject
    the drive on the host first to avoid losing unwritten data.

EXAMPLE
    root@espjack# unmount
    Ejecting... (make sure the host has finished writing / safely ejected)
    Unmounted. SD is back under firmware control.
```
