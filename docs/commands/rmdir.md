# rmdir

Category: files

Summary: Remove an empty directory (SD or SMB share)

Usage:

```
rmdir <path | //host/share/dir <creds>>
```

Manual:

```
DESCRIPTION
    Removes an empty directory, on the SD card or - for a
    //host/share/dir path - on an SMB share.

OPTIONS
    On a remote path, append credentials:
      -u <user> -p <pass>   or   -H <nthash>   (NT hash, or LM:NT)
      [-d <domain>] [--local-auth]

EXAMPLE
    root@espjack# rmdir /loot
    Removed.
```
