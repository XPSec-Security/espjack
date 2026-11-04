# mkdir

Category: files

Summary: Create a directory (SD or SMB share)

Usage:

```
mkdir <path | //host/share/dir <creds>>
```

Manual:

```
DESCRIPTION
    Creates a directory. A local path creates on the SD card (the
    parent must exist); a //host/share/dir path creates on an SMB
    share.

OPTIONS
    On a remote path, append credentials:
      -u <user> -p <pass>   or   -H <nthash>   (NT hash, or LM:NT)
      [-d <domain>] [--local-auth]

EXAMPLES
    root@espjack# mkdir /loot
    Created.

    root@espjack# mkdir //192.168.1.10/share/dropbox -u jsmith -p P@ssw0rd -d CORP
    Created.
```
