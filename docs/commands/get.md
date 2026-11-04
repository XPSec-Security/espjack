# get

Category: files

Summary: Download a file from an SMB share to the SD card

Usage:

```
get //host/share/file <sd-path> <creds>
```

Manual:

```
DESCRIPTION
    Downloads a file from an SMB share to the SD card.

OPTIONS
    //host/share/file  Remote source path.
    <sd-path>          Local destination on the SD card.
    On a remote path, append credentials:
      -u <user> -p <pass>   or   -H <nthash>   (NT hash, or LM:NT)
      [-d <domain>] [--local-auth]

EXAMPLE
    root@espjack# get //192.168.1.10/share/db.bak /loot/db.bak -u jsmith -p P@ssw0rd -d CORP
    Downloaded 104857 bytes to /loot/db.bak
```
