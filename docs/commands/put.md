# put

Category: files

Summary: Upload a file from the SD card to an SMB share

Usage:

```
put <sd-path> //host/share/file <creds>
```

Manual:

```
DESCRIPTION
    Uploads a file from the SD card to an SMB share (needs write
    rights). An existing remote file is overwritten.

OPTIONS
    <sd-path>          Local source on the SD card.
    //host/share/file  Remote destination path.
    On a remote path, append credentials:
      -u <user> -p <pass>   or   -H <nthash>   (NT hash, or LM:NT)
      [-d <domain>] [--local-auth]

EXAMPLE
    root@espjack# put /tools/agent.exe //192.168.1.10/share/agent.exe -u jsmith -p P@ssw0rd -d CORP
    Uploaded 73216 bytes.
```
