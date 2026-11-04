# cat

Category: files

Summary: Print a file (SD or SMB share)

Usage:

```
cat <path | //host/share/file <creds>>
```

Manual:

```
DESCRIPTION
    Prints a file. A local path reads the SD card; a //host/share/file
    path reads a file from an SMB share. Binary files print as raw
    bytes, so stick to text.

OPTIONS
    On a remote path, append credentials:
      -u <user> -p <pass>   or   -H <nthash>   (NT hash, or LM:NT)
      [-d <domain>] [--local-auth]

EXAMPLES
    root@espjack# cat /wordlists/users.txt
    administrator
    jsmith

    root@espjack# cat //192.168.1.10/SYSVOL/corp.local/scripts/logon.bat -u jsmith -p P@ssw0rd -d CORP
    @echo off
    net use H: \\fs01\home
```
