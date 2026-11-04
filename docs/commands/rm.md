# rm

Category: files

Summary: Delete a file (SD or SMB share)

Usage:

```
rm <path | //host/share/file <creds>>
```

Manual:

```
DESCRIPTION
    Deletes a file, without asking. A local path removes from the SD
    card; a //host/share/file path deletes on an SMB share (needs
    delete rights). Use rmdir for directories.

OPTIONS
    On a remote path, append credentials:
      -u <user> -p <pass>   or   -H <nthash>   (NT hash, or LM:NT)
      [-d <domain>] [--local-auth]

EXAMPLES
    root@espjack# rm /lab1.pcap
    Removed.

    root@espjack# rm //192.168.1.10/share/old.txt -u jsmith -p P@ssw0rd -d CORP
    Removed.
```
