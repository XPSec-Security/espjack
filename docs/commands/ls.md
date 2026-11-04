# ls

Category: files

Summary: List files on the SD card or an SMB share

Usage:

```
ls [path | //host/share/dir <creds>]
```

Manual:

```
DESCRIPTION
    Lists a directory. A local path lists the SD card (default: the
    root); a //host/share/dir path lists a directory on an SMB share
    over the network. Directory names end with '/'.

OPTIONS
    On a remote path, append credentials:
      -u <user> -p <pass>   or   -H <nthash>   (NT hash, or LM:NT)
      [-d <domain>] [--local-auth]

EXAMPLES
    root@espjack# ls
    NAME                                   SIZE
    wordlists/                            <DIR>
    loot/                                 <DIR>
    users.txt                              1873

    root@espjack# ls //192.168.1.10/C$/Users -u jsmith -p P@ssw0rd -d CORP
    NAME                                             SIZE
    Administrator/                                  <DIR>
    jsmith/                                         <DIR>
    Public/                                         <DIR>
```
