# loot

Category: system

Summary: List or clear captured loot in /loot

Usage:

```
loot [list | clear]
```

Manual:

```
DESCRIPTION
    Manages captured loot, which every module writes under /loot on the
    SD card (Responder hashes, pcap files, etc.). 'list' shows the
    files and total size; 'clear' deletes them. Retrieve loot off the
    device with 'mount' (USB drive) or 'get'/the WireGuard pivot.

SUBCOMMANDS
    list   Show loot files and total size (default).
    clear  Delete all files in /loot.

EXAMPLE
    root@espjack# loot
    NAME                                   SIZE
    responder_ntlm.txt                      412
    sweep.pcap                           821400
    2 file(s), 821812 bytes total in /loot
```
