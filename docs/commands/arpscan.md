# arpscan

Category: recon

Summary: ARP sweep (default: local /24; works even if ICMP is blocked)

Usage:

```
arpscan [ip[/prefix]]
```

Manual:

```
DESCRIPTION
    Layer-2 host discovery: sends an ARP who-has for each address and
    lists the ones that answer, with their MAC. A host can't ignore ARP
    and still be reachable, so this finds machines that block ping.
    Only hosts on the local segment can answer (ARP doesn't cross
    routers). Runs 6 parallel workers.

OPTIONS
    [ip[/prefix]]  Range to sweep, /20 to /32 (a bare IP means just that
                   host). Default: the local /24 of the current WiFi
                   connection (.1 to .254).

EXAMPLES
    root@espjack# arpscan
    Sweeping... (Ctrl+C to stop)
      [########################] 100%

    IP               MAC
    192.168.1.1      60:83:E7:E8:F3:B0
    192.168.1.10     B4:2E:99:12:AB:CD
    192.168.1.23     00:15:5D:0A:0B:0C

    root@espjack# arpscan 192.168.1.10
    Sweeping... (Ctrl+C to stop)
      [########################] 100%

    IP               MAC
    192.168.1.10     B4:2E:99:12:AB:CD
```
