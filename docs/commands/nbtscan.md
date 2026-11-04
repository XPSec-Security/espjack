# nbtscan

Category: recon

Summary: NetBIOS node status sweep (default: local /24, no credentials)

Usage:

```
nbtscan [ip[/prefix]]
```

Manual:

```
DESCRIPTION
    Sends a NetBIOS NODE STATUS query (UDP/137, like 'nbtstat -A') to
    each address and lists the hosts that reply, with their NetBIOS
    name and MAC. No credentials needed. Only machines with NetBIOS
    over TCP/IP enabled answer - mostly Windows. Runs 6 parallel workers.

OPTIONS
    [ip[/prefix]]  Range to sweep, /20 to /32 (a bare IP means just that
                   host). Default: the local /24 of the current WiFi
                   connection (.1 to .254).

EXAMPLE
    root@espjack# nbtscan
    Sweeping... (Ctrl+C to stop)
      [########################] 100%

    IP               NAME                 MAC
    192.168.1.10     DC01                 00:15:5D:01:02:03
    192.168.1.23     WS-FINANCE01         00:15:5D:0A:0B:0C
```
