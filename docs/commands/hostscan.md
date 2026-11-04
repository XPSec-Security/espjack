# hostscan

Category: recon

Summary: ICMP ping sweep (default: local /24)

Usage:

```
hostscan [ip[/prefix]]
```

Manual:

```
DESCRIPTION
    ICMP echo (ping) sweep. Runs one host at a time - the ping library
    can't be used from parallel tasks - so a full /24 takes a while.
    Hosts that drop ping won't show up; use arpscan for those. This
    device's own IP is always listed.

OPTIONS
    [ip[/prefix]]  Range to sweep, /20 to /32 (a bare IP means just that
                   host). Default: the local /24 of the current WiFi
                   connection (.1 to .254).

EXAMPLES
    root@espjack# hostscan
    Sweeping... (Ctrl+C to stop)
      [########################] 100%

    4 live host(s):
      192.168.1.1
      192.168.1.10
      192.168.1.23
      192.168.1.42

    root@espjack# hostscan 192.168.1.0/28
    (same output, only .0 to .15)
```
