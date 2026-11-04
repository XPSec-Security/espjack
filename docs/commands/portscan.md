# portscan

Category: recon

Summary: TCP port scan (connect/banner/version)

Usage:

```
portscan <target>[/prefix] [-p a-b] [-top] [-m 0|1|2] [-t ms]
```

Manual:

```
DESCRIPTION
    TCP connect scan (this network stack can't do raw/SYN scans). The
    port list is split across 6 parallel workers. With a /prefix, every
    host in the range is scanned, one host after another.

OPTIONS
    <target>[/prefix]  One host (192.168.1.10) or a range
                       (192.168.1.0/24). Prefix /20 to /32.
    -p <start-end>     Port range. Default 1-1024. One port: -p 80-80.
    -top               Scan a built-in list of 54 common ports instead.
    -m <0|1|2>         0 = open/closed only, 1 = also grab the banner,
                       2 = banner + version detection (default).
    -t <ms>            Connect timeout per port, default 400. Raise it
                       on slow links, lower it for speed.

EXAMPLES
    root@espjack# portscan 192.168.1.10 -top
    Scanning... (Ctrl+C to stop)
      [########################] 100%

    3 open port(s):
    IP               PORT     SERVICE          VERSION/BANNER
    192.168.1.10     22       ssh              SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
    192.168.1.10     80       http             nginx/1.18.0 (Ubuntu)
    192.168.1.10     445      smb              

    root@espjack# portscan 192.168.1.0/28 -p 80-80 -m 0
    Scanning range... (Ctrl+C to stop)
      [########################] 100%

    2 open port(s):
    IP               PORT     SERVICE          VERSION/BANNER
    192.168.1.1      80       http             
    192.168.1.10     80       http             
```
