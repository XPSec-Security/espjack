# socks5

Category: pivot

Summary: SOCKS5 proxy to pivot into the LAN (over WireGuard)

Usage:

```
socks5 on [port] | off | status
```

Manual:

```
DESCRIPTION
    Runs a SOCKS5 proxy (CONNECT, no auth) on the device. Bring up the
    WireGuard pivot first, then point a SOCKS5 client on your side at
    the device's tunnel IP and this port - your traffic exits onto the
    target LAN through the implant, so you reach internal hosts as if
    you were on-site. IPv4 and domain targets; a few concurrent
    connections (the device's socket budget is small).

SUBCOMMANDS
    on [port]  Start the proxy (default port 1080).
    off        Stop it.
    status     Running state, port, active/served connections.

EXAMPLE
    root@espjack# wireguard up /wg0.conf
    root@espjack# socks5 on
    SOCKS5 proxy up on :1080. Reach it via the WireGuard tunnel IP to pivot into the LAN.
    (on your box: curl --socks5 10.8.0.2:1080 http://192.168.1.10/)
```
