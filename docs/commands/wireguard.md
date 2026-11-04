# wireguard

Category: pivot

Summary: WireGuard pivot tunnel from a wg-quick config file

Usage:

```
wireguard up <file> | down | status
```

Manual:

```
DESCRIPTION
    Brings up a WireGuard tunnel from a standard wg-quick config file
    on the SD card, so the remote peer can reach this device through
    the tunnel. Needs an active WiFi connection. Only PrivateKey,
    Address, PublicKey, PresharedKey and Endpoint are read; AllowedIPs,
    DNS and the rest are ignored.

SUBCOMMANDS
    up <file>  Start the tunnel from a config on the SD card.
    down       Stop it.
    status     Tunnel state, local tunnel IP and endpoint (also shown
               by 'wireguard' with no arguments).

CONFIG FILE
    [Interface]
    PrivateKey = <this device's private key>
    Address = 10.8.0.2/32

    [Peer]
    PublicKey = <server public key>
    PresharedKey = <optional>
    Endpoint = vpn.example.com:51820

EXAMPLES
    root@espjack# wireguard up /wg0.conf
    WireGuard tunnel up.

    root@espjack# wireguard status
      running                yes
      localIp                10.8.0.2
      endpoint               vpn.example.com
      port                   51820
```
