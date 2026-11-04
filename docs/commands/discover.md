# discover

Category: recon

Summary: Find UPnP/SSDP + mDNS/Bonjour devices (multicast)

Usage:

```
discover
```

Manual:

```
DESCRIPTION
    Finds devices that announce themselves over multicast - no port
    sweep, works from a normal station. Sends an SSDP M-SEARCH
    (UPnP: routers, smart TVs, media servers, cameras, printers) and an
    mDNS/Bonjour service query (_services._dns-sd._udp), then lists what
    replied. A fast way to inventory a subnet and spot juicy targets.

EXAMPLE
    root@espjack# discover
    Discovering (SSDP + mDNS, ~6s)...

    SSDP/UPnP (2):
      192.168.1.1      Linux/3.14 UPnP/1.0 [upnp:rootdevice]
      192.168.1.50     Roku/9.4 UPnP/1.0
    mDNS/Bonjour (2):
      192.168.1.23     _companion-link._tcp.local
      192.168.1.77     _ipp._tcp.local
```
