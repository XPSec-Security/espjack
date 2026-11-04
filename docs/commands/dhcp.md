# dhcp

Category: recon

Summary: Show this station's DHCP lease details

Usage:

```
dhcp
```

Manual:

```
DESCRIPTION
    Shows this device's own DHCP lease - IP, mask, gateway and the DNS
    servers the network handed out. Reading other hosts' DHCP traffic
    is not possible passively on a WPA network (it's encrypted per-
    station); capture it instead via the ARP-spoof relay + pcap.

EXAMPLE
    root@espjack# dhcp
    Current DHCP lease (this station):
      ip:       192.168.1.42
      mask:     255.255.255.0
      gateway:  192.168.1.1
      dns1:     192.168.1.1
      dns2:     0.0.0.0
```
