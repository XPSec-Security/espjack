# reboot

Category: system

Summary: Restart the device

Usage:

```
reboot
```

Manual:

```
DESCRIPTION
    Restarts the device. Background tasks (arpspoof, responder, pcap,
    wireguard) stop without cleanup - run 'arpspoof off' first so
    victims' ARP caches are healed.

EXAMPLE
    root@espjack# reboot
    Rebooting...
    (boot log, then the banner and a fresh prompt)
```
