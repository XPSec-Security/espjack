# arpspoof

Category: mitm & poisoning

Summary: ARP cache poisoning - whole subnet or one target

Usage:

```
arpspoof on [victim gateway] | off | status
```

Manual:

```
DESCRIPTION
    ARP cache poisoning with transparent relay. Repeatedly tells each
    victim that the gateway's IP is at this device's MAC (and the
    gateway the same about each victim), so their traffic is sent here.
    A WiFi RX hook then re-injects each intercepted frame to the real
    gateway or victim, so victims stay online while you sit in the
    middle (not a black-hole/DoS). Re-poisons every 2 s; 'off' sends
    corrective ARP replies so caches recover. 'status' (or no argument)
    shows the relay state and how many frames have been forwarded.

SUBCOMMANDS
    on                     Auto: detect the gateway, find every host on
                           the local /24 (ARP, 6 workers) and poison all
                           of them.
    on <victim> <gateway>  Poison a single victim.
    off                    Stop and heal the ARP caches.
    status                 Mode, phase, gateway, frames sent, victims.

EXAMPLES
    root@espjack# arpspoof on
    ARP spoofing started in background. Use 'arpspoof status' or 'arpspoof off'.

    root@espjack# arpspoof status
      running:     yes
      mode:        all
      phase:       discovering
      progress:    41% (105/254 hosts probed)
      gateway:     192.168.1.1 (60:83:E7:E8:F3:B0)
      frames sent: 0
      victims (2):
        192.168.1.10     B4:2E:99:12:AB:CD
        192.168.1.23     00:15:5D:0A:0B:0C

    root@espjack# arpspoof status
      running:     yes
      mode:        all
      phase:       poisoning
      gateway:     192.168.1.1 (60:83:E7:E8:F3:B0)
      frames sent: 36
      relay:       on - victims stay online (1842 frames forwarded)
      victims (3):
        192.168.1.10     B4:2E:99:12:AB:CD
        192.168.1.23     00:15:5D:0A:0B:0C
        192.168.1.31     3C:22:FB:44:55:66

    root@espjack# arpspoof off
    Stopping (ARP caches will be healed)...

NOTES
    To confirm poisoning from a Windows victim, run
    tools/watch-gateway-mac.ps1 from this repo on that machine.
    Run 'arpspoof off' before 'reboot', or victims keep the poisoned
    entry until it expires.
```
