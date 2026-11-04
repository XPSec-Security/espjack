# pcap

Category: capture

Summary: Packet capture to SD (Ethernet; -w = raw 802.11)

Usage:

```
pcap start [name] [-w] | stop | status
```

Manual:

```
DESCRIPTION
    Writes captured packets to a .pcap file on the SD card (open in
    Wireshark). Two modes:

      default (Ethernet): taps DECRYPTED Ethernet frames from the
      station data path, so real IP/DNS is visible. On its own it only
      sees our own + broadcast traffic - run 'arpspoof on' alongside it
      and the victims' traffic (DNS, HTTP, ...) flows through us and is
      captured. This is the fix for "pcap only shows WiFi noise".

      -w (802.11): raw 802.11 of the associated channel via promiscuous
      mode. Management/control frames are visible but WPA data payloads
      are encrypted.

    Frames the SD card can't keep up with are counted as dropped.

SUBCOMMANDS
    start [name] [-w]  Capture to /<name>.pcap (default /capture.pcap).
                       -w selects raw 802.11 instead of Ethernet.
    stop               Stop and close the file.
    status             Mode, packets/bytes written, drops (also shown
                       by 'pcap' with no arguments).

EXAMPLES
    root@espjack# arpspoof on
    ARP spoofing started in background. Use 'arpspoof status' or 'arpspoof off'.
    root@espjack# pcap start victims
    Capturing Ethernet in background. 'pcap status' / 'pcap stop'.

    root@espjack# pcap status
      running                yes
      file                   /loot/victims.pcap
      mode                   ethernet
      packets                1843
      bytes                  412977
      dropped                0

    root@espjack# pcap stop
    Stopping...
    [PCAP] Done: 2210 packets, 498310 bytes
```
