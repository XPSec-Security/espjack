# dnsspoof

Category: mitm & poisoning

Summary: Forge DNS A answers on the MITM relay (needs arpspoof)

Usage:

```
dnsspoof on [ip] | off | status
```

Manual:

```
DESCRIPTION
    Forges DNS answers for victims whose traffic flows through the ARP
    relay: an A-record query is answered locally with a chosen IP
    (default this device), redirecting the victim (e.g. to a phishing /
    captive page). Run 'arpspoof on' first, or victim DNS never reaches
    us. Only A queries are forged; others pass through.

SUBCOMMANDS
    on [ip]  Start forging; answer with 'ip' (default: this device).
    off      Stop forging.
    status   Whether it's active and how many answers were forged.

EXAMPLE
    root@espjack# arpspoof on
    root@espjack# dnsspoof on 192.168.1.42
    DNS spoof on -> 192.168.1.42

    root@espjack# dnsspoof status
    active: yes, 37 answer(s) forged
```
