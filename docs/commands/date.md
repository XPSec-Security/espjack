# date

Category: system

Summary: Show the current UTC time (NTP-synced on connect)

Usage:

```
date
```

Manual:

```
DESCRIPTION
    Shows the current UTC time. The clock is set by NTP a few seconds
    after 'wifi connect'; until then (or with no connection) it reports
    that it isn't set. Correct time makes pcap/loot timestamps valid.

EXAMPLE
    root@espjack# date
    2026-11-04 14:03:22 UTC
```
