# run

Category: system

Summary: Run CLI commands from an SD script file

Usage:

```
run <file>
```

Manual:

```
DESCRIPTION
    Runs an SD-card text file as a payload: each line is executed as a
    CLI command, in order. Blank lines and lines starting with '#' are
    skipped. Background commands (arpspoof on, responder on, pcap
    start) return immediately and keep running; blocking commands
    (scans) run to completion before the next line. Ctrl+C stops the
    whole script. Use 'delay <ms>' between steps for timing.

OPTIONS
    <file>  Script path on the SD card (e.g. /scripts/recon.txt).

EXAMPLE
    root@espjack# cat /scripts/recon.txt
    # connect, map the subnet, start a capture
    wifi connect CorpWifi s3cret
    delay 2000
    arpscan
    arpspoof on
    pcap start sweep

    root@espjack# run /scripts/recon.txt
    [autorun] running /scripts/recon.txt
    autorun> wifi connect CorpWifi ******
    autorun> delay 2000
    autorun> arpscan
    ...
    [autorun] done.

NOTES
    A file named /autorun.txt runs automatically at boot (3 s cancel
    window) - the same format - so a dropped device acts unattended.
```
