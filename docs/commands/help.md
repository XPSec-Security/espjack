# help

Category: system

Summary: List all commands, or show detailed help for one

Usage:

```
help [command]
```

Manual:

```
DESCRIPTION
    With no argument, lists every command grouped by category. With a
    command name, prints that command's manual - the same text as
    '<command> -h'.

EXAMPLES
    root@espjack# help

    Available commands (use '<command> -h' for details):

    network:
      wifi         WiFi scanning and connection
      download     HTTP(S) GET a file straight to the SD card

    recon:
      portscan     TCP port scan (connect/banner/version)
      ...

    root@espjack# help arpscan
    (prints the arpscan manual)
```
