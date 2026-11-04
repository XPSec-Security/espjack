# ESPJack documentation

Complete documentation for ESPJack: an offensive-security and post-exploitation
implant firmware for any ESP32-S3 board with a microSD card over SPI. There is
no display and no web panel. Everything happens over a Linux-style serial CLI
on the S3's native USB.

Warning: authorized use only. This firmware bundles active offensive tooling:
ARP spoofing with transparent relay, DNS spoofing, LLMNR/NBT-NS poisoning with
credential capture, port/host/service scanning, zero- and
authenticated-credential Active Directory enumeration, a WireGuard pivot with
a SOCKS5 proxy, and a payload/autorun runner. Use it only on networks and
systems you own or are explicitly authorized to test. You are responsible for
complying with applicable laws and the scope of any engagement.

Scope note: ESPJack is a post-exploitation implant (drop and pivot,
enumeration, credential capture, lateral movement, exfiltration). WiFi-layer
attacks such as deauthentication, evil-twin access points or captive-portal
phishing, and WPA handshake capture are intentionally out of scope. Project
guidance is to use a dedicated WiFi-attack tool (such as Bruce) for those.

## Table of contents

1. [How it works](#how-it-works)
2. [Hardware](#hardware)
3. [Building and flashing](#building-and-flashing)
4. [SD card setup](#sd-card-setup)
5. [Command reference](#command-reference)
6. [Honesty notes and known limitations](#honesty-notes-and-known-limitations)
7. [Project layout](#project-layout)

## How it works

1. Flash the firmware and open the USB serial console at 115200 8N1. You get
   a banner and a `root@espjack#` prompt: a small Linux-style shell with line
   editing, command history (arrow keys), and `Ctrl+C` to cancel a running
   command.
2. Run `wifi connect <ssid> [password]` to join a network. Most commands
   need an active connection first; they print a clear error if not.
3. Run commands directly at the prompt, or put a script on the SD card and
   run it with the `run` command, or name it `/autorun.txt` so it executes
   automatically on every boot (after a 3 second `Ctrl+C` cancel window).
   This is meant for a device that is plugged in and left behind.
4. `help` lists every command grouped by category. `<command> -h` (or
   `help <command>`) prints that command's full manual: description,
   options or subcommands, and example output. This documentation set
   mirrors that same text, one file per command, under `commands/`.

## Hardware

ESPJack targets the generic `esp32-s3-devkitc-1` PlatformIO board
definition, which works for essentially any ESP32-S3 module or devkit. That
board definition only affects flash size and partitioning defaults, not pin
assignments, so it is not tied to a specific physical board.

A microSD card over SPI is optional overall, but required for several
features: wordlists for Kerberos-related commands, loot storage, autorun and
`run` scripts, and the `mount` USB-drive feature.

The SD SPI pins default to the M5Stack Cardputer ADV wiring (`CS=12 SCK=40
MISO=39 MOSI=14`, plus driving GPIO5 high, which that board family needs for
the card to enumerate correctly), but these pins are not compiled in. See
[SD card setup](#sd-card-setup) below to point them at a different board
without rebuilding the firmware.

The USB stack is configured as a composite CDC (the serial console) plus MSC
(mass storage) device, so the `mount` command can expose the SD card to a
host computer as an ordinary USB drive without disturbing the console.

## Building and flashing

Building requires [PlatformIO](https://platformio.org/).

```bash
pio run -t upload
pio device monitor
```

Library dependencies are declared in `platformio.ini`; PlatformIO installs
them automatically on the first build.

## SD card setup

### Pin configuration and network identity

SD pins, and a couple of network-identity settings, are not stored on the
SD card itself. Storing them there would be circular, since the pins have to
be known before the card can be read at all. Instead they live in
`/settings.json` on the device's internal flash (LittleFS), managed entirely
through the `settings` command:

```
settings show                              # print the current settings
settings set sd.cs 10                      # change one SD pin (needs reboot)
settings set sd.sck 12
settings set sd.miso 13
settings set sd.mosi 11
settings set hostname MyPhone              # DHCP hostname, blends in on 'wifi connect'
settings set mac AA:BB:CC:DD:EE:FF         # spoof the STA MAC, blends in on 'wifi connect'
settings reset                             # back to the Cardputer ADV defaults
```

Changing one of the `sd.*` pins needs a `reboot` to take effect. `hostname`
and `mac` take effect on the next `wifi connect`.

To target a different ESP32-S3 board, set the four `sd.*` pins to match its
wiring and reboot; no firmware changes are needed.

A reference copy of the settings schema is kept at
`sd_card/settings.json.example` in the repository, purely for documentation.
It is not meant to be copied onto the SD card, since the firmware never
reads settings from there.

### Directory layout

```
/settings.json      Not used. The real one lives on internal flash, see above.
/autorun.txt         Optional. Commands to run automatically at boot.
/scripts/...         Optional. Payloads for the 'run <file>' command.
/wordlists/
  users.txt          One username per line. Default for kerbrute, asreproast.
  spns.txt           One service/host[:port] per line. Default for kerberoast.
/loot/               Everything the tools capture lands here automatically:
  responder_ntlm.txt   NTLMv2/v1/Basic captures from Responder, one
                       hashcat-ready line per capture.
  <name>.pcap          Packet captures from the 'pcap' command.
```

`/loot` is created automatically on first boot with a card present. Use
`loot list` or `loot clear` to manage it, `mount` to pull files off over
USB, or `get`/`put` over an SMB share.

The repository ships templates under `sd_card/` for everything above except
`/loot` (which needs no template, since it is created and filled
automatically): `autorun.txt.example`, `scripts/*.txt.example`, and
`wordlists/*.txt.example`. Copy the ones you want to the card, drop the
`.example` suffix, and edit as needed. See `sd_card/README.md` in the
repository for a walkthrough of each one.

### Autorun example

```
# /autorun.txt - runs automatically about 3 seconds after boot
wifi connect CorpWifi s3cretpass
delay 2000
arpscan
arpspoof on
responder on
pcap start sweep
```

## Command reference

Run `help` on the device for the same grouped list, or `<command> -h` for
the full manual. Every command below links to its own page with usage,
description, options, and example output exactly as the device prints it.

### network

- [`wifi`](commands/wifi.md): WiFi scanning and connection
- [`download`](commands/download.md): HTTP(S) GET a file straight to the SD card

### recon

- [`portscan`](commands/portscan.md): TCP port scan (connect/banner/version)
- [`hostscan`](commands/hostscan.md): ICMP ping sweep (default: local /24)
- [`arpscan`](commands/arpscan.md): ARP sweep (default: local /24; works even if ICMP is blocked)
- [`nbtscan`](commands/nbtscan.md): NetBIOS node status sweep (default: local /24, no credentials)
- [`nslookup`](commands/nslookup.md): DNS lookup of any record type
- [`discover`](commands/discover.md): Find UPnP/SSDP + mDNS/Bonjour devices (multicast)
- [`snmp`](commands/snmp.md): SNMP v1 sysDescr check (default community public)
- [`dhcp`](commands/dhcp.md): Show this station's DHCP lease details

### active directory

- [`smbrecon`](commands/smbrecon.md): SMB2 recon; anonymous banner, or authed check/spray across a range
- [`smbshares`](commands/smbshares.md): List the server's SMB shares (SRVSVC)
- [`ldaprecon`](commands/ldaprecon.md): LDAP recon: anonymous RootDSE, or authed user/password-policy enum
- [`kerbrute`](commands/kerbrute.md): Kerberos AS-REQ username enumeration
- [`asreproast`](commands/asreproast.md): AS-REP roasting (no credentials needed)
- [`kerberoast`](commands/kerberoast.md): Kerberoasting (needs valid creds; experimental)

### mitm & poisoning

- [`arpspoof`](commands/arpspoof.md): ARP cache poisoning - whole subnet or one target
- [`responder`](commands/responder.md): LLMNR/NBT-NS poisoning + NTLM/Basic credential trap
- [`dnsspoof`](commands/dnsspoof.md): Forge DNS A answers on the MITM relay (needs arpspoof)

### capture

- [`pcap`](commands/pcap.md): Packet capture to SD (Ethernet; -w = raw 802.11)

### pivot

- [`wireguard`](commands/wireguard.md): WireGuard pivot tunnel from a wg-quick config file
- [`socks5`](commands/socks5.md): SOCKS5 proxy to pivot into the LAN (over WireGuard)

### files

- [`ls`](commands/ls.md): List files on the SD card or an SMB share
- [`cat`](commands/cat.md): Print a file (SD or SMB share)
- [`echo`](commands/echo.md): Print text, or write/append it to a file
- [`rm`](commands/rm.md): Delete a file (SD or SMB share)
- [`mkdir`](commands/mkdir.md): Create a directory (SD or SMB share)
- [`rmdir`](commands/rmdir.md): Remove an empty directory (SD or SMB share)
- [`mv`](commands/mv.md): Rename/move a file on the SD card
- [`cp`](commands/cp.md): Copy a file on the SD card
- [`get`](commands/get.md): Download a file from an SMB share to the SD card
- [`put`](commands/put.md): Upload a file from the SD card to an SMB share
- [`stat`](commands/stat.md): Show a file's type and size
- [`df`](commands/df.md): Show SD card space usage

### system

- [`help`](commands/help.md): List all commands, or show detailed help for one
- [`settings`](commands/settings.md): Edit SD pins + network identity (hostname/MAC)
- [`run`](commands/run.md): Run CLI commands from an SD script file
- [`delay`](commands/delay.md): Pause (for scripts/autorun); Ctrl+C skips
- [`loot`](commands/loot.md): List or clear captured loot in /loot
- [`date`](commands/date.md): Show the current UTC time (NTP-synced on connect)
- [`mount`](commands/mount.md): Export the SD card to the host as a USB drive
- [`unmount`](commands/unmount.md): Stop exporting the SD card and reclaim it
- [`clear`](commands/clear.md): Clear the terminal screen
- [`reboot`](commands/reboot.md): Restart the device
