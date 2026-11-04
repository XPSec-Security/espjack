# settings

Category: system

Summary: Edit SD pins + network identity (hostname/MAC)

Usage:

```
settings show | set <key> <value> | reset
```

Manual:

```
DESCRIPTION
    Device settings, kept in /settings.json on the ESP32's internal
    flash (not on the SD card, since the SD pins must be known before
    the card can be read). Holds the SD card's SPI pins (default: M5
    Cardputer ADV, cs=12 sck=40 miso=39 mosi=14) and the network
    identity used to blend in: hostname (what the router/DHCP shows)
    and a MAC override (the real MAC's Espressif OUI otherwise
    fingerprints the device). SD-pin changes need a 'reboot'; hostname
    and MAC apply on the next 'wifi connect'.

SUBCOMMANDS
    show                               Print /settings.json.
    set sd.<cs|sck|miso|mosi> <gpio>   Change one SD pin (reboot).
    set hostname <name>                DHCP hostname ('' = default).
    set mac <AA:BB:CC:DD:EE:FF>        Spoof the STA MAC ('' = real).
    reset                              Restore all defaults.

EXAMPLES
    root@espjack# settings set hostname Galaxy-S23
    Saved. Takes effect on the next 'wifi connect'.

    root@espjack# settings set mac 60:83:E7:11:22:33
    Saved. Takes effect on the next 'wifi connect'.

    root@espjack# settings show
    {
      "sd": { "cs": 12, "sck": 40, "miso": 39, "mosi": 14 },
      "hostname": "Galaxy-S23",
      "mac": "60:83:E7:11:22:33"
    }

    root@espjack# settings reset
    Reset to defaults. Run 'reboot' for it to take effect.

NOTES
    Pick a hostname/MAC-OUI that matches real devices on the target
    network. 'wifi status' shows the hostname the network sees.
```
