This folder holds templates for what goes on the microSD card. Copy the
files you want to the card's root (dropping the `.example` suffix) and edit
as needed. None of this requires a rebuild.

## settings.json.example

This one is different from the rest: it is a reference copy of the schema,
not a file the firmware reads from the SD card. The real `/settings.json`
lives on the device's internal flash (LittleFS), because the SD pins have
to be known before the SD card can be read at all, so storing them on the
card itself would be circular.

Do not copy this file to the SD card expecting it to be read. Instead, edit
the live settings with the `settings` command on the device:

```
settings show
settings set sd.cs 12
settings set sd.sck 40
settings set sd.miso 39
settings set sd.mosi 14
settings set hostname MyPhone
settings set mac AA:BB:CC:DD:EE:FF
settings reset
```

Changing an `sd.*` pin needs a `reboot` to take effect; `hostname` and `mac`
take effect on the next `wifi connect`.

## autorun.txt.example

Copy to `/autorun.txt` on the card to have it run automatically on every
boot, after a 3 second Ctrl+C cancel window. One CLI command per line,
blank lines and `#` comments are ignored.

## scripts/

Example payloads for the `run <file>` command, which executes any script on
the card the same way autorun does, on demand instead of at boot:

```
run /scripts/recon-sweep.txt
```

- `recon-sweep.txt.example`: read-only discovery, no poisoning or capture.
- `ad-check.txt.example`: zero-credential Active Directory recon against a
  domain controller.

## wordlists/

- `users.txt.example`: one username per line. Default path for `kerbrute`
  and `asreproast` (`/wordlists/users.txt`).
- `spns.txt.example`: one `service/host[:port]` per line. Default path for
  `kerberoast` (`/wordlists/spns.txt`).

## loot/

Created automatically on first boot with a card present. Everything the
tools capture lands here on its own (Responder hashes, pcap files); nothing
to copy ahead of time. Manage it with the `loot` command, or pull files off
with `mount` (USB drive) or over an SMB share with `get`/`put`.
