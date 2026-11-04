# ESPJack

**An ESP32-S3 Offensive Security Toolkit.**

ESPJack is a lightweight, command-line security toolkit designed for ESP32-S3 devices. Built for security research, penetration testing and authorized network assessments, it brings network reconnaissance, traffic interception, Active Directory enumeration and post-exploitation capabilities into a compact embedded platform.

No display. No web interface. Just a USB serial connection and a powerful CLI.

---

## Features

| Category | Capabilities |
|---|---|
| **Network** | Wi-Fi scanning, connection and network discovery |
| **Reconnaissance** | Host discovery, port scanning, DNS, SNMP and DHCP |
| **Active Directory** | SMB, LDAP, Kerberos, AS-REP Roasting and Kerberoasting |
| **MITM** | ARP spoofing, DNS spoofing and Responder |
| **Capture** | Network packet capture and PCAP export |
| **Pivoting** | WireGuard tunnel and SOCKS5 proxy |
| **File System** | File management, SMB transfers and SD card access |
| **Automation** | Scripts, payload execution and automatic startup |

## How It Works

ESPJack runs directly on the ESP32-S3 and exposes a Linux-style command-line interface through its native USB serial connection.

Getting started takes just a few steps:

1. Flash the firmware onto your ESP32-S3.
2. Connect the device to your computer via USB.
3. Open a serial terminal at `115200` baud.
4. Connect to a Wi-Fi network.
5. Start running commands.

```bash
wifi scan
wifi connect <ssid> <password>
help
```

ESPJack also supports scripts stored on the microSD card, including automatic execution at startup through `/autorun.txt`.

## Hardware Requirements

- ESP32-S3 development board.
- Native USB connection.
- microSD card (optional, required for storage-dependent features).

The firmware targets the generic `esp32-s3-devkitc-1` PlatformIO board definition and supports different ESP32-S3 development boards.

### microSD Configuration

The default SPI configuration follows the M5Stack Cardputer ADV wiring:

| Signal | GPIO |
|---|---:|
| CS | 12 |
| SCK | 40 |
| MISO | 39 |
| MOSI | 14 |
| Card enable | 5 |

Custom GPIO assignments can be configured without rebuilding the firmware.

See [SD Card Setup](https://github.com/XPSec-Security/espjack/wiki) for details.

## Installation

### Build and Flash

ESPJack uses [PlatformIO](https://platformio.org/) for firmware development and deployment.

Clone the repository:

```bash
git clone https://github.com/XPSec-Security/espjack.git
cd espjack
```

Build and upload:

```bash
pio run -t upload
```

Open the serial monitor:

```bash
pio device monitor
```

PlatformIO automatically installs the dependencies defined in `platformio.ini`.

## Serial Console

ESPJack communicates through the ESP32-S3 native USB serial interface.

**Connection settings:**

| Parameter | Value |
|---|---|
| Baud rate | 115200 |
| Data bits | 8 |
| Parity | None |
| Stop bits | 1 |

Install pySerial:

```bash
pip install pyserial
```

**Windows**

```bash
python -m serial.tools.miniterm COM8 115200
```

**Linux / macOS**

```bash
python -m serial.tools.miniterm /dev/ttyACM0 115200
```

To list available serial ports:

```bash
python -m serial.tools.list_ports
```

Once connected, you should see the ESPJack shell:

```text
root@espjack#
```

Use `Ctrl+C` to interrupt a running command and `Ctrl+]` to exit miniterm.

## SD Card Setup

The microSD card provides persistent storage for scripts, wordlists, packet captures and collected data.

### Directory Structure

```text
/
├── autorun.txt
├── scripts/
├── wordlists/
│   ├── users.txt
│   └── spns.txt
└── loot/
    ├── responder_ntlm.txt
    └── captures.pcap
```

Sample wordlists are available in:

```text
sd_card/wordlists/
```

Copy the desired `.example` files to `/wordlists/` and remove the `.example` extension.

The `/loot` directory is created automatically when a microSD card is detected.

### Device Settings

ESPJack stores device settings in its internal flash at `/settings.json`.

Examples:

```bash
settings show

settings set sd.cs 10
settings set sd.sck 12
settings set sd.miso 13
settings set sd.mosi 11

settings set hostname MyDevice
settings set mac AA:BB:CC:DD:EE:FF

settings reset
```

Changes to SD card GPIO assignments require a reboot.

### Autorun

ESPJack supports automatic command execution during startup.

Create `/autorun.txt` on the microSD card:

```bash
wifi connect <ssid> <password>
delay 3000
arpspoof on
responder on
pcap start sweep
```

The autorun process starts approximately three seconds after boot. Press `Ctrl+C` during this window to cancel execution.

## Command Reference

ESPJack provides a collection of tools organized into functional categories.

| Category | Commands |
|---|---|
| **Network** | `wifi`, `download` |
| **Reconnaissance** | `portscan`, `hostscan`, `arpscan`, `nbtscan`, `nslookup`, `discover`, `snmp`, `dhcp` |
| **Active Directory** | `smbrecon`, `smbshares`, `ldaprecon`, `kerbrute`, `asreproast`, `kerberoast` |
| **MITM & Poisoning** | `arpspoof`, `responder`, `dnsspoof` |
| **Capture** | `pcap` |
| **Pivoting** | `wireguard`, `socks5` |
| **File Management** | `ls`, `cat`, `echo`, `rm`, `mkdir`, `rmdir`, `mv`, `cp`, `get`, `put`, `stat`, `df` |
| **System** | `help`, `settings`, `run`, `delay`, `loot`, `date`, `mount`, `unmount`, `clear`, `reboot` |

For a complete command reference, run:

```bash
help
```

To display detailed documentation and available options for a specific command:

```bash
<command> -h
```

Or:

```bash
help <command>
```

Visit the [ESPJack Wiki](https://github.com/XPSec-Security/espjack/wiki) for detailed documentation and usage examples.

## Technical Notes & Limitations

ESPJack is designed around the capabilities and constraints of the ESP32-S3 platform.

- **Scanning:** Uses TCP connect and application-layer techniques rather than raw SYN scanning.
- **Protocol implementations:** SMB2, LDAP, Kerberos and SOCKS5 are lightweight, custom implementations focused on the functionality required by the toolkit.
- **ARP spoofing:** Uses a custom Layer 2 relay to keep intercepted devices connected during authorized testing.
- **SOCKS5:** Supports CONNECT only. BIND and UDP ASSOCIATE are not implemented.
- **Concurrent connections:** Limited by the ESP32-S3 networking stack and available socket resources.
- **Kerberoasting:** Experimental implementation using RC4-HMAC Kerberos cryptography.
- **AS-REP Roasting:** Does not require password decryption to retrieve the relevant authentication material.

Performance and compatibility may vary depending on the target network, hardware and server configuration.

## Security & Responsible Use

ESPJack includes active security testing and network interception capabilities.

It is intended exclusively for:

- Authorized penetration testing.
- Security research and education.
- Controlled laboratory environments.
- Networks and systems you own or have explicit permission to assess.

**Never use ESPJack against systems or networks without proper authorization.**

The user is responsible for complying with applicable laws, regulations and engagement scopes.

## Documentation

For detailed guides, command references and configuration instructions:

**[ESPJack Wiki](https://github.com/XPSec-Security/espjack/wiki)**

## License

See the repository for licensing information.

---

**ESPJack** · Developed by [XPSec Security](https://github.com/XPSec-Security)
