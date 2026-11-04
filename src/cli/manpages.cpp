// '<command> -h' / 'help <command>' text. See manpages.h for the layout.
// Each page here is the body AFTER the NAME and USAGE block (which the CLI
// prints from its command table): a single OPTIONS or SUBCOMMANDS section.
// A command with no such section has no entry and shows just NAME + USAGE.
//
// Adding a command or a flag? Add/update its entry below. Descriptions,
// examples and notes are not kept here: they live in the GitHub wiki
// (https://github.com/XPSec-Security/espjack/wiki), one page per command.
#include "manpages.h"
#include <cstring>

namespace {
    struct ManPage { const char *name; const char *text; };

    const ManPage PAGES[] = {
        {"wifi",
            "SUBCOMMANDS\n"
            "    scan                   List nearby access points: SSID, signal (RSSI),\n"
            "                           channel, encryption and BSSID.\n"
            "    connect <ssid> [pass]  Join a network. Omit the password for open\n"
            "                           networks; quote SSIDs with spaces (\"My Net\").\n"
            "                           The password is masked as **** while typing.\n"
            "                           Applies the hostname/MAC overrides from\n"
            "                           'settings' first. Gives up after 20 s; Ctrl+C\n"
            "                           aborts.\n"
            "    disconnect             Drop the current connection and stop auto-\n"
            "                           reconnect.\n"
            "    status                 Show IP, gateway, mask, DNS, MAC, BSSID, RSSI,\n"
            "                           channel and hostname.\n"
        },
        {"portscan",
            "OPTIONS\n"
            "    <target>[/prefix]  One host (192.168.1.10) or a range\n"
            "                       (192.168.1.0/24). Prefix /20 to /32.\n"
            "    -p <start-end>     Port range. Default 1-1024. One port: -p 80-80.\n"
            "    -top               Scan a built-in list of 54 common ports instead.\n"
            "    -s, --syn          SYN scan (half-open): sends a SYN and reads the\n"
            "                       reply, never completing the handshake. Lists open\n"
            "                       ports and counts closed (RST) and filtered (no\n"
            "                       reply). No banner or version; -m is ignored.\n"
            "    -m <0|1|2>         Connect scan: 0 = open/closed only, 1 = also grab\n"
            "                       the banner, 2 = banner + version (default).\n"
            "    -t <ms>            Connect scan: timeout per port. SYN scan: how long\n"
            "                       to wait for late replies. Default 400.\n"
        },
        {"hostscan",
            "OPTIONS\n"
            "    [ip[/prefix]]  Range to sweep, /20 to /32 (a bare IP means just that\n"
            "                   host). Default: the local /24 of the current WiFi\n"
            "                   connection (.1 to .254).\n"
        },
        {"arpscan",
            "OPTIONS\n"
            "    [ip[/prefix]]  Range to sweep, /20 to /32 (a bare IP means just that\n"
            "                   host). Default: the local /24 of the current WiFi\n"
            "                   connection (.1 to .254).\n"
        },
        {"nbtscan",
            "OPTIONS\n"
            "    [ip[/prefix]]  Range to sweep, /20 to /32 (a bare IP means just that\n"
            "                   host). Default: the local /24 of the current WiFi\n"
            "                   connection (.1 to .254).\n"
        },
        {"nslookup",
            "OPTIONS\n"
            "    <name>        Host to look up. For -type PTR you may pass an IP\n"
            "                  directly (it is turned into an in-addr.arpa query).\n"
            "    -type <t>     Record type: A (default), AAAA, CNAME, MX, NS, TXT,\n"
            "                  PTR, SOA, SRV, CAA or ANY.\n"
            "    -server <ip>  Resolver to ask. Default: the network's own DNS.\n"
        },
        {"snmp",
            "OPTIONS\n"
            "    <target>[/prefix]  One SNMP device (UDP/161), or a CIDR block to\n"
            "                       sweep (e.g. 192.168.1.0/24, max /20).\n"
            "    [community]        Community string. Default 'public'.\n"
        },
        {"smbrecon",
            "OPTIONS\n"
            "    <target>[/prefix]  One host, or a CIDR block to sweep (e.g.\n"
            "                       192.168.1.0/24, max /20) - one line per host.\n"
            "    -t <ms>            Authenticated mode only: delay between hosts.\n"
            "                       Default 250. Raise it on a lockout-sensitive\n"
            "                       domain.\n"
            "    --users            Authenticated: enumerate domain user accounts\n"
            "                       (name + RID) over SAMR.\n"
            "    --pass-pol         Authenticated: read the password and lockout\n"
            "                       policy over SAMR.\n"
            "    -u <user>     Username for authenticated mode.\n"
            "    -p <pass>     Password (used unless -H is given).\n"
            "    -H <nthash>   Pass-the-hash: 32-hex-char NT hash (or LM:NT - the NT\n"
            "                  half is used). Use instead of -p.\n"
            "    -d <domain>   Logon domain (AD), NetBIOS name or FQDN. Do not put it in\n"
            "                  -u (no DOMAIN\\user form). Omit it and the domain the\n"
            "                  server announces is used: a domain member or DC means a\n"
            "                  domain login, a standalone box means a local login.\n"
            "    --local-auth  Force the target's local SAM, e.g. a local admin on a\n"
            "                  domain-joined host (domain = the target's computer name).\n"
        },
        {"smbshares",
            "OPTIONS\n"
            "    <target>[/prefix]  One SMB server, or a CIDR block to sweep (e.g.\n"
            "                       192.168.1.0/24, max /20).\n"
            "    -t <ms>            Sweep with credentials only: delay between hosts\n"
            "                       that answer. Default 250.\n"
            "    -u <user>     Username for authenticated mode.\n"
            "    -p <pass>     Password (used unless -H is given).\n"
            "    -H <nthash>   Pass-the-hash: 32-hex-char NT hash (or LM:NT - the NT\n"
            "                  half is used). Use instead of -p.\n"
            "    -d <domain>   Logon domain (AD), NetBIOS name or FQDN. Do not put it in\n"
            "                  -u (no DOMAIN\\user form). Omit it and the domain the\n"
            "                  server announces is used: a domain member or DC means a\n"
            "                  domain login, a standalone box means a local login.\n"
            "    --local-auth  Force the target's local SAM, e.g. a local admin on a\n"
            "                  domain-joined host (domain = the target's computer name).\n"
        },
        {"ldaprecon",
            "OPTIONS\n"
            "    <target>[/prefix]  One host, or a CIDR block to sweep for DCs\n"
            "                       (e.g. 192.168.1.0/24, max /20).\n"
            "    -u <user>          Username (enables authenticated bind).\n"
            "    -p <pass>          Password. LDAP needs a password; -H (pass-the-\n"
            "                       hash) is not supported here.\n"
            "    -d <domain>        Domain; combined with -u as user@domain (UPN).\n"
            "    --users            Enumerate domain user accounts (sAMAccountName).\n"
            "    --pass-pol         Read the domain password policy.\n"
        },
        {"kerbrute",
            "OPTIONS\n"
            "    <kdc>       IP of a domain controller (Kerberos, TCP/88).\n"
            "    <realm>     The AD DNS domain in upper case, e.g. CORP.LOCAL\n"
            "                (ldaprecon/smbrecon show it).\n"
            "    [wordlist]  One username per line on the SD card.\n"
            "                Default /wordlists/users.txt.\n"
        },
        {"asreproast",
            "OPTIONS\n"
            "    <kdc>       IP of a domain controller (Kerberos, TCP/88).\n"
            "    <realm>     The AD DNS domain in upper case, e.g. CORP.LOCAL\n"
            "                (ldaprecon/smbrecon show it).\n"
            "    [wordlist]  One username per line on the SD card.\n"
            "                Default /wordlists/users.txt.\n"
        },
        {"kerberoast",
            "OPTIONS\n"
            "    <kdc>       IP of a domain controller (Kerberos, TCP/88).\n"
            "    <realm>     The AD DNS domain in upper case, e.g. CORP.LOCAL\n"
            "                (ldaprecon/smbrecon show it).\n"
            "    <user>      A valid domain username.\n"
            "    <pass>      Its password.\n"
            "    [wordlist]  One SPN per line on the SD card.\n"
            "                Default /wordlists/spns.txt.\n"
        },
        {"arpspoof",
            "SUBCOMMANDS\n"
            "    on                     Auto: detect the gateway, find every host on\n"
            "                           the local /24 (ARP, 6 workers) and poison all\n"
            "                           of them.\n"
            "    on <victim> <gateway>  Poison a single victim.\n"
            "    off                    Stop and heal the ARP caches.\n"
            "    status                 Mode, phase, gateway, frames sent, victims.\n"
        },
        {"responder",
            "SUBCOMMANDS\n"
            "    on      Start poisoning and the SMB/HTTP servers.\n"
            "    off     Stop.\n"
            "    status  Queries answered and the captures so far (also shown by\n"
            "            'responder' with no arguments).\n"
            "    clear   Forget the captures held in memory (the SD file is kept).\n"
        },
        {"dnsspoof",
            "SUBCOMMANDS\n"
            "    on [ip]  Start forging; answer with 'ip' (default: this device).\n"
            "    off      Stop forging.\n"
            "    status   Whether it's active and how many answers were forged.\n"
        },
        {"pcap",
            "SUBCOMMANDS\n"
            "    start [name] [-w]  Capture to /<name>.pcap (default /capture.pcap).\n"
            "                       -w selects raw 802.11 instead of Ethernet.\n"
            "    stop               Stop and close the file.\n"
            "    status             Mode, packets/bytes written, drops (also shown\n"
            "                       by 'pcap' with no arguments).\n"
        },
        {"socks5",
            "SUBCOMMANDS\n"
            "    on [port]  Start the proxy (default port 1080).\n"
            "    off        Stop it.\n"
            "    status     Running state, port, active/served connections.\n"
        },
        {"wireguard",
            "SUBCOMMANDS\n"
            "    up <file>  Start the tunnel from a config on the SD card.\n"
            "    down       Stop it.\n"
            "    status     Tunnel state, local tunnel IP and endpoint (also shown\n"
            "               by 'wireguard' with no arguments).\n"
        },
        {"ls",
            "OPTIONS\n"
            "    On a remote path, append credentials:\n"
            "      -u <user> -p <pass>   or   -H <nthash>   (NT hash, or LM:NT)\n"
            "      [-d <domain>] [--local-auth]\n"
        },
        {"cat",
            "OPTIONS\n"
            "    On a remote path, append credentials:\n"
            "      -u <user> -p <pass>   or   -H <nthash>   (NT hash, or LM:NT)\n"
            "      [-d <domain>] [--local-auth]\n"
        },
        {"rm",
            "OPTIONS\n"
            "    On a remote path, append credentials:\n"
            "      -u <user> -p <pass>   or   -H <nthash>   (NT hash, or LM:NT)\n"
            "      [-d <domain>] [--local-auth]\n"
        },
        {"mkdir",
            "OPTIONS\n"
            "    On a remote path, append credentials:\n"
            "      -u <user> -p <pass>   or   -H <nthash>   (NT hash, or LM:NT)\n"
            "      [-d <domain>] [--local-auth]\n"
        },
        {"rmdir",
            "OPTIONS\n"
            "    On a remote path, append credentials:\n"
            "      -u <user> -p <pass>   or   -H <nthash>   (NT hash, or LM:NT)\n"
            "      [-d <domain>] [--local-auth]\n"
        },
        {"get",
            "OPTIONS\n"
            "    //host/share/file  Remote source path.\n"
            "    <sd-path>          Local destination on the SD card.\n"
            "    On a remote path, append credentials:\n"
            "      -u <user> -p <pass>   or   -H <nthash>   (NT hash, or LM:NT)\n"
            "      [-d <domain>] [--local-auth]\n"
        },
        {"put",
            "OPTIONS\n"
            "    <sd-path>          Local source on the SD card.\n"
            "    //host/share/file  Remote destination path.\n"
            "    On a remote path, append credentials:\n"
            "      -u <user> -p <pass>   or   -H <nthash>   (NT hash, or LM:NT)\n"
            "      [-d <domain>] [--local-auth]\n"
        },
        {"settings",
            "SUBCOMMANDS\n"
            "    show                               Print /settings.json.\n"
            "    set sd.<cs|sck|miso|mosi> <gpio>   Change one SD pin (reboot).\n"
            "    set hostname <name>                DHCP hostname ('' = default).\n"
            "    set mac <AA:BB:CC:DD:EE:FF>        Spoof the STA MAC ('' = real).\n"
            "    reset                              Restore all defaults.\n"
        },
        {"run",
            "OPTIONS\n"
            "    <file>  Script path on the SD card (e.g. /scripts/recon.txt).\n"
        },
        {"loot",
            "SUBCOMMANDS\n"
            "    list   Show loot files and total size (default).\n"
            "    clear  Delete all files in /loot.\n"
        },
    };
}

const char *manPage(const char *name) {
    for (auto &p : PAGES) {
        if (strcmp(p.name, name) == 0) return p.text;
    }
    return nullptr;
}
