#pragma once
#include <Arduino.h>
#include <IPAddress.h>

// Shared by every host-sweep module (arpscan/hostscan/nbtscan/portscan) so
// they all accept the same "<ip>[/prefix]" range syntax from the CLI.

inline uint32_t ipToU32(const IPAddress &ip) {
    return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) | ((uint32_t)ip[2] << 8) | (uint32_t)ip[3];
}

inline IPAddress u32ToIp(uint32_t v) {
    return IPAddress((v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF);
}

// Parses "a.b.c.d[/prefix]" into a [base, base+count) host range. No
// '/prefix' means a single host (count=1). 'base' is the network address
// (host bits zeroed), matching normal CIDR notation. Capped at /20 (4096
// hosts) so a sweep from a single device still finishes in reasonable time.
inline bool parseIpRange(const String &in, IPAddress &base, uint32_t &count, String &err) {
    int slash = in.indexOf('/');
    String ipPart = slash >= 0 ? in.substring(0, slash) : in;

    IPAddress ip;
    if (!ip.fromString(ipPart)) { err = "Invalid IP."; return false; }

    int prefix = 32;
    if (slash >= 0) {
        prefix = in.substring(slash + 1).toInt();
        if (prefix < 20 || prefix > 32) { err = "Prefix must be between /20 and /32 (max 4096 hosts)."; return false; }
    }

    uint32_t hostBits = 32 - (uint32_t)prefix;
    uint32_t size = 1UL << hostBits;
    uint32_t mask = hostBits == 0 ? 0xFFFFFFFFu : ~((1UL << hostBits) - 1);
    base = u32ToIp(ipToU32(ip) & mask);
    count = size;
    return true;
}
