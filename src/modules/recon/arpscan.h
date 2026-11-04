#pragma once
#include <Arduino.h>

// ARP-based host discovery for the local /24. Unlike HostScan (ICMP ping
// sweep), this never sends an ICMP packet, so it isn't dropped by host
// firewalls that block ping — it relies purely on layer-2 ARP, which every
// host on the segment must answer to receive any IP traffic at all.
namespace ArpScan {
    // With no args, sweeps the local /24 (as seen from the current WiFi
    // connection). Pass 'rangeCount' > 0 to instead sweep exactly
    // ['rangeBase', 'rangeBase' + rangeCount) - see cli.cpp's use of
    // parseIpRange() for the "<ip>[/prefix]" syntax this implements.
    bool start(const IPAddress &rangeBase = IPAddress(0, 0, 0, 0), uint32_t rangeCount = 0);
    void stop();

    // JSON: {running, done, total, base, hosts:[{ip,mac}]}
    String status();
}
