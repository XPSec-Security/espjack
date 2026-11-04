#pragma once
#include <Arduino.h>

// Local subnet host discovery via ICMP ping sweep.
// Assumes a /24 mask derived from the current IP/mask.
namespace HostScan {
    // With no args, sweeps the local /24. Pass 'rangeCount' > 0 to instead
    // sweep exactly ['rangeBase', 'rangeBase' + rangeCount) - see cli.cpp's
    // use of parseIpRange() for the "<ip>[/prefix]" syntax this implements.
    // Returns false if one is already running.
    bool start(const IPAddress &rangeBase = IPAddress(0, 0, 0, 0), uint32_t rangeCount = 0);

    // Stop the sweep.
    void stop();

    // JSON: {running, done, total, base, hosts:[...]}
    String status();
}
