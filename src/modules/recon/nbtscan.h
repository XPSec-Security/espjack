#pragma once
#include <Arduino.h>

// NetBIOS Node Status ("nbtstat -A" / nbtscan equivalent) sweep of the
// local /24: for each host, sends an unauthenticated NBT-NS NODE STATUS
// query (UDP/137) and extracts the primary NetBIOS name and MAC address
// from the reply. Zero credentials, works against any legacy-NetBIOS-
// enabled Windows host regardless of domain membership.
namespace NbtScan {
    // With no args, sweeps the local /24. Pass 'rangeCount' > 0 to instead
    // sweep exactly ['rangeBase', 'rangeBase' + rangeCount) - see cli.cpp's
    // use of parseIpRange() for the "<ip>[/prefix]" syntax this implements.
    bool start(const IPAddress &rangeBase = IPAddress(0, 0, 0, 0), uint32_t rangeCount = 0);
    void stop();

    // JSON: {running, done, total, hosts:[{ip,name,mac}]}
    String status();
}
