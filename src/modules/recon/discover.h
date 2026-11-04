#pragma once
#include <Arduino.h>

// Passive-ish service discovery on the local segment, without a port sweep:
//  - SSDP/UPnP: multicast M-SEARCH, collects responding devices (routers,
//    media servers, cameras, printers...).
//  - mDNS/Bonjour: multicast service enumeration (_services._dns-sd._udp).
// Both are multicast, so they work from a normal station without poisoning.
namespace Discover {
    // Runs both sweeps (a few seconds) and returns JSON:
    //   {ssdp:[{ip,info}], mdns:[{ip,name}]}
    String run();
}
