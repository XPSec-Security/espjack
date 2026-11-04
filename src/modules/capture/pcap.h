#pragma once
#include <Arduino.h>

// Packet capture to a PCAP file on the SD card (openable in Wireshark).
//
// Two modes:
//  - Ethernet (default): decrypted Ethernet frames tapped from the station
//    data path (LINKTYPE_ETHERNET = 1), so real IP/DNS is visible. On its
//    own this only sees our own + broadcast traffic; run it together with
//    'arpspoof on' to capture the victims' traffic (the relay routes it
//    through us), as authorized.
//  - 802.11 (wifi80211=true): raw 802.11 of the associated channel via
//    promiscuous mode (LINKTYPE_IEEE802_11 = 105). Management/control frames
//    are visible; WPA data payloads are encrypted.
namespace Pcap {
    // Start capturing to /<filename>.pcap on the SD card. Returns false if the
    // SD is not ready or a capture is already running.
    bool start(const String &filename, bool wifi80211 = false);

    // Stop the capture and close the file.
    void stop();

    // JSON: {running, file, packets, bytes, dropped}
    String status();
}
