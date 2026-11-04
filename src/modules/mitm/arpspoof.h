#pragma once
#include <Arduino.h>
#include <IPAddress.h>

// Bidirectional ARP spoofing (cache poisoning) between one or more victims
// and the gateway.
//
// WARNING: Use only on networks you are explicitly authorized to test.
// The ESP32 has a single L2 interface; this module performs ARP cache
// poisoning (interception) but does NOT transparently forward traffic like a
// full router — so it can disrupt victims' connectivity while active.
// On stop it sends corrective frames to "heal" every ARP cache it touched.
namespace ArpSpoof {
    // Start poisoning a single, manually-chosen victim against a manually-
    // chosen gateway. Returns false if already running or if either MAC
    // fails to resolve.
    bool start(const IPAddress &victim, const IPAddress &gateway);

    // Start poisoning the whole local /24: auto-detects the gateway
    // (WiFi.gatewayIP()) and discovers every other live host on the subnet
    // via an ARP sweep, then poisons all of them against the gateway — no
    // manual IP entry needed. Runs the discovery phase first (status()
    // reports phase:"discovering"), then moves into phase:"poisoning".
    // Returns false if already running or if WiFi isn't connected.
    bool startAll();

    // Stop and send corrective frames to every poisoned victim.
    void stop();

    // JSON: {running, mode:"single"|"all", phase:"discovering"|"poisoning",
    //        gateway, gatewayMac, discoverDone, discoverTotal,
    //        victims:[{ip,mac}], sent}
    String status();
}
