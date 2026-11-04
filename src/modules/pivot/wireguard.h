#pragma once
#include <Arduino.h>

// WireGuard pivot: brings up a WireGuard tunnel so a remote peer (your
// attack box / C2) gets routed, encrypted access into the network this
// device is currently sitting on — i.e. this device acts as the pivot/jump
// host. Configured from a standard wg-quick style .conf/.wg0 file on the
// SD card (see cli/wgconfig.h for the parser); the `wireguard up <file>`
// CLI command wires the two together.
//
// Requires the device to already be connected to the target WiFi network.
//
// Caveats (be upfront about them):
//  - This library implements WireGuard as a client-style tunnel on top of
//    lwIP; it does not do kernel-level routing. Traffic you want reachable
//    from the far end must be something this device itself proxies/forwards
//    at the application layer (e.g. the attack modules below act as that
//    traffic source), not arbitrary third-party packets on the LAN.
//  - Only one peer (your WireGuard server) is supported, matching the
//    library's scope.
namespace WireGuardPivot {
    struct Config {
        String localIp;      // tunnel address assigned to this device, e.g. "10.8.0.2"
        String privateKey;   // this device's WireGuard private key (base64)
        String endpoint;     // remote WireGuard server address/hostname
        uint16_t endpointPort;
        String endpointPublicKey; // remote server's public key (base64)
        String presharedKey;      // optional extra symmetric key (base64); "" if unused
    };

    // Brings the tunnel up. Returns false on bad config or if WiFi (STA)
    // isn't connected yet.
    bool start(const Config &cfg);

    void stop();
    bool isUp();

    // JSON: {running, localIp, endpoint, port}
    String status();
}
