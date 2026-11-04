#pragma once
#include <Arduino.h>
#include "../modules/pivot/wireguard.h"

// Parses a standard wg-quick style WireGuard config file (.conf/.wg0) from
// the SD card into a WireGuardPivot::Config:
//
//   [Interface]
//   PrivateKey = <base64>
//   Address = 10.8.0.2/24
//
//   [Peer]
//   PublicKey = <base64>
//   PresharedKey = <base64>      ; optional
//   Endpoint = vpn.example.com:51820
//   AllowedIPs = 0.0.0.0/0       ; parsed but not used (see WireGuardPivot)
namespace WgConfig {
    // Returns false and fills 'error' with a human-readable reason on
    // failure (missing file, missing required field, ...).
    bool loadFromFile(const String &path, WireGuardPivot::Config &out, String &error);
}
