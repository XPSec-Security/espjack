#include "wireguard.h"
#include <WiFi.h>
#include <ArduinoJson.h>
#include <WireGuard-ESP32.h>

namespace {
    WireGuard wg;
    bool g_up = false;
    WireGuardPivot::Config g_cfg;
}

namespace WireGuardPivot {

bool start(const Config &cfg) {
    if (WiFi.status() != WL_CONNECTED) return false;
    if (cfg.localIp.length() == 0 || cfg.privateKey.length() == 0 ||
        cfg.endpoint.length() == 0 || cfg.endpointPublicKey.length() == 0) {
        return false;
    }

    IPAddress local;
    if (!local.fromString(cfg.localIp)) return false;

    g_cfg = cfg;
    bool ok = wg.begin(local, cfg.privateKey.c_str(), cfg.endpoint.c_str(),
                        cfg.endpointPublicKey.c_str(), cfg.endpointPort, 0,
                        cfg.presharedKey.length() ? cfg.presharedKey.c_str() : nullptr);
    g_up = ok;
    Serial.printf("[WG] begin() -> %s (tunnel ip %s, peer %s:%u)\n",
                  ok ? "ok" : "FAILED", cfg.localIp.c_str(),
                  cfg.endpoint.c_str(), cfg.endpointPort);
    return ok;
}

void stop() {
    if (g_up) {
        wg.end();
        g_up = false;
    }
}

bool isUp() {
    return g_up;
}

String status() {
    JsonDocument doc;
    doc["running"] = g_up;
    doc["localIp"] = g_cfg.localIp;
    doc["endpoint"] = g_cfg.endpoint;
    doc["port"] = g_cfg.endpointPort;

    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace WireGuardPivot
