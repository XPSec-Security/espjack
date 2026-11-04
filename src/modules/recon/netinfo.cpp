#include "netinfo.h"
#include <WiFi.h>
#include <ArduinoJson.h>

String netinfoJson() {
    JsonDocument doc;
    doc["ssid"]     = WiFi.SSID();
    doc["ip"]       = WiFi.localIP().toString();
    doc["gateway"]  = WiFi.gatewayIP().toString();
    doc["subnet"]   = WiFi.subnetMask().toString();
    doc["dns"]      = WiFi.dnsIP().toString();
    doc["mac"]      = WiFi.macAddress();
    doc["bssid"]    = WiFi.BSSIDstr();
    doc["rssi"]     = WiFi.RSSI();
    doc["channel"]  = WiFi.channel();
    doc["hostname"] = WiFi.getHostname() ? WiFi.getHostname() : "";

    String out;
    serializeJson(doc, out);
    return out;
}
