#include "config.h"
#include <SPI.h>
#include <SD.h>
#include <LittleFS.h>
#include <ArduinoJson.h>

namespace {
    bool g_sdReady = false;
    const char *SETTINGS_PATH = "/settings.json";

    // Resolved at runtime from settings.json, defaulting to the compiled-in
    // Cardputer ADV pins above.
    int g_cs = ESPJACK_SD_CS, g_sck = ESPJACK_SD_SCK, g_miso = ESPJACK_SD_MISO, g_mosi = ESPJACK_SD_MOSI;

    // Network identity (empty = use the hardware default). Applied by the
    // 'wifi connect' command before associating, so the device can blend in.
    String g_hostname = "";
    String g_mac = "";

    // Dedicated SPI bus for the SD card.
    SPIClass g_sdSpi(HSPI);

    void writeSettingsFile() {
        JsonDocument doc;
        doc["sd"]["cs"] = g_cs;
        doc["sd"]["sck"] = g_sck;
        doc["sd"]["miso"] = g_miso;
        doc["sd"]["mosi"] = g_mosi;
        doc["hostname"] = g_hostname;
        doc["mac"] = g_mac;

        File f = LittleFS.open(SETTINGS_PATH, "w");
        if (!f) { Serial.println("[SETTINGS] Could not write " + String(SETTINGS_PATH)); return; }
        serializeJsonPretty(doc, f);
        f.close();
    }
}

void loadSettings() {
    if (!LittleFS.begin(true /*formatOnFail*/)) {
        Serial.println("[SETTINGS] LittleFS mount failed; using compiled-in SD pin defaults.");
        return;
    }

    if (!LittleFS.exists(SETTINGS_PATH)) {
        Serial.println("[SETTINGS] No " + String(SETTINGS_PATH) + " yet, creating it with defaults.");
        writeSettingsFile();
        return;
    }

    File f = LittleFS.open(SETTINGS_PATH, "r");
    if (!f) { Serial.println("[SETTINGS] Could not open " + String(SETTINGS_PATH) + "; using defaults."); return; }

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, f);
    f.close();
    if (err) {
        Serial.printf("[SETTINGS] %s is malformed (%s); using defaults.\n", SETTINGS_PATH, err.c_str());
        return;
    }

    g_cs   = doc["sd"]["cs"]   | g_cs;
    g_sck  = doc["sd"]["sck"]  | g_sck;
    g_miso = doc["sd"]["miso"] | g_miso;
    g_mosi = doc["sd"]["mosi"] | g_mosi;
    g_hostname = (const char *)(doc["hostname"] | "");
    g_mac      = (const char *)(doc["mac"] | "");
    Serial.printf("[SETTINGS] SD pins: cs=%d sck=%d miso=%d mosi=%d\n", g_cs, g_sck, g_miso, g_mosi);
    if (g_hostname.length()) Serial.printf("[SETTINGS] hostname: %s\n", g_hostname.c_str());
    if (g_mac.length()) Serial.printf("[SETTINGS] mac override: %s\n", g_mac.c_str());
}

int sdPinCs()   { return g_cs; }
int sdPinSck()  { return g_sck; }
int sdPinMiso() { return g_miso; }
int sdPinMosi() { return g_mosi; }

bool setSdPinSetting(const String &key, int value) {
    if (key == "cs") g_cs = value;
    else if (key == "sck") g_sck = value;
    else if (key == "miso") g_miso = value;
    else if (key == "mosi") g_mosi = value;
    else return false;
    writeSettingsFile();
    return true;
}

String netHostname() { return g_hostname; }
String netMac() { return g_mac; }

bool setNetSetting(const String &key, const String &value) {
    if (key == "hostname") g_hostname = value;
    else if (key == "mac") g_mac = value;
    else return false;
    writeSettingsFile();
    return true;
}

void resetSettings() {
    g_cs = ESPJACK_SD_CS; g_sck = ESPJACK_SD_SCK; g_miso = ESPJACK_SD_MISO; g_mosi = ESPJACK_SD_MOSI;
    g_hostname = "";
    g_mac = "";
    writeSettingsFile();
}

String settingsJsonText() {
    File f = LittleFS.open(SETTINGS_PATH, "r");
    if (!f) return "{}";
    String out = f.readString();
    f.close();
    return out;
}

bool initSD() {
    // Some Cardputer-family boards share GPIO5 with other peripherals and
    // need it actively driven high for the SD card to enumerate correctly.
    // Harmless on boards where that pin is unused.
    pinMode(5, OUTPUT);
    digitalWrite(5, HIGH);

    g_sdSpi.begin(g_sck, g_miso, g_mosi, g_cs);
    if (!SD.begin(g_cs, g_sdSpi)) {
        Serial.println("[SD] Not mounted (ok: PCAP/wordlists/downloads will be unavailable).");
        g_sdReady = false;
        return false;
    }
    if (SD.cardType() == CARD_NONE) {
        Serial.println("[SD] No card present.");
        g_sdReady = false;
        return false;
    }
    Serial.printf("[SD] Mounted. ~%llu MB free\n",
                  (SD.totalBytes() - SD.usedBytes()) / (1024ULL * 1024ULL));
    if (!SD.exists("/loot")) SD.mkdir("/loot");   // standard loot directory
    g_sdReady = true;
    return true;
}

bool sdReady() {
    return g_sdReady;
}
