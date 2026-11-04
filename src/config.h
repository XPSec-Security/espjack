#pragma once
#include <Arduino.h>

// Compiled-in fallback microSD pins (SPI) - these match the M5Stack
// Cardputer ADV wiring. They're only used if /settings.json (on internal
// LittleFS, loaded by loadSettings()) doesn't override them, so flashing
// onto a different ESP32-S3 board just means editing settings.json, no
// recompile needed.
#ifndef ESPJACK_SD_CS
#define ESPJACK_SD_CS 12
#endif
#ifndef ESPJACK_SD_SCK
#define ESPJACK_SD_SCK 40
#endif
#ifndef ESPJACK_SD_MISO
#define ESPJACK_SD_MISO 39
#endif
#ifndef ESPJACK_SD_MOSI
#define ESPJACK_SD_MOSI 14
#endif

// Loads /settings.json from internal LittleFS, creating it with the
// compiled-in defaults above if it doesn't exist yet. Call once from
// setup(), before initSD().
void loadSettings();

// Current effective SD pins (compiled default, or whatever settings.json
// overrode them to).
int sdPinCs();
int sdPinSck();
int sdPinMiso();
int sdPinMosi();

// Rewrites /settings.json with a new SD pin value (persisted immediately;
// takes effect on the next boot). Returns false on an unknown key.
bool setSdPinSetting(const String &key, int value);

// Network identity overrides (empty string = hardware default), applied by
// 'wifi connect' before associating. Help the device blend into a network:
// hostname is what the router/DHCP shows; mac ("AA:BB:CC:DD:EE:FF") replaces
// the Espressif-OUI MAC that otherwise fingerprints the device.
String netHostname();
String netMac();

// Persists a network setting ("hostname" or "mac") to /settings.json.
// Takes effect on the next 'wifi connect'. Returns false on an unknown key.
bool setNetSetting(const String &key, const String &value);

// Resets /settings.json to the compiled-in defaults.
void resetSettings();

// Returns the raw contents of /settings.json (for the CLI to print).
String settingsJsonText();

// Initialize the SD card (used for wordlists, captures/loot, downloaded
// files and WireGuard config), using the pins resolved by loadSettings().
// Returns false on failure. Most of the CLI still works without it;
// commands that need it report a clear error.
bool initSD();

// Whether the SD card mounted successfully.
bool sdReady();
