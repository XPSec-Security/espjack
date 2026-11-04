// ESPJack - offensive-security toolkit, serial-CLI only.
//
// Runs on any ESP32-S3 board with a microSD card over SPI. There is no
// web server and no display: everything happens over the USB serial
// console (115200 8N1) through a small Linux-style CLI (see src/cli).
//
// WARNING: this firmware bundles active offensive-security tooling (ARP
// spoofing, LLMNR/NBT-NS poisoning + credential capture, port/host
// scanning, zero-auth AD enumeration, a WireGuard pivot). Use only on
// networks and systems you are explicitly authorized to test.

#include <Arduino.h>
#include "config.h"
#include "cli/cli.h"
#include "modules/system/usbdrive.h"

void setup() {
    Serial.begin(115200);
    delay(300); // let the USB CDC console enumerate before we print anything

    loadSettings();
    initSD();
    UsbDrive::init();   // register the (initially empty) USB drive; 'mount' fills it
    Cli::begin();
    Cli::runAutorun();  // run /autorun.txt if present (cancellable)
}

void loop() {
    Cli::update();
    delay(5);
}
