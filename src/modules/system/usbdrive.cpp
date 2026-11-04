#include "usbdrive.h"
#include "../../config.h"
#include <SD.h>
#include <ArduinoJson.h>
#include "USB.h"
#include "USBMSC.h"

namespace {
    // File-scope instance on purpose: USBMSC's constructor calls
    // tinyusb_enable_interface(), which must run BEFORE the boot-time
    // USB.begin(). A global runs during C++ static init (before app_main), so
    // the MSC interface makes it into the composite descriptor alongside CDC.
    USBMSC g_msc;
    volatile bool g_mounted = false;
    uint32_t g_sectors = 0;
    const uint16_t SECTOR = 512;

    // TinyUSB may issue a multi-block transfer as one call with a byte
    // 'offset' into the command; the sector is lba + offset/512.
    int32_t onRead(uint32_t lba, uint32_t offset, void *buffer, uint32_t bufsize) {
        uint32_t base = lba + offset / SECTOR;
        uint32_t count = bufsize / SECTOR;
        uint8_t *b = (uint8_t *)buffer;
        for (uint32_t i = 0; i < count; ++i)
            if (!SD.readRAW(b + i * SECTOR, base + i)) return -1;
        return (int32_t)(count * SECTOR);
    }
    int32_t onWrite(uint32_t lba, uint32_t offset, uint8_t *buffer, uint32_t bufsize) {
        uint32_t base = lba + offset / SECTOR;
        uint32_t count = bufsize / SECTOR;
        for (uint32_t i = 0; i < count; ++i)
            if (!SD.writeRAW(buffer + i * SECTOR, base + i)) return -1;
        return (int32_t)(count * SECTOR);
    }
}

namespace UsbDrive {

void init() {
    g_msc.vendorID("ESPJack");
    g_msc.productID("SD Card");
    g_msc.productRevision("1.0");
    g_msc.onRead(onRead);
    g_msc.onWrite(onWrite);
    g_msc.isWritable(true);
    g_msc.mediaPresent(false);            // empty slot until 'mount'
    if (sdReady()) {
        g_sectors = SD.numSectors();
        g_msc.begin(g_sectors, SECTOR);    // sets size; interface already registered
    }
}

bool mount(String &err) {
    if (g_mounted) { err = "already mounted"; return false; }
    if (!sdReady()) { err = "SD card not available"; return false; }
    g_sectors = SD.numSectors();
    if (!g_sectors) { err = "could not read SD size"; return false; }
    g_msc.begin(g_sectors, SECTOR);
    g_msc.mediaPresent(true);
    g_mounted = true;
    return true;
}

void unmount() {
    if (!g_mounted) return;
    g_msc.mediaPresent(false);
    g_mounted = false;
    // Re-read the card so the firmware's FAT reflects the host's changes.
    SD.end();
    initSD();
}

bool isMounted() { return g_mounted; }

String status() {
    JsonDocument doc;
    doc["mounted"] = g_mounted;
    doc["sectors"] = g_sectors;
    doc["sizeMB"] = (double)((uint64_t)g_sectors * SECTOR) / (1024.0 * 1024.0);
    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace UsbDrive
