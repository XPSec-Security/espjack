#include "pcap.h"
#include "../../config.h"
#include "../mitm/nettap.h"
#include <SD.h>
#include <WiFi.h>
#include <ArduinoJson.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/ringbuf.h>
#include <sys/time.h>

namespace {
    const size_t SNAPLEN = 512;         // bytes kept per frame (full DNS + all headers)
    const size_t RB_SIZE = 48 * 1024;   // capture ring buffer

    // LINKTYPE_ETHERNET (1): decrypted Ethernet frames tapped from the
    // station data path (real IP/DNS; with arpspoof on, the victims' too).
    // LINKTYPE_IEEE802_11 (105): raw 802.11 via promiscuous mode.
    const uint32_t DLT_ETHERNET = 1;
    const uint32_t DLT_80211 = 105;

    volatile bool g_running = false;
    volatile bool g_stopReq = false;
    bool g_wifiMode = false;
    String g_file;
    volatile uint32_t g_packets = 0;
    volatile uint32_t g_bytes = 0;
    volatile uint32_t g_dropped = 0;

    RingbufHandle_t g_rb = nullptr;
    TaskHandle_t g_task = nullptr;

    #pragma pack(push, 1)
    struct PcapGlobalHdr {
        uint32_t magic; uint16_t vMajor; uint16_t vMinor;
        int32_t thiszone; uint32_t sigfigs; uint32_t snaplen; uint32_t network;
    };
    struct PcapRecHdr { uint32_t tsSec; uint32_t tsUsec; uint32_t inclLen; uint32_t origLen; };
    #pragma pack(pop)

    // Copies a frame into the ring buffer. Runs in the WiFi task (relay/
    // promiscuous), so it must do no heavy work and no large stack use -
    // xRingbufferSend copies straight from 'data', no intermediate buffer.
    void enqueue(const uint8_t *data, uint32_t len) {
        if (!g_running || g_rb == nullptr || len == 0) return;
        uint32_t l = len > SNAPLEN ? SNAPLEN : len;
        if (xRingbufferSend(g_rb, data, l, 0) != pdTRUE) g_dropped++;
    }

    void ethSink(const uint8_t *eth, uint16_t len) { enqueue(eth, len); }

    void IRAM_ATTR snifferCb(void *buf, wifi_promiscuous_pkt_type_t type) {
        const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
        enqueue(p->payload, p->rx_ctrl.sig_len);
    }

    void writeRec(File &fh, const uint8_t *data, uint32_t len) {
        struct timeval tv;
        gettimeofday(&tv, nullptr);
        PcapRecHdr rh = {(uint32_t)tv.tv_sec, (uint32_t)tv.tv_usec, len, len};
        fh.write((uint8_t *)&rh, sizeof(rh));
        fh.write(data, len);
        g_packets++;
        g_bytes += len;
    }

    void writerTask(void *) {
        File fh = SD.open(g_file.c_str(), FILE_WRITE);
        if (!fh) {
            Serial.printf("[PCAP] Could not open %s\n", g_file.c_str());
            g_running = false; g_task = nullptr; vTaskDelete(nullptr); return;
        }

        PcapGlobalHdr gh = {0xa1b2c3d4, 2, 4, 0, 0, (uint32_t)SNAPLEN,
                            g_wifiMode ? DLT_80211 : DLT_ETHERNET};
        fh.write((uint8_t *)&gh, sizeof(gh));
        fh.flush();

        if (g_wifiMode) {
            esp_wifi_set_promiscuous(true);
            wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA};
            esp_wifi_set_promiscuous_filter(&filter);
            esp_wifi_set_promiscuous_rx_cb(&snifferCb);
        } else {
            NetTap::ensureHook();
            NetTap::setSink(ethSink);
        }

        uint32_t sinceFlush = 0;
        while (!g_stopReq) {
            size_t itemSize = 0;
            uint8_t *item = (uint8_t *)xRingbufferReceive(g_rb, &itemSize, pdMS_TO_TICKS(200));
            if (item) {
                writeRec(fh, item, itemSize);
                vRingbufferReturnItem(g_rb, item);
                if (++sinceFlush >= 16) {
                    fh.flush();
                    sinceFlush = 0;
                    // Yield so the CLI task (same core, same priority) always
                    // gets time even under a constant stream of frames.
                    vTaskDelay(1);
                }
            }
        }

        if (g_wifiMode) esp_wifi_set_promiscuous(false);
        else NetTap::setSink(nullptr);

        // Give any in-flight frames a moment, then drain what's left.
        delay(30);
        for (int i = 0; i < 2048; ++i) {
            size_t itemSize = 0;
            uint8_t *item = (uint8_t *)xRingbufferReceive(g_rb, &itemSize, 0);
            if (!item) break;
            writeRec(fh, item, itemSize);
            vRingbufferReturnItem(g_rb, item);
        }
        fh.flush();
        fh.close();
        Serial.printf("[PCAP] Done: %u packets, %u bytes\n", g_packets, g_bytes);

        g_running = false; g_task = nullptr;
        vTaskDelete(nullptr);
    }
}

namespace Pcap {

bool start(const String &filename, bool wifi80211) {
    if (g_running) return false;
    if (!sdReady()) return false;

    String name = filename;
    name.trim();
    if (name.length() == 0) name = "capture";
    name.replace("/", "_");
    name.replace("\\", "_");
    g_file = "/loot/" + name;
    if (!g_file.endsWith(".pcap")) g_file += ".pcap";

    g_wifiMode = wifi80211;
    g_packets = g_bytes = g_dropped = 0;
    g_stopReq = false;

    if (!g_rb) g_rb = xRingbufferCreate(RB_SIZE, RINGBUF_TYPE_NOSPLIT);
    if (!g_rb) return false;

    g_running = true;
    // Priority 1 (same as the Arduino loop/CLI task) so the scheduler
    // round-robins them instead of the writer starving the console.
    xTaskCreatePinnedToCore(writerTask, "pcap", 8192, nullptr, 1, &g_task, 1);
    return true;
}

void stop() { g_stopReq = true; }

String status() {
    JsonDocument doc;
    doc["running"] = g_running;
    doc["file"]    = g_file;
    doc["mode"]    = g_wifiMode ? "802.11" : "ethernet";
    doc["packets"] = g_packets;
    doc["bytes"]   = g_bytes;
    doc["dropped"] = g_dropped;

    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace Pcap
