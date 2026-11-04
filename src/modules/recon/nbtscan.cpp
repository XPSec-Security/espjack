#include "nbtscan.h"
#include <WiFi.h>
#include <WiFiUdp.h>
#include <ArduinoJson.h>
#include <esp_random.h>
#include <vector>
#include "../common/iprange.h"

namespace {
    volatile bool g_running = false;
    volatile bool g_stopReq = false;
    volatile uint32_t g_done = 0;
    uint32_t g_total = 254;

    struct Host { String ip; String name; String mac; };
    std::vector<Host> g_hosts;
    SemaphoreHandle_t g_mtx = nullptr;
    IPAddress g_self;

    // See the matching fields in recon/arpscan.cpp.
    uint32_t g_rangeBaseU32 = 0;
    uint32_t g_rangeStart = 0;

    // Each worker opens its own UDP socket (a different ephemeral port),
    // so there's no shared state across them like ESP32Ping has.
    const int NUM_WORKERS = 6;
    volatile int g_workersAlive = 0;

    void workerFinished() {
        bool last;
        if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
        g_workersAlive--;
        last = (g_workersAlive == 0);
        if (g_mtx) xSemaphoreGive(g_mtx);
        if (last) g_running = false;
    }

    String macStr(const uint8_t *m) {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
        return String(buf);
    }

    // First-level NetBIOS name encoding: 16 raw bytes -> 32 'A'-'P' chars,
    // framed as a single DNS-style label (len 0x20) + root terminator.
    void encodeWildcardName(uint8_t *out /*34 bytes*/) {
        uint8_t raw[16];
        raw[0] = '*';
        for (int i = 1; i < 16; ++i) raw[i] = 0x00;

        out[0] = 0x20;
        for (int i = 0; i < 16; ++i) {
            out[1 + i * 2]     = 'A' + ((raw[i] >> 4) & 0xF);
            out[1 + i * 2 + 1] = 'A' + (raw[i] & 0xF);
        }
        out[33] = 0x00;
    }

    // Sends an NBSTAT (NODE STATUS) query and parses the primary NetBIOS
    // name + source MAC from the reply.
    bool queryHost(WiFiUDP &udp, const IPAddress &target, String &name, String &mac) {
        uint8_t nameField[34];
        encodeWildcardName(nameField);

        uint8_t pkt[12 + 34 + 4];
        uint16_t txId = (uint16_t)esp_random();
        pkt[0] = txId >> 8; pkt[1] = txId & 0xFF;
        pkt[2] = 0x00; pkt[3] = 0x00; // standard query
        pkt[4] = 0x00; pkt[5] = 0x01; // QDCOUNT=1
        pkt[6] = 0x00; pkt[7] = 0x00;
        pkt[8] = 0x00; pkt[9] = 0x00;
        pkt[10] = 0x00; pkt[11] = 0x00;
        memcpy(pkt + 12, nameField, 34);
        pkt[46] = 0x00; pkt[47] = 0x21; // QTYPE NBSTAT
        pkt[48] = 0x00; pkt[49] = 0x01; // QCLASS IN

        udp.beginPacket(target, 137);
        udp.write(pkt, sizeof(pkt));
        udp.endPacket();

        uint32_t deadline = millis() + 300;
        int n = 0;
        while (millis() < deadline) {
            n = udp.parsePacket();
            if (n > 0) break;
            delay(10);
        }
        if (n <= 0) return false;

        uint8_t buf[512];
        n = udp.read(buf, sizeof(buf) > (size_t)n ? n : sizeof(buf));
        if (n < 12 + 34 + 8 + 2 + 1) return false;

        int pos = 12 + 34 + 8; // skip header + echoed name + type/class/ttl
        uint16_t rdlen = (buf[pos] << 8) | buf[pos + 1];
        pos += 2;
        if (pos + 1 > n) return false;

        uint8_t numNames = buf[pos];
        pos += 1;
        if (pos + numNames * 18 + 6 > n) return false;

        bool gotName = false;
        for (int i = 0; i < numNames; ++i) {
            const uint8_t *entry = buf + pos + i * 18;
            uint8_t suffix = entry[15];
            if (!gotName || suffix == 0x00) {
                String nm;
                for (int c = 0; c < 15 && entry[c] != ' '; ++c) nm += (char)entry[c];
                name = nm;
                gotName = true;
                if (suffix == 0x00) break; // prefer the unique workstation name
            }
        }
        pos += numNames * 18;
        mac = macStr(buf + pos);
        return gotName;
    }

    struct WorkerRange { int start, end; };

    void workerTask(void *arg) {
        WorkerRange range = *(WorkerRange *)arg;
        delete (WorkerRange *)arg;

        WiFiUDP udp;
        udp.begin(0); // ephemeral local port, unique per worker

        for (int idx = range.start; idx < range.end; ++idx) {
            if (g_stopReq) break;
            IPAddress target = u32ToIp(g_rangeBaseU32 + idx);
            if (target == g_self) { g_done++; continue; }

            String name, mac;
            if (queryHost(udp, target, name, mac)) {
                if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
                g_hosts.push_back({target.toString(), name, mac});
                if (g_mtx) xSemaphoreGive(g_mtx);
            }
            g_done++;
        }

        udp.stop();
        workerFinished();
        vTaskDelete(nullptr);
    }
}

namespace NbtScan {

bool start(const IPAddress &rangeBase, uint32_t rangeCount) {
    if (g_running) return false;
    if (WiFi.status() != WL_CONNECTED) return false;
    if (!g_mtx) g_mtx = xSemaphoreCreateMutex();

    g_self = WiFi.localIP();

    if (rangeCount > 0) {
        g_rangeBaseU32 = ipToU32(rangeBase);
        g_rangeStart = 0;
        g_total = rangeCount;
    } else {
        IPAddress mask = WiFi.subnetMask();
        IPAddress subnetBase(g_self[0] & mask[0], g_self[1] & mask[1], g_self[2] & mask[2], 0);
        g_rangeBaseU32 = ipToU32(subnetBase);
        g_rangeStart = 1;
        g_total = 254;
    }

    g_done = 0;
    g_stopReq = false;
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    g_hosts.clear();
    if (g_mtx) xSemaphoreGive(g_mtx);

    int workers = NUM_WORKERS;
    g_workersAlive = workers;
    g_running = true;

    uint32_t perWorker = (g_total + workers - 1) / workers;
    for (int w = 0; w < workers; ++w) {
        uint32_t s = g_rangeStart + (uint32_t)w * perWorker;
        uint32_t e = s + perWorker < g_rangeStart + g_total ? s + perWorker : g_rangeStart + g_total;
        if (s >= e) { workerFinished(); continue; }
        WorkerRange *range = new WorkerRange{(int)s, (int)e};
        TaskHandle_t h = nullptr;
        xTaskCreatePinnedToCore(workerTask, "nbtscan-w", 4096, range, 1, &h, w % 2);
    }
    return true;
}

void stop() { g_stopReq = true; }

String status() {
    JsonDocument doc;
    doc["running"] = g_running;
    doc["done"] = g_done;
    doc["total"] = g_total;

    JsonArray arr = doc["hosts"].to<JsonArray>();
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    for (auto &h : g_hosts) {
        JsonObject o = arr.add<JsonObject>();
        o["ip"] = h.ip;
        o["name"] = h.name;
        o["mac"] = h.mac;
    }
    if (g_mtx) xSemaphoreGive(g_mtx);

    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace NbtScan
