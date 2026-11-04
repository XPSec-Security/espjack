#include "hostscan.h"
#include <WiFi.h>
#include <ArduinoJson.h>
#include <ESP32Ping.h>
#include <vector>
#include "../common/iprange.h"

// Unlike PortScan/ArpScan/NbtScan, this sweep stays single-task: the
// bundled ESP32Ping library tracks its state in PingClass static members
// (_expected_count/_errors/_success/_avg_time) shared by every instance,
// so concurrent Ping.ping() calls from multiple tasks would corrupt each
// other's counters. ArpScan is the parallel-safe alternative for host
// discovery if this feels slow.
namespace {
    volatile bool g_running = false;
    volatile bool g_stopReq = false;
    volatile uint32_t g_done = 0;
    uint32_t g_total = 254;
    IPAddress g_base;  // network address (last octet 0)
    std::vector<String> g_hosts;
    SemaphoreHandle_t g_mtx = nullptr;
    TaskHandle_t g_task = nullptr;

    // Generic [rangeBaseU32 + rangeStart, rangeBaseU32 + rangeStart + total)
    // index range, set by start() before the task is spawned.
    uint32_t g_rangeBaseU32 = 0;
    uint32_t g_rangeStart = 0;

    void scanTask(void *) {
        IPAddress ip = WiFi.localIP();

        for (uint32_t idx = g_rangeStart; idx < g_rangeStart + g_total; ++idx) {
            if (g_stopReq) break;
            IPAddress target = u32ToIp(g_rangeBaseU32 + idx);

            // Do not ping ourselves, but count us as "up".
            bool up;
            if (target == ip) {
                up = true;
            } else {
                up = Ping.ping(target, 1);  // 1 attempt
            }

            if (up) {
                if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
                g_hosts.push_back(target.toString());
                if (g_mtx) xSemaphoreGive(g_mtx);
            }
            g_done++;
            vTaskDelay(1);
        }
        g_running = false;
        g_task = nullptr;
        vTaskDelete(nullptr);
    }
}

namespace HostScan {

bool start(const IPAddress &rangeBase, uint32_t rangeCount) {
    if (g_running) return false;
    if (WiFi.status() != WL_CONNECTED) return false;

    if (!g_mtx) g_mtx = xSemaphoreCreateMutex();

    if (rangeCount > 0) {
        g_rangeBaseU32 = ipToU32(rangeBase);
        g_rangeStart = 0;
        g_total = rangeCount;
        g_base = rangeBase;
    } else {
        IPAddress ip = WiFi.localIP();
        IPAddress mask = WiFi.subnetMask();
        IPAddress subnetBase(ip[0] & mask[0], ip[1] & mask[1], ip[2] & mask[2], 0);
        g_rangeBaseU32 = ipToU32(subnetBase);
        g_rangeStart = 1;
        g_total = 254;
        g_base = subnetBase;
    }

    g_done = 0;
    g_stopReq = false;

    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    g_hosts.clear();
    if (g_mtx) xSemaphoreGive(g_mtx);

    g_running = true;
    xTaskCreatePinnedToCore(scanTask, "hostscan", 4096, nullptr, 1, &g_task, 0);
    return true;
}

void stop() {
    g_stopReq = true;
}

String status() {
    JsonDocument doc;
    doc["running"] = g_running;
    doc["done"]    = g_done;
    doc["total"]   = g_total;
    doc["base"]    = g_base.toString();

    JsonArray arr = doc["hosts"].to<JsonArray>();
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    for (auto &h : g_hosts) arr.add(h);
    if (g_mtx) xSemaphoreGive(g_mtx);

    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace HostScan
