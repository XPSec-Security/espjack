#include "arpscan.h"
#include <WiFi.h>
#include <ArduinoJson.h>
#include <vector>
#include "../common/iprange.h"

extern "C" {
    #include "esp_netif.h"
    #include "esp_netif_net_stack.h"
    #include "lwip/etharp.h"
    #include "lwip/netif.h"
    #include "lwip/tcpip.h" // LOCK_TCPIP_CORE/UNLOCK_TCPIP_CORE
}

namespace {
    volatile bool g_running = false;
    volatile bool g_stopReq = false;
    volatile uint32_t g_done = 0;
    uint32_t g_total = 254;
    IPAddress g_base;

    struct Host { String ip; String mac; };
    std::vector<Host> g_hosts;
    SemaphoreHandle_t g_mtx = nullptr;

    IPAddress g_self;
    struct netif *g_nif = nullptr;

    // Generic [g_rangeBaseU32 + g_rangeStart, g_rangeBaseU32 + g_rangeStart +
    // g_total) index range. Default (auto) mode sets this to the local /24
    // skipping the network address (.0); an explicit CIDR from the CLI
    // scans the whole block it was given instead.
    uint32_t g_rangeBaseU32 = 0;
    uint32_t g_rangeStart = 0;

    // Each etharp_* call is serialized by LOCK_TCPIP_CORE anyway, but that
    // lock is only held for the brief call itself - the ~50ms wait between
    // retries happens outside it, so several workers still overlap on the
    // part that actually dominates wall time.
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

    struct netif *getStaNetif() {
        esp_netif_t *e = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (e) return (struct netif *)esp_netif_get_netif_impl(e);
        return netif_default;
    }

    String macStr(const uint8_t *m) {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
        return String(buf);
    }

    // Fires an ARP "who-has" and gives the stack a short window to populate
    // its cache from the reply. 3 quick retries, ~150ms total per host.
    //
    // etharp_find_addr()/etharp_request() walk into lwIP's netif output
    // path (ethernet_output) and ESP-IDF's lwIP build asserts that the
    // TCPIP core lock is held whenever that happens from outside the
    // lwIP/tcpip thread itself — which this background task is. Without
    // the lock, this trips "Required to lock TCPIP core functionality!"
    // and reboots the device.
    bool resolve(struct netif *nif, const IPAddress &ip, uint8_t out[6]) {
        ip4_addr_t target;
        ip4_addr_set_u32(&target, (uint32_t)ip);

        for (int attempt = 0; attempt < 3; ++attempt) {
            struct eth_addr *ethRet = nullptr;
            const ip4_addr_t *ipRet = nullptr;

            LOCK_TCPIP_CORE();
            bool found = etharp_find_addr(nif, &target, &ethRet, &ipRet) >= 0 && ethRet;
            if (found) memcpy(out, ethRet->addr, 6);
            UNLOCK_TCPIP_CORE();
            if (found) return true;

            LOCK_TCPIP_CORE();
            etharp_request(nif, &target);
            UNLOCK_TCPIP_CORE();
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        return false;
    }

    struct WorkerRange { int start, end; };

    void workerTask(void *arg) {
        WorkerRange range = *(WorkerRange *)arg;
        delete (WorkerRange *)arg;

        for (int idx = range.start; idx < range.end && g_nif; ++idx) {
            if (g_stopReq) break;
            IPAddress target = u32ToIp(g_rangeBaseU32 + idx);
            if (target == g_self) { g_done++; continue; }

            uint8_t mac[6];
            if (resolve(g_nif, target, mac)) {
                if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
                g_hosts.push_back({target.toString(), macStr(mac)});
                if (g_mtx) xSemaphoreGive(g_mtx);
            }
            g_done++;
        }
        workerFinished();
        vTaskDelete(nullptr);
    }
}

namespace ArpScan {

bool start(const IPAddress &rangeBase, uint32_t rangeCount) {
    if (g_running) return false;
    if (WiFi.status() != WL_CONNECTED) return false;
    if (!g_mtx) g_mtx = xSemaphoreCreateMutex();

    g_nif = getStaNetif();
    g_self = WiFi.localIP();

    if (rangeCount > 0) {
        g_rangeBaseU32 = ipToU32(rangeBase);
        g_rangeStart = 0;
        g_total = rangeCount;
        g_base = rangeBase;
    } else {
        IPAddress mask = WiFi.subnetMask();
        IPAddress subnetBase(g_self[0] & mask[0], g_self[1] & mask[1], g_self[2] & mask[2], 0);
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
        xTaskCreatePinnedToCore(workerTask, "arpscan-w", 4096, range, 1, &h, w % 2);
    }
    return true;
}

void stop() { g_stopReq = true; }

String status() {
    JsonDocument doc;
    doc["running"] = g_running;
    doc["done"] = g_done;
    doc["total"] = g_total;
    doc["base"] = g_base.toString();

    JsonArray arr = doc["hosts"].to<JsonArray>();
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    for (auto &h : g_hosts) {
        JsonObject o = arr.add<JsonObject>();
        o["ip"] = h.ip;
        o["mac"] = h.mac;
    }
    if (g_mtx) xSemaphoreGive(g_mtx);

    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace ArpScan
