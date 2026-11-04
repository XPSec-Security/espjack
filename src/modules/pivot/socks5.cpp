#include "socks5.h"
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiServer.h>
#include <ArduinoJson.h>

namespace {
    volatile bool g_running = false;
    volatile bool g_stop = false;
    uint16_t g_port = 1080;
    volatile int g_active = 0;
    volatile uint32_t g_served = 0;
    TaskHandle_t g_listener = nullptr;
    WiFiServer g_server(1080);

    const int MAX_CONNS = 4;        // lwIP socket budget is small
    SemaphoreHandle_t g_mtx = nullptr;

    void adjActive(int d) {
        if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
        g_active += d;
        if (g_mtx) xSemaphoreGive(g_mtx);
    }

    // Reads exactly n bytes with a timeout. Returns false on close/timeout.
    bool readN(WiFiClient &c, uint8_t *buf, int n, uint32_t timeoutMs = 5000) {
        uint32_t dl = millis() + timeoutMs;
        int got = 0;
        while (got < n) {
            if (c.available()) { int r = c.read(buf + got, n - got); if (r > 0) got += r; }
            else { if (!c.connected() || millis() > dl) return false; delay(2); }
        }
        return true;
    }

    // Pumps bytes both ways until either side closes or the proxy stops.
    void pump(WiFiClient &a, WiFiClient &b) {
        uint8_t buf[512];
        while (!g_stop) {
            bool did = false;
            while (a.available()) { int n = a.read(buf, sizeof(buf)); if (n > 0) { b.write(buf, n); did = true; } else break; }
            while (b.available()) { int n = b.read(buf, sizeof(buf)); if (n > 0) { a.write(buf, n); did = true; } else break; }
            if (!a.connected() && !a.available() && !b.connected() && !b.available()) break;
            if ((!a.connected() && !a.available()) || (!b.connected() && !b.available())) {
                // one side fully done: drain the other once more then stop
                if (!did) break;
            }
            if (!did) delay(2);
        }
    }

    void connTask(void *arg) {
        WiFiClient client = *(WiFiClient *)arg;
        delete (WiFiClient *)arg;

        uint8_t hdr[4];
        // Greeting: VER, NMETHODS, METHODS...
        if (!readN(client, hdr, 2) || hdr[0] != 0x05) { client.stop(); adjActive(-1); vTaskDelete(nullptr); return; }
        uint8_t nm = hdr[1];
        uint8_t tmp[255];
        if (nm && !readN(client, tmp, nm)) { client.stop(); adjActive(-1); vTaskDelete(nullptr); return; }
        uint8_t noauth[2] = {0x05, 0x00};
        client.write(noauth, 2);         // select "no authentication"

        // Request: VER CMD RSV ATYP ...
        if (!readN(client, hdr, 4) || hdr[0] != 0x05) { client.stop(); adjActive(-1); vTaskDelete(nullptr); return; }
        uint8_t cmd = hdr[1], atyp = hdr[3];
        String host; uint16_t port = 0;
        bool ok = true;
        if (atyp == 0x01) {              // IPv4
            uint8_t a4[4]; if (!readN(client, a4, 4)) ok = false;
            else host = IPAddress(a4[0], a4[1], a4[2], a4[3]).toString();
        } else if (atyp == 0x03) {       // domain
            uint8_t l; if (!readN(client, &l, 1) || !readN(client, tmp, l)) ok = false;
            else { tmp[l] = 0; host = String((char *)tmp); }
        } else {
            ok = false;                   // IPv6 unsupported
        }
        uint8_t pb[2];
        if (ok && readN(client, pb, 2)) port = (pb[0] << 8) | pb[1]; else ok = false;

        WiFiClient target;
        bool connected = false;
        if (ok && cmd == 0x01) connected = target.connect(host.c_str(), port, 8000);

        // Reply: VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
        uint8_t rep[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        if (!ok) rep[1] = 0x07;          // command/address not supported
        else if (!connected) rep[1] = 0x05; // connection refused
        client.write(rep, sizeof(rep));

        if (ok && connected) {
            g_served++;
            pump(client, target);
        }
        target.stop();
        client.stop();
        adjActive(-1);
        vTaskDelete(nullptr);
    }

    void listenerTask(void *) {
        g_server = WiFiServer(g_port);
        g_server.begin();
        g_running = true;
        while (!g_stop) {
            WiFiClient c = g_server.available();
            if (c) {
                if (g_active >= MAX_CONNS) { c.stop(); }
                else {
                    adjActive(1);
                    WiFiClient *p = new WiFiClient(c);
                    if (xTaskCreatePinnedToCore(connTask, "socks-conn", 8192, p, 1, nullptr, 1) != pdPASS) {
                        delete p; c.stop(); adjActive(-1);
                    }
                }
            } else {
                delay(10);
            }
        }
        g_server.end();
        g_running = false;
        g_listener = nullptr;
        vTaskDelete(nullptr);
    }
}

namespace Socks5 {

bool start(uint16_t port) {
    if (g_running) return false;
    if (WiFi.status() != WL_CONNECTED) return false;
    if (!g_mtx) g_mtx = xSemaphoreCreateMutex();
    g_port = port ? port : 1080;
    g_active = 0;
    g_served = 0;
    g_stop = false;
    xTaskCreatePinnedToCore(listenerTask, "socks5", 4096, nullptr, 1, &g_listener, 1);
    return true;
}

void stop() { g_stop = true; }

bool isRunning() { return g_running; }

String status() {
    JsonDocument doc;
    doc["running"] = g_running;
    doc["port"] = g_port;
    doc["active"] = g_active;
    doc["served"] = g_served;
    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace Socks5
