#include "portscan.h"
#include <WiFi.h>
#include <WiFiClient.h>
#include <ArduinoJson.h>
#include <vector>
#include "../common/iprange.h"

namespace {
    struct Result {
        String ip;
        uint16_t port;
        String service;
        String banner;
        String version;
    };

    volatile bool g_running = false;
    volatile bool g_stopReq = false;
    IPAddress g_target;
    PortScan::Mode g_mode = PortScan::MODE_CONNECT;
    uint16_t g_timeout = 400;
    volatile uint32_t g_done = 0;
    uint32_t g_total = 0;
    std::vector<Result> g_results;
    // The port list is described, not materialized: a full 1-65535 sweep as
    // a std::vector<uint16_t> doubles up to 128KB (plus the old 64KB block
    // during growth), which a board without PSRAM can't allocate - the
    // failed allocation aborts and reboots the chip. g_useTop selects the
    // TOP_PORTS preset; otherwise port i is g_portStart + i.
    bool g_useTop = false;
    uint32_t g_portStart = 0;
    size_t g_portCount = 0;
    SemaphoreHandle_t g_mtx = nullptr;

    // Hosts are scanned one at a time (each one getting the full worker
    // pool across its ports); only the port dimension is parallelized.
    uint32_t g_rangeBaseU32 = 0;
    uint32_t g_hostCount = 1;
    IPAddress g_curTarget;
    TaskHandle_t g_driverTask = nullptr;

    // Port scanning is dominated by waiting on each connection attempt's
    // timeout, not CPU work, so several concurrent workers (each with its
    // own socket) finish a host's port list roughly NUM_WORKERS times
    // faster than one task working through it alone.
    const int NUM_WORKERS = 6;
    volatile int g_workersAlive = 0;

    void workerFinished() {
        if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
        g_workersAlive--;
        if (g_mtx) xSemaphoreGive(g_mtx);
    }

    // Most common ports (the "top" preset).
    const uint16_t TOP_PORTS[] = {
        21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,514,587,
        631,993,995,1025,1080,1433,1521,1723,2049,2121,3000,3128,3306,3389,
        5000,5060,5432,5555,5900,5985,6379,8000,8008,8080,8081,8443,8888,
        9000,9090,9100,9200,10000,11211,27017,32768,49152
    };

    uint16_t portAt(size_t i) { return g_useTop ? TOP_PORTS[i] : (uint16_t)(g_portStart + i); }

    const char *guessService(uint16_t p) {
        switch (p) {
            case 21: return "ftp";       case 22: return "ssh";
            case 23: return "telnet";    case 25: return "smtp";
            case 53: return "dns";       case 80: return "http";
            case 110: return "pop3";     case 111: return "rpcbind";
            case 135: return "msrpc";    case 139: return "netbios-ssn";
            case 143: return "imap";     case 161: return "snmp";
            case 389: return "ldap";     case 443: return "https";
            case 445: return "smb";      case 465: return "smtps";
            case 587: return "submission"; case 993: return "imaps";
            case 995: return "pop3s";    case 1433: return "mssql";
            case 1521: return "oracle";  case 3306: return "mysql";
            case 3389: return "rdp";     case 5432: return "postgres";
            case 5900: return "vnc";     case 5985: return "winrm";
            case 6379: return "redis";   case 8080: return "http-proxy";
            case 8443: return "https-alt"; case 9200: return "elasticsearch";
            case 11211: return "memcached"; case 27017: return "mongodb";
            default: return "unknown";
        }
    }

    bool isHttpPort(uint16_t p) {
        return p == 80 || p == 8080 || p == 8000 || p == 8008 || p == 8081 || p == 9090 || p == 3000;
    }

    String sanitize(const String &in) {
        String out;
        out.reserve(in.length());
        for (size_t i = 0; i < in.length() && out.length() < 220; ++i) {
            char c = in[i];
            if (c == '\n') { out += "\\n"; }
            else if (c == '\r') { /* skip */ }
            else if (c >= 32 && c < 127) out += c;
            else out += '.';
        }
        return out;
    }

    // Extract a "version" string from the banner, loosely imitating nmap -sV.
    String detectVersion(uint16_t port, const String &banner) {
        if (banner.length() == 0) return "";
        String b = banner;
        if (b.startsWith("SSH-")) {
            int nl = b.indexOf('\n'); int cr = b.indexOf('\r');
            int end = nl < 0 ? b.length() : nl; if (cr >= 0 && cr < end) end = cr;
            return b.substring(0, end);
        }
        if (b.startsWith("220 ") || b.startsWith("220-")) {         // FTP/SMTP
            int cr = b.indexOf('\r'); return b.substring(0, cr < 0 ? b.length() : cr);
        }
        if (b.startsWith("+OK")) { int cr = b.indexOf('\r'); return b.substring(0, cr < 0 ? b.length() : cr); }
        if (b.startsWith("* OK")) { int cr = b.indexOf('\r'); return b.substring(0, cr < 0 ? b.length() : cr); }
        int srv = b.indexOf("Server:");
        if (srv >= 0) {
            int start = srv + 7; while (start < (int)b.length() && b[start] == ' ') start++;
            int cr = b.indexOf('\r', start); if (cr < 0) cr = b.indexOf('\n', start);
            return b.substring(start, cr < 0 ? b.length() : cr);
        }
        // fallback: first readable line
        int cr = b.indexOf('\r'); if (cr < 0) cr = b.indexOf('\n');
        return b.substring(0, cr < 0 ? (b.length() > 60 ? 60 : b.length()) : cr);
    }

    String grabBanner(WiFiClient &c, uint16_t port) {
        // For HTTP, trigger a response with a GET; other services usually send
        // a greeting on their own.
        if (isHttpPort(port)) {
            c.printf("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: ESPJack\r\nConnection: close\r\n\r\n",
                     g_curTarget.toString().c_str());
        }
        String data;
        uint32_t deadline = millis() + 900;
        while (millis() < deadline && data.length() < 300) {
            while (c.available()) {
                data += (char)c.read();
                if (data.length() >= 300) break;
            }
            if (!c.connected() && !c.available()) break;
            delay(20);
        }
        return data;
    }

    struct WorkerRange { size_t start, end; };

    void workerTask(void *arg) {
        WorkerRange range = *(WorkerRange *)arg;
        delete (WorkerRange *)arg;

        for (size_t i = range.start; i < range.end; ++i) {
            if (g_stopReq) break;
            uint16_t port = portAt(i);

            WiFiClient client;
            if (client.connect(g_curTarget, port, (int32_t)g_timeout)) {
                Result r;
                r.ip = g_curTarget.toString();
                r.port = port;
                r.service = guessService(port);
                if (g_mode != PortScan::MODE_CONNECT) {
                    String raw = grabBanner(client, port);
                    r.banner = sanitize(raw);
                    if (g_mode == PortScan::MODE_VERSION) r.version = sanitize(detectVersion(port, raw));
                }
                client.stop();

                if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
                g_results.push_back(r);
                if (g_mtx) xSemaphoreGive(g_mtx);
            }
            g_done++;
            vTaskDelay(1);
        }
        workerFinished();
        vTaskDelete(nullptr);
    }

    // Scans one host's full port list with the worker pool, blocking until
    // every worker is done.
    void scanOneHost() {
        size_t n = g_portCount;
        int workers = NUM_WORKERS < (int)n ? NUM_WORKERS : (int)n;
        if (workers < 1) workers = 1;
        g_workersAlive = workers;

        size_t perWorker = (n + workers - 1) / workers;
        for (int w = 0; w < workers; ++w) {
            size_t s = (size_t)w * perWorker;
            size_t e = s + perWorker < n ? s + perWorker : n;
            WorkerRange *range = new WorkerRange{s, e};
            if (xTaskCreatePinnedToCore(workerTask, "portscan-w", 6144, range, 1, nullptr, w % 2) != pdPASS) {
                delete range;           // not enough heap for another worker: count it as finished
                workerFinished();       // so the wait below can't hang
            }
        }
        while (g_workersAlive > 0) vTaskDelay(pdMS_TO_TICKS(50));
    }

    // Drives the host dimension: one host at a time, each getting the full
    // worker pool across its ports (see scanOneHost()).
    void driverTask(void *) {
        for (uint32_t h = 0; h < g_hostCount && !g_stopReq; ++h) {
            g_curTarget = u32ToIp(g_rangeBaseU32 + h);
            scanOneHost();
        }
        g_running = false;
        g_driverTask = nullptr;
        vTaskDelete(nullptr);
    }
}

namespace PortScan {

bool start(const IPAddress &target, uint16_t startPort, uint16_t endPort,
           Mode mode, bool top, uint16_t timeoutMs, uint32_t hostCount) {
    if (g_running) return false;

    if (top) {
        g_useTop = true;
        g_portStart = 0;
        g_portCount = sizeof(TOP_PORTS) / sizeof(TOP_PORTS[0]);
    } else {
        if (startPort == 0 || endPort < startPort) return false;
        g_useTop = false;
        g_portStart = startPort;
        g_portCount = (size_t)endPort - startPort + 1;
    }

    if (!g_mtx) g_mtx = xSemaphoreCreateMutex();

    g_target     = target;
    g_rangeBaseU32 = ipToU32(target);
    g_hostCount  = hostCount ? hostCount : 1;
    g_mode       = mode;
    g_timeout    = timeoutMs ? timeoutMs : 400;
    g_done       = 0;
    g_total      = (uint32_t)g_portCount * g_hostCount;
    g_stopReq    = false;

    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    g_results.clear();
    if (g_mtx) xSemaphoreGive(g_mtx);

    g_running = true;
    xTaskCreatePinnedToCore(driverTask, "portscan-driver", 3072, nullptr, 1, &g_driverTask, 0);
    return true;
}

void stop() { g_stopReq = true; }

bool running() { return g_running; }

void progress(uint32_t &done, uint32_t &total) { done = g_done; total = g_total; }

String status() {
    JsonDocument doc;
    doc["running"]   = g_running;
    doc["target"]    = g_target.toString();
    doc["hostCount"] = g_hostCount;
    doc["mode"]      = (int)g_mode;
    doc["done"]      = g_done;
    doc["total"]     = g_total;

    JsonArray arr = doc["results"].to<JsonArray>();
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    for (auto &r : g_results) {
        JsonObject o = arr.add<JsonObject>();
        o["ip"]      = r.ip;
        o["port"]    = r.port;
        o["service"] = r.service;
        o["banner"]  = r.banner;
        o["version"] = r.version;
    }
    if (g_mtx) xSemaphoreGive(g_mtx);

    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace PortScan
