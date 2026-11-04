#include "portscan.h"
#include <WiFi.h>
#include <WiFiClient.h>
#include <ArduinoJson.h>
#include <vector>
#include <algorithm>
#include <errno.h>
#include <esp_random.h>
#include <lwip/sockets.h>
#include <lwip/ip4.h>
#include <lwip/netif.h>
#include <lwip/etharp.h>
#include <lwip/tcpip.h>
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
    // SYN mode only: ports that answered RST / never answered, and a fatal
    // error (raw sockets unavailable, no memory, no route) if there was one.
    volatile uint32_t g_closed = 0;
    volatile uint32_t g_filtered = 0;
    String g_error;
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

    // ------------------------------------------------------------------
    // SYN (half-open) scan.
    //
    // A bare SYN goes out on an lwIP raw socket for every port and the reply
    // classifies it: SYN/ACK = open, RST = closed, nothing = filtered. The
    // handshake is never completed. lwIP itself answers the unsolicited
    // SYN/ACK with a RST (no connection matches it), which tears the
    // half-open connection down on the target - the same thing nmap relies
    // on when it scans through the OS stack.
    //
    // Stateless: the sequence number is a keyed hash of (target, port), so a
    // reply is recognised by ack-1 and no per-probe table is needed. A bitmap
    // of answered ports (8 KB, heap) removes duplicates and lets the second
    // pass resend only the ports that never answered.
    //
    // The raw socket's receive queue holds just 6 packets, so it is drained
    // after every send; sending is paced to about 1000 probes per second.
    // ------------------------------------------------------------------
    uint32_t g_synSecret = 0;
    uint16_t g_synSport = 0;

    // g_error is read by the CLI thread while this task may be writing it.
    void setError(const String &e) {
        if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
        g_error = e;
        if (g_mtx) xSemaphoreGive(g_mtx);
    }

    uint32_t synCookie(uint32_t ip, uint16_t port) {
        uint32_t x = g_synSecret ^ ip;
        x = (x ^ (x >> 16)) * 0x45d9f3bu;
        x ^= (uint32_t)port * 0x9E3779B1u;
        x = (x ^ (x >> 15)) * 0x2c1b3c6du;
        return x ^ (x >> 13);
    }

    uint32_t csumAdd(uint32_t sum, const uint8_t *d, size_t n) {
        for (size_t i = 0; i + 1 < n; i += 2) sum += (uint32_t)((d[i] << 8) | d[i + 1]);
        if (n & 1) sum += (uint32_t)(d[n - 1] << 8);
        return sum;
    }

    uint16_t csumFold(uint32_t sum) {
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        return (uint16_t)~sum;
    }

    // 24-byte TCP SYN with an MSS option. srcNet/dstNet are in network byte
    // order (the TCP checksum covers them through the pseudo-header).
    void buildSyn(uint8_t *out, uint32_t srcNet, uint32_t dstNet, uint16_t sport, uint16_t dport, uint32_t seq) {
        memset(out, 0, 24);
        out[0] = sport >> 8; out[1] = sport & 0xFF;
        out[2] = dport >> 8; out[3] = dport & 0xFF;
        out[4] = seq >> 24;  out[5] = seq >> 16;  out[6] = seq >> 8;  out[7] = seq;
        out[12] = 0x60;                              // data offset: 6 words
        out[13] = 0x02;                              // SYN
        out[14] = 0x04; out[15] = 0x00;              // window 1024
        out[20] = 2; out[21] = 4; out[22] = 0x05; out[23] = 0xB4;   // MSS 1460
        uint8_t ph[12];
        memcpy(ph, &srcNet, 4); memcpy(ph + 4, &dstNet, 4);
        ph[8] = 0; ph[9] = 6; ph[10] = 0; ph[11] = 24;              // zero, TCP, length
        uint16_t c = csumFold(csumAdd(csumAdd(0, ph, 12), out, 24));
        out[16] = c >> 8; out[17] = c & 0xFF;
    }

    uint32_t be32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

    // State of the neighbour entry for an on-link target: 1 = resolved,
    // 0 = on-link but nobody answered ARP (yet), -1 = not applicable (routed,
    // or a tunnel interface with no ARP).
    int arpState(uint32_t dstNet) {
        ip4_addr_t d;
        d.addr = dstNet;
        int res = -1;
        LOCK_TCPIP_CORE();
        struct netif *n = ip4_route(&d);
        if (n && (n->flags & NETIF_FLAG_ETHARP) && ip4_addr_netcmp(&d, netif_ip4_addr(n), netif_ip4_netmask(n))) {
            struct eth_addr *eth = nullptr;
            const ip4_addr_t *ipRet = nullptr;
            res = etharp_find_addr(n, &d, &eth, &ipRet) >= 0 ? 1 : 0;
        }
        UNLOCK_TCPIP_CORE();
        return res;
    }

    void scanHostSyn(const IPAddress &host) {
        const uint32_t dstH = ipToU32(host);
        const uint32_t dstNet = htonl(dstH);
        const uint32_t portTotal = (uint32_t)g_portCount;
        uint32_t srcNet = 0;

        // Which source address will lwIP stamp on the packets? It is the
        // address of the interface that routes to the target (the WiFi
        // station, or the WireGuard tunnel), and the TCP checksum covers it,
        // so ask lwIP's routing table for that interface. (A connected UDP
        // socket cannot answer this: lwIP leaves its local address at 0.0.0.0
        // until the first send.)
        bool haveSrc = false;
        {
            ip4_addr_t d;
            d.addr = dstNet;
            LOCK_TCPIP_CORE();
            struct netif *rt = ip4_route(&d);
            if (rt) {
                srcNet = ip4_addr_get_u32(netif_ip4_addr(rt));
                haveSrc = srcNet != 0;
            }
            UNLOCK_TCPIP_CORE();
        }
        // A throw-away datagram makes lwIP ARP for an on-link host before the
        // first probe goes out (the raw send would otherwise be the one to
        // trigger the ARP request, and could be dropped while it is pending).
        if (haveSrc) {
            int u = lwip_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (u >= 0) {
                sockaddr_in d = {};
                d.sin_len = sizeof(d); d.sin_family = AF_INET; d.sin_port = htons(9); d.sin_addr.s_addr = dstNet;
                if (lwip_connect(u, (sockaddr *)&d, sizeof(d)) == 0) {
                    const char z = 0;
                    lwip_send(u, &z, 1, 0);
                }
                lwip_close(u);
            }
        }
        if (!haveSrc) {
            setError("no route to " + host.toString());
            g_done += portTotal;
            return;
        }

        // Is anybody home? On-link target with no ARP answer after ~0.5 s:
        // in a sweep it is skipped (a dead address would burn the whole port
        // list's timeouts); a single target is scanned regardless.
        int st = arpState(dstNet);
        for (int w = 0; w < 10 && st == 0 && !g_stopReq; ++w) { vTaskDelay(pdMS_TO_TICKS(50)); st = arpState(dstNet); }
        if (st == 0 && g_hostCount > 1) { g_done += portTotal; return; }

        int s = lwip_socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (s < 0) {
            setError("raw TCP sockets are not available (errno " + String(errno) + ")");
            g_stopReq = true;
            return;
        }
        uint8_t *seen = (uint8_t *)calloc(8192, 1);          // one bit per port
        if (!seen) {
            lwip_close(s);
            setError("out of memory");
            g_stopReq = true;
            return;
        }

        uint32_t nOpen = 0, nClosed = 0;
        const size_t firstResult = g_results.size();

        auto handle = [&](const uint8_t *buf, int n) {
            if (n < 40 || (buf[0] >> 4) != 4 || buf[9] != 6) return;      // IPv4 TCP only
            int ihl = (buf[0] & 0x0F) * 4;
            if (n < ihl + 20) return;
            uint32_t from;
            memcpy(&from, buf + 12, 4);
            if (from != dstNet) return;
            const uint8_t *t = buf + ihl;
            uint16_t sp = (uint16_t)((t[0] << 8) | t[1]);
            uint16_t dp = (uint16_t)((t[2] << 8) | t[3]);
            if (dp != g_synSport) return;
            uint8_t fl = t[13];
            bool isSyn = fl & 0x02, isRst = fl & 0x04, isAck = fl & 0x10;
            if (isAck && be32(t + 8) != synCookie(dstH, sp) + 1) return;  // not a reply to one of our probes
            if (!isAck && !isRst) return;
            if (seen[sp >> 3] & (1 << (sp & 7))) return;                  // duplicate
            if (isSyn && isAck) {
                seen[sp >> 3] |= (1 << (sp & 7));
                ++nOpen;
                Result r;
                r.ip = host.toString();
                r.port = sp;
                r.service = guessService(sp);
                if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
                g_results.push_back(r);
                if (g_mtx) xSemaphoreGive(g_mtx);
            } else if (isRst) {
                seen[sp >> 3] |= (1 << (sp & 7));
                ++nClosed;
            }
        };
        auto drain = [&]() {
            uint8_t buf[96];
            int n;
            while ((n = lwip_recvfrom(s, buf, sizeof(buf), MSG_DONTWAIT, nullptr, nullptr)) > 0) handle(buf, n);
        };

        sockaddr_in to = {};
        to.sin_len = sizeof(to); to.sin_family = AF_INET; to.sin_addr.s_addr = dstNet;

        for (int pass = 0; pass < 2 && !g_stopReq; ++pass) {
            for (size_t i = 0; i < g_portCount && !g_stopReq; ++i) {
                uint16_t port = portAt(i);
                if (pass == 1 && (seen[port >> 3] & (1 << (port & 7)))) continue;   // already answered
                uint8_t syn[24];
                buildSyn(syn, srcNet, dstNet, g_synSport, port, synCookie(dstH, port));
                if (lwip_sendto(s, syn, sizeof(syn), 0, (sockaddr *)&to, sizeof(to)) < 0) {
                    vTaskDelay(2);                                                   // out of buffers: back off, retry once
                    lwip_sendto(s, syn, sizeof(syn), 0, (sockaddr *)&to, sizeof(to));
                }
                if (pass == 0) g_done++;
                drain();
                if (i & 1) vTaskDelay(1);                                            // ~1000 probes per second
            }
            // Late replies; the second pass then resends only what never answered.
            uint32_t until = millis() + g_timeout;
            while (!g_stopReq && (int32_t)(until - millis()) > 0) { drain(); vTaskDelay(pdMS_TO_TICKS(5)); }
        }
        drain();

        lwip_close(s);
        free(seen);

        if (!g_stopReq) {
            g_closed += nClosed;
            g_filtered += portTotal - nOpen - nClosed;
        }
        // Replies arrive in any order: list the host's open ports by number.
        if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
        std::sort(g_results.begin() + firstResult, g_results.end(),
                  [](const Result &a, const Result &b) { return a.port < b.port; });
        if (g_mtx) xSemaphoreGive(g_mtx);
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
            if (g_mode == PortScan::MODE_SYN) scanHostSyn(g_curTarget);
            else scanOneHost();
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
    g_closed     = 0;
    g_filtered   = 0;
    g_error      = "";
    // Per-scan SYN identity: a secret for the sequence-number cookies and a
    // source port above lwIP's own ephemeral range (16384-32767).
    g_synSecret  = esp_random();
    g_synSport   = (uint16_t)(40000 + esp_random() % 20000);

    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    g_results.clear();
    if (g_mtx) xSemaphoreGive(g_mtx);

    g_running = true;
    if (xTaskCreatePinnedToCore(driverTask, "portscan-driver", 6144, nullptr, 1, &g_driverTask, 0) != pdPASS) {
        g_running = false;
        return false;
    }
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
    doc["closed"]    = g_closed;
    doc["filtered"]  = g_filtered;
    String err;
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    err = g_error;
    if (g_mtx) xSemaphoreGive(g_mtx);
    doc["error"]     = err;

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
