#include "discover.h"
#include <WiFi.h>
#include <WiFiUdp.h>
#include <ArduinoJson.h>
#include <esp_random.h>
#include <vector>

namespace {
    struct Dev { String ip; String info; };

    void addUnique(std::vector<Dev> &v, const String &ip, const String &info) {
        for (auto &d : v) if (d.ip == ip && d.info == info) return;
        if (v.size() < 64) v.push_back({ip, info});
    }

    // Returns the trimmed value of an HTTP-style "Key:" header line in 's'.
    String header(const String &s, const char *key) {
        int i = s.indexOf(key);
        if (i < 0) { String lo = s; lo.toUpperCase(); i = lo.indexOf(key); if (i < 0) return ""; }
        i += strlen(key);
        int e = s.indexOf('\n', i);
        String v = s.substring(i, e < 0 ? s.length() : e);
        v.trim();
        return v;
    }

    void ssdpSweep(std::vector<Dev> &out) {
        WiFiUDP u;
        u.begin(0);
        const char *msg =
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 2\r\n"
            "ST: ssdp:all\r\n\r\n";
        IPAddress mc(239, 255, 255, 250);
        u.beginPacket(mc, 1900);
        u.write((const uint8_t *)msg, strlen(msg));
        u.endPacket();

        uint32_t end = millis() + 3000;
        char buf[600];
        while (millis() < end) {
            int n = u.parsePacket();
            if (n > 0) {
                int r = u.read((uint8_t *)buf, sizeof(buf) - 1);
                if (r > 0) {
                    buf[r] = 0;
                    String s(buf);
                    String server = header(s, "SERVER:");
                    String st = header(s, "ST:");
                    String info = server.length() ? server : st;
                    if (st.length() && server.length()) info += " [" + st + "]";
                    addUnique(out, u.remoteIP().toString(), info);
                }
            } else delay(20);
        }
        u.stop();
    }

    // Decode a (possibly compressed) DNS name at buf[pos] into 'out'.
    void decodeName(const uint8_t *buf, int len, int &pos, String &out) {
        bool jumped = false; int saved = pos, guard = 0;
        while (pos < len && guard++ < 64) {
            uint8_t l = buf[pos];
            if (l == 0) { if (!jumped) saved = pos + 1; break; }
            if ((l & 0xC0) == 0xC0) {
                if (pos + 1 >= len) break;
                int ptr = ((l & 0x3F) << 8) | buf[pos + 1];
                if (!jumped) saved = pos + 2;
                jumped = true; pos = ptr; continue;
            }
            pos++;
            if (out.length()) out += '.';
            for (int i = 0; i < l && pos < len; ++i) out += (char)buf[pos++];
        }
        pos = jumped ? saved : pos + 1;
    }

    void mdnsSweep(std::vector<Dev> &out) {
        WiFiUDP u;
        u.begin(0);
        // Query PTR _services._dns-sd._udp.local (service-type enumeration).
        uint8_t pkt[64]; int p = 0;
        uint16_t id = (uint16_t)esp_random();
        pkt[p++] = id >> 8; pkt[p++] = id & 0xFF;
        pkt[p++] = 0; pkt[p++] = 0;      // flags
        pkt[p++] = 0; pkt[p++] = 1;      // QD=1
        pkt[p++] = 0; pkt[p++] = 0; pkt[p++] = 0; pkt[p++] = 0; pkt[p++] = 0; pkt[p++] = 0;
        const char *labels[] = {"_services", "_dns-sd", "_udp", "local"};
        for (auto lbl : labels) { int ln = strlen(lbl); pkt[p++] = ln; memcpy(pkt + p, lbl, ln); p += ln; }
        pkt[p++] = 0;                    // root
        pkt[p++] = 0; pkt[p++] = 12;     // QTYPE PTR
        pkt[p++] = 0; pkt[p++] = 1;      // QCLASS IN

        IPAddress mc(224, 0, 0, 251);
        u.beginPacket(mc, 5353);
        u.write(pkt, p);
        u.endPacket();

        uint32_t end = millis() + 3000;
        uint8_t buf[768];
        while (millis() < end) {
            int n = u.parsePacket();
            if (n > 0) {
                int r = u.read(buf, sizeof(buf));
                if (r >= 12) {
                    String ip = u.remoteIP().toString();
                    int an = (buf[6] << 8) | buf[7];
                    int pos = 12;
                    int qd = (buf[4] << 8) | buf[5];
                    for (int i = 0; i < qd; ++i) { String t; decodeName(buf, r, pos, t); pos += 4; }
                    for (int i = 0; i < an && pos + 10 <= r; ++i) {
                        String owner; decodeName(buf, r, pos, owner);
                        uint16_t rtype = (buf[pos] << 8) | buf[pos + 1];
                        uint16_t rdlen = (buf[pos + 8] << 8) | buf[pos + 9];
                        pos += 10;
                        String val;
                        if (rtype == 12) { int pp = pos; decodeName(buf, r, pp, val); }  // PTR
                        pos += rdlen;
                        addUnique(out, ip, val.length() ? val : owner);
                    }
                }
            } else delay(20);
        }
        u.stop();
    }
}

namespace Discover {

String run() {
    std::vector<Dev> ssdp, mdns;
    ssdpSweep(ssdp);
    mdnsSweep(mdns);

    JsonDocument doc;
    JsonArray sa = doc["ssdp"].to<JsonArray>();
    for (auto &d : ssdp) { JsonObject o = sa.add<JsonObject>(); o["ip"] = d.ip; o["info"] = d.info; }
    JsonArray ma = doc["mdns"].to<JsonArray>();
    for (auto &d : mdns) { JsonObject o = ma.add<JsonObject>(); o["ip"] = d.ip; o["name"] = d.info; }

    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace Discover
