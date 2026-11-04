#include "dnslookup.h"
#include <WiFi.h>
#include <WiFiUdp.h>
#include <ArduinoJson.h>
#include <esp_random.h>

namespace {
    struct TypeInfo { const char *name; uint16_t value; };
    const TypeInfo TYPES[] = {
        {"A", 1}, {"NS", 2}, {"CNAME", 5}, {"SOA", 6}, {"PTR", 12},
        {"MX", 15}, {"TXT", 16}, {"AAAA", 28}, {"SRV", 33}, {"CAA", 257},
        {"ANY", 255},
    };

    uint16_t typeValue(const String &name) {
        String up = name; up.toUpperCase();
        for (auto &t : TYPES) if (up == t.name) return t.value;
        return 0;
    }

    const char *typeName(uint16_t v) {
        for (auto &t : TYPES) if (t.value == v) return t.name;
        return "?";
    }

    // Encodes "a.b.c" as length-prefixed labels into out; returns bytes used.
    int encodeName(const String &host, uint8_t *out) {
        int pos = 0, start = 0;
        for (int i = 0; i <= (int)host.length(); ++i) {
            if (i == (int)host.length() || host[i] == '.') {
                int len = i - start;
                if (len > 63) return -1;
                out[pos++] = (uint8_t)len;
                for (int j = start; j < i; ++j) out[pos++] = host[j];
                start = i + 1;
            }
        }
        out[pos++] = 0; // root label
        return pos;
    }

    // Reads a (possibly compressed) DNS name starting at buf[pos] into 'out'.
    // Advances 'pos' past the name in the record stream (following the first
    // compression pointer only for the return position, per the format).
    void decodeName(const uint8_t *buf, int len, int &pos, String &out) {
        bool jumped = false;
        int savedPos = pos;
        int guard = 0;
        while (pos < len && guard++ < 128) {
            uint8_t l = buf[pos];
            if (l == 0) { if (!jumped) savedPos = pos + 1; break; }
            if ((l & 0xC0) == 0xC0) {           // compression pointer
                if (pos + 1 >= len) break;
                int ptr = ((l & 0x3F) << 8) | buf[pos + 1];
                if (!jumped) savedPos = pos + 2;
                jumped = true;
                pos = ptr;
                continue;
            }
            pos++;
            if (out.length()) out += '.';
            for (int i = 0; i < l && pos < len; ++i) out += (char)buf[pos++];
        }
        pos = jumped ? savedPos : pos + 1;
    }

    uint16_t rd16(const uint8_t *p) { return (p[0] << 8) | p[1]; }
    uint32_t rd32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; }

    String hex(const uint8_t *p, int n) {
        String s;
        for (int i = 0; i < n; ++i) { char b[4]; snprintf(b, sizeof(b), "%02x", p[i]); s += b; }
        return s;
    }

    // Formats one record's rdata (at buf+rdpos, rdlen bytes) by type.
    String formatRdata(const uint8_t *buf, int len, int rdpos, int rdlen, uint16_t type) {
        switch (type) {
            case 1: // A
                if (rdlen != 4) break;
                return IPAddress(buf[rdpos], buf[rdpos+1], buf[rdpos+2], buf[rdpos+3]).toString();
            case 28: { // AAAA
                if (rdlen != 16) break;
                String s;
                for (int i = 0; i < 16; i += 2) {
                    if (i) s += ':';
                    char b[6]; snprintf(b, sizeof(b), "%x", rd16(buf + rdpos + i)); s += b;
                }
                return s;
            }
            case 2: case 5: case 12: { // NS, CNAME, PTR -> a name
                int p = rdpos; String s;
                decodeName(buf, len, p, s);
                return s;
            }
            case 15: { // MX: preference + exchange name
                if (rdlen < 3) break;
                int p = rdpos + 2; String s;
                decodeName(buf, len, p, s);
                return String(rd16(buf + rdpos)) + " " + s;
            }
            case 16: { // TXT: one or more length-prefixed strings
                String s; int p = rdpos, end = rdpos + rdlen;
                while (p < end) {
                    int l = buf[p++];
                    for (int i = 0; i < l && p < end; ++i) s += (char)buf[p++];
                    if (p < end) s += ' ';
                }
                return s;
            }
            case 6: { // SOA: mname rname serial refresh retry expire minimum
                int p = rdpos; String mname, rname;
                decodeName(buf, len, p, mname);
                decodeName(buf, len, p, rname);
                if (p + 20 > len) return mname + " " + rname;
                String s = mname + " " + rname;
                s += " serial=" + String(rd32(buf + p));
                return s;
            }
            case 33: { // SRV: priority weight port target
                if (rdlen < 7) break;
                int p = rdpos + 6; String tgt;
                decodeName(buf, len, p, tgt);
                return String(rd16(buf + rdpos)) + " " + String(rd16(buf + rdpos + 2)) +
                       " " + String(rd16(buf + rdpos + 4)) + " " + tgt;
            }
        }
        return hex(buf + rdpos, rdlen); // unknown / malformed -> raw hex
    }

    // Builds d.c.b.a.in-addr.arpa for a dotted IPv4; returns "" if not an IP.
    String toReverse(const String &ip) {
        IPAddress a;
        if (!a.fromString(ip)) return "";
        return String(a[3]) + "." + a[2] + "." + a[1] + "." + a[0] + ".in-addr.arpa";
    }
}

namespace DnsLookup {

String query(const String &name, const String &typeStr, const IPAddress &serverIn) {
    JsonDocument doc;
    String ts = typeStr.length() ? typeStr : "A";
    uint16_t qtype = typeValue(ts);
    doc["query"] = name;
    doc["type"] = ts;

    if (qtype == 0) { doc["ok"] = false; doc["error"] = "Unknown record type."; String o; serializeJson(doc, o); return o; }

    IPAddress server = serverIn;
    if (server == IPAddress(0, 0, 0, 0)) server = WiFi.dnsIP();
    if (server == IPAddress(0, 0, 0, 0)) server = WiFi.gatewayIP();
    doc["server"] = server.toString();

    String qname = name;
    if (qtype == 12) { String r = toReverse(name); if (r.length()) qname = r; } // PTR from an IP

    uint8_t pkt[600];
    uint16_t id = (uint16_t)esp_random();
    pkt[0] = id >> 8; pkt[1] = id & 0xFF;
    pkt[2] = 0x01; pkt[3] = 0x00;  // RD=1
    pkt[4] = 0x00; pkt[5] = 0x01;  // QDCOUNT=1
    pkt[6] = pkt[7] = pkt[8] = pkt[9] = pkt[10] = pkt[11] = 0x00;
    int pos = 12;
    int nl = encodeName(qname, pkt + pos);
    if (nl < 0) { doc["ok"] = false; doc["error"] = "Name too long."; String o; serializeJson(doc, o); return o; }
    pos += nl;
    pkt[pos++] = qtype >> 8; pkt[pos++] = qtype & 0xFF;
    pkt[pos++] = 0x00; pkt[pos++] = 0x01; // IN

    WiFiUDP udp;
    udp.begin(0);
    udp.beginPacket(server, 53);
    udp.write(pkt, pos);
    udp.endPacket();

    uint8_t buf[1024];
    uint32_t deadline = millis() + 3000;
    int n = 0;
    while (millis() < deadline) {
        n = udp.parsePacket();
        if (n > 0) break;
        delay(10);
    }
    if (n <= 0) { udp.stop(); doc["ok"] = false; doc["error"] = "No response (timeout)."; String o; serializeJson(doc, o); return o; }

    n = udp.read(buf, sizeof(buf) < (size_t)n ? sizeof(buf) : n);
    udp.stop();
    if (n < 12) { doc["ok"] = false; doc["error"] = "Short response."; String o; serializeJson(doc, o); return o; }

    uint8_t rcode = buf[3] & 0x0F;
    if (rcode != 0) {
        const char *msg = rcode == 3 ? "NXDOMAIN (no such name)" :
                          rcode == 2 ? "SERVFAIL" : rcode == 5 ? "REFUSED" : "query failed";
        doc["ok"] = false; doc["error"] = msg;
        String o; serializeJson(doc, o); return o;
    }

    int qd = rd16(buf + 4), an = rd16(buf + 6);
    int p = 12;
    for (int i = 0; i < qd; ++i) { String tmp; decodeName(buf, n, p, tmp); p += 4; } // skip questions

    JsonArray arr = doc["answers"].to<JsonArray>();
    for (int i = 0; i < an && p + 10 <= n; ++i) {
        String rname;
        decodeName(buf, n, p, rname);
        uint16_t rtype = rd16(buf + p);
        uint32_t ttl = rd32(buf + p + 4);
        uint16_t rdlen = rd16(buf + p + 8);
        p += 10;
        if (p + rdlen > n) break;
        JsonObject o = arr.add<JsonObject>();
        o["name"] = rname;
        o["type"] = typeName(rtype);
        o["ttl"] = ttl;
        o["data"] = formatRdata(buf, n, p, rdlen, rtype);
        p += rdlen;
    }
    doc["ok"] = true;

    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace DnsLookup
