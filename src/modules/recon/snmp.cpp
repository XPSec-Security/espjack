#include "snmp.h"
#include <WiFiUdp.h>
#include <ArduinoJson.h>
#include <esp_random.h>

namespace {
    // Minimal BER length (short form only; our packet is small).
    int putTlv(uint8_t *out, uint8_t tag, const uint8_t *val, int len) {
        out[0] = tag; out[1] = (uint8_t)len;
        if (len && val) memcpy(out + 2, val, len);
        return 2 + len;
    }
}

namespace Snmp {

String get(const IPAddress &target, const String &community, uint32_t timeoutMs) {
    JsonDocument doc;
    String comm = community.length() ? community : "public";

    // sysDescr.0 = 1.3.6.1.2.1.1.1.0  -> OID bytes (first two nodes = 1*40+3).
    const uint8_t oid[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00};

    uint8_t varbind[32]; int vb = 0;
    uint8_t oidTlv[16]; int ol = putTlv(oidTlv, 0x06, oid, sizeof(oid));
    uint8_t nullTlv[2]; int nl = putTlv(nullTlv, 0x05, nullptr, 0);
    uint8_t inner[32]; int il = 0;
    memcpy(inner + il, oidTlv, ol); il += ol;
    memcpy(inner + il, nullTlv, nl); il += nl;
    vb = putTlv(varbind, 0x30, inner, il);              // varbind SEQUENCE

    uint8_t vbl[40]; int vbll = putTlv(vbl, 0x30, varbind, vb);  // varbindlist SEQUENCE

    uint16_t reqId = (uint16_t)esp_random();
    uint8_t pdu[80]; int pp = 0;
    uint8_t idBytes[2] = {(uint8_t)(reqId >> 8), (uint8_t)(reqId & 0xFF)};
    pp += putTlv(pdu + pp, 0x02, idBytes, 2);           // request-id
    uint8_t zero = 0;
    pp += putTlv(pdu + pp, 0x02, &zero, 1);             // error-status
    pp += putTlv(pdu + pp, 0x02, &zero, 1);             // error-index
    memcpy(pdu + pp, vbl, vbll); pp += vbll;
    uint8_t pduTlv[96]; int pdl = putTlv(pduTlv, 0xA0, pdu, pp);  // GetRequest PDU [0]

    uint8_t msg[160]; int mp = 0;
    uint8_t ver = 0;
    mp += putTlv(msg + mp, 0x02, &ver, 1);              // version v1 (0)
    mp += putTlv(msg + mp, 0x04, (const uint8_t *)comm.c_str(), comm.length()); // community
    memcpy(msg + mp, pduTlv, pdl); mp += pdl;
    uint8_t packet[200];
    int plen = putTlv(packet, 0x30, msg, mp);

    WiFiUDP udp;
    udp.begin(0);
    udp.beginPacket(target, 161);
    udp.write(packet, plen);
    udp.endPacket();

    uint32_t deadline = millis() + timeoutMs;
    int n = 0;
    while (millis() < deadline) { n = udp.parsePacket(); if (n > 0) break; delay(20); }
    if (n <= 0) { udp.stop(); doc["ok"] = false; doc["error"] = "no response (closed/filtered or wrong community)";
                  String o; serializeJson(doc, o); return o; }

    uint8_t resp[512];
    n = udp.read(resp, sizeof(resp) < (size_t)n ? sizeof(resp) : n);
    udp.stop();

    // Pull the last OCTET STRING (0x04) in the response - the sysDescr value.
    String descr;
    for (int i = 0; i + 2 < n; ++i) {
        if (resp[i] == 0x04) {
            int l = resp[i + 1];
            if (l > 0 && l < 0x80 && i + 2 + l <= n) {
                bool printable = true;
                for (int j = 0; j < l; ++j) { char ch = resp[i + 2 + j]; if (ch != '\n' && ch != '\r' && (ch < 32 || ch > 126)) { printable = false; break; } }
                if (printable && l > descr.length()) descr = String((const char *)(resp + i + 2), l);
            }
        }
    }
    doc["ok"] = true;
    doc["community"] = comm;
    doc["sysDescr"] = descr.length() ? descr : "(reply received, no readable sysDescr)";
    String o; serializeJson(doc, o); return o;
}

} // namespace Snmp
