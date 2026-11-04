#include "smbrecon.h"
#include <WiFiClient.h>
#include <ArduinoJson.h>
#include <esp_random.h>

namespace {
    volatile bool g_running = false;
    volatile bool g_stopReq = false;
    IPAddress g_target;
    String g_error, g_dialect, g_nbDomain, g_nbComputer, g_dnsDomain, g_dnsComputer;
    bool g_signingRequired = false;
    bool g_nullSession = false;
    bool g_done = false;
    TaskHandle_t g_task = nullptr;

    // ---- NetBIOS Session Service (TCP/445 framing: 4-byte big-endian length) ----
    bool nbssWrite(WiFiClient &c, const uint8_t *buf, size_t len) {
        uint8_t hdr[4] = {0x00, (uint8_t)((len >> 16) & 0xFF), (uint8_t)((len >> 8) & 0xFF), (uint8_t)(len & 0xFF)};
        c.write(hdr, 4);
        c.write(buf, len);
        return true;
    }

    int nbssRead(WiFiClient &c, uint8_t *buf, size_t cap, uint32_t timeoutMs = 3000) {
        uint32_t deadline = millis() + timeoutMs;
        while (c.available() < 4) {
            if (millis() > deadline || !c.connected()) return -1;
            delay(10);
        }
        uint8_t hdr[4];
        c.read(hdr, 4);
        uint32_t len = ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | hdr[3];
        if (len > cap) return -1;
        size_t got = 0;
        while (got < len) {
            if (millis() > deadline || !c.connected()) return -1;
            if (c.available()) {
                int n = c.read(buf + got, len - got);
                if (n > 0) got += n;
            } else {
                delay(5);
            }
        }
        return (int)len;
    }

    // ---- small helpers ----
    void put16(uint8_t *b, int off, uint16_t v) { b[off] = v & 0xFF; b[off + 1] = (v >> 8) & 0xFF; }
    void put32(uint8_t *b, int off, uint32_t v) {
        b[off] = v & 0xFF; b[off + 1] = (v >> 8) & 0xFF; b[off + 2] = (v >> 16) & 0xFF; b[off + 3] = (v >> 24) & 0xFF;
    }
    uint16_t get16(const uint8_t *b, int off) { return b[off] | (b[off + 1] << 8); }
    uint32_t get32(const uint8_t *b, int off) {
        return (uint32_t)b[off] | ((uint32_t)b[off + 1] << 8) | ((uint32_t)b[off + 2] << 16) | ((uint32_t)b[off + 3] << 24);
    }

    // Builds a 64-byte SMB2 header.
    void smb2Header(uint8_t *h, uint16_t command, uint64_t messageId, uint64_t sessionId) {
        memset(h, 0, 64);
        h[0] = 0xFE; h[1] = 'S'; h[2] = 'M'; h[3] = 'B';
        put16(h, 4, 64);               // StructureSize
        put16(h, 12, command);         // Command
        put16(h, 14, 31);              // CreditRequest
        put32(h, 16, 0);               // Flags (request)
        for (int i = 0; i < 8; ++i) h[24 + i] = (uint8_t)(messageId >> (8 * i));
        for (int i = 0; i < 8; ++i) h[40 + i] = (uint8_t)(sessionId >> (8 * i));
    }

    const char *dialectName(uint16_t d) {
        switch (d) {
            case 0x0202: return "2.0.2";
            case 0x0210: return "2.1";
            case 0x0300: return "3.0";
            default: return "unknown";
        }
    }

    bool doNegotiate(WiFiClient &c) {
        uint8_t pkt[64 + 36 + 6];
        smb2Header(pkt, 0x0000, 0, 0);
        uint8_t *body = pkt + 64;
        put16(body, 0, 36);             // StructureSize
        put16(body, 2, 3);               // DialectCount
        put16(body, 4, 0);               // SecurityMode
        put16(body, 6, 0);               // Reserved
        put32(body, 8, 0);               // Capabilities
        for (int i = 0; i < 16; ++i) body[12 + i] = (uint8_t)esp_random(); // ClientGuid
        put32(body, 28, 0); put16(body, 32, 0); put16(body, 34, 0);        // negotiate context (unused <3.1.1)
        put16(body, 36, 0x0202);
        put16(body, 38, 0x0210);
        put16(body, 40, 0x0300);

        if (!nbssWrite(c, pkt, sizeof(pkt))) return false;

        uint8_t resp[512];
        int n = nbssRead(c, resp, sizeof(resp));
        if (n < 64 + 8) { g_error = "negotiate: no/short response"; return false; }

        uint32_t status = get32(resp, 8);
        if (status != 0) { g_error = "negotiate: status " + String(status, 16); return false; }

        const uint8_t *rbody = resp + 64;
        uint16_t secMode = get16(rbody, 2);
        uint16_t dialect = get16(rbody, 4);
        g_signingRequired = (secMode & 0x0002) != 0;
        g_dialect = dialectName(dialect);
        return true;
    }

    // Raw NTLMSSP NEGOTIATE (Type1) message, 32 bytes, no payload.
    int buildNtlmType1(uint8_t *out) {
        memset(out, 0, 32);
        memcpy(out, "NTLMSSP\0", 8);
        out[8] = 1;
        uint32_t flags = 0xA0888205u; // unicode|target|ntlm|alwayssign|extsec|target-info|128|56
        put32(out, 12, flags);
        // domain/workstation fields: length 0, max 0, payload offset 32 (end)
        put16(out, 16, 0); put16(out, 18, 0); put32(out, 20, 32);
        put16(out, 24, 0); put16(out, 26, 0); put32(out, 28, 32);
        return 32;
    }

    // Parses AV_PAIR target-info from an NTLM Type2 to pull domain/computer
    // names, both the NetBIOS (ids 1/2) and DNS (ids 3/4) variants.
    void parseType2TargetInfo(const uint8_t *msg, int len) {
        if (len < 48) return;
        uint16_t tiLen = get16(msg, 40);
        uint32_t tiOff = get32(msg, 44);
        if (tiOff + tiLen > (uint32_t)len) return;
        const uint8_t *p = msg + tiOff;
        int remaining = tiLen;
        while (remaining >= 4) {
            uint16_t avId = p[0] | (p[1] << 8);
            uint16_t avLen = p[2] | (p[3] << 8);
            if (4 + avLen > remaining) break;
            const uint8_t *val = p + 4;
            String s;
            for (int i = 0; i + 1 < avLen; i += 2) s += (char)val[i]; // UTF16LE -> ASCII
            switch (avId) {
                case 1: g_nbComputer = s; break;
                case 2: g_nbDomain = s; break;
                case 3: g_dnsComputer = s; break;
                case 4: g_dnsDomain = s; break;
                default: break;
            }
            if (avId == 0) break; // MsvAvEOL
            p += 4 + avLen;
            remaining -= 4 + avLen;
        }
    }

    bool doSessionSetupNegotiate(WiFiClient &c, uint8_t *type2Out, int &type2Len, uint64_t &sessionIdOut) {
        uint8_t t1[32];
        int t1len = buildNtlmType1(t1);

        uint8_t pkt[64 + 24 + 32];
        smb2Header(pkt, 0x0001, 1, 0);
        uint8_t *body = pkt + 64;
        memset(body, 0, 24);
        put16(body, 0, 25);              // StructureSize
        body[2] = 0;                      // Flags
        body[3] = 1;                      // SecurityMode: signing enabled
        put32(body, 4, 0);                // Capabilities
        put32(body, 8, 0);                // Channel
        put16(body, 12, 64 + 24);          // SecurityBufferOffset
        put16(body, 14, t1len);            // SecurityBufferLength
        memcpy(body + 24, t1, t1len);

        if (!nbssWrite(c, pkt, 64 + 24 + t1len)) return false;

        uint8_t resp[1024];
        int n = nbssRead(c, resp, sizeof(resp));
        if (n < 64 + 8) { g_error = "session-setup#1: no/short response"; return false; }

        uint32_t status = get32(resp, 8);
        // STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
        if (status != 0xC0000016 && status != 0x00000000) {
            g_error = "session-setup#1: status " + String(status, 16);
            return false;
        }
        sessionIdOut = 0;
        for (int i = 0; i < 8; ++i) sessionIdOut |= ((uint64_t)resp[40 + i]) << (8 * i);

        // SecurityBufferOffset is measured from the start of the SMB2
        // header (byte 0 of 'resp'), not from the start of the body - so
        // the buffer is at resp+secOff, never resp+64+secOff.
        const uint8_t *rbody = resp + 64;
        uint16_t secOff = get16(rbody, 4);
        uint16_t secLen = get16(rbody, 6);
        if (secOff + secLen > (uint32_t)n || secLen > 512) { g_error = "session-setup#1: bad buffer"; return false; }

        memcpy(type2Out, resp + secOff, secLen);
        type2Len = secLen;
        parseType2TargetInfo(type2Out, type2Len);
        return true;
    }

    // Empty-credential NTLMSSP AUTHENTICATE (Type3): anonymous null session.
    int buildNtlmType3Anonymous(uint8_t *out) {
        memset(out, 0, 64);
        memcpy(out, "NTLMSSP\0", 8);
        out[8] = 3;
        // Lm/Nt challenge response: len=0, offset=64 (end of fixed header)
        put16(out, 12, 0); put16(out, 14, 0); put32(out, 16, 64);
        put16(out, 20, 0); put16(out, 22, 0); put32(out, 24, 64);
        // Domain/User/Workstation: all empty, offset=64
        put16(out, 28, 0); put16(out, 30, 0); put32(out, 32, 64);
        put16(out, 36, 0); put16(out, 38, 0); put32(out, 40, 64);
        put16(out, 44, 0); put16(out, 46, 0); put32(out, 48, 64);
        // Session key: empty
        put16(out, 52, 0); put16(out, 54, 0); put32(out, 56, 64);
        put32(out, 60, 0xA0088205u);
        return 64;
    }

    bool doSessionSetupAuth(WiFiClient &c, uint64_t sessionId) {
        uint8_t t3[64];
        int t3len = buildNtlmType3Anonymous(t3);

        uint8_t pkt[64 + 24 + 64];
        smb2Header(pkt, 0x0001, 2, sessionId);
        uint8_t *body = pkt + 64;
        memset(body, 0, 24);
        put16(body, 0, 25);
        body[3] = 1;
        put16(body, 12, 64 + 24);
        put16(body, 14, t3len);
        memcpy(body + 24, t3, t3len);

        if (!nbssWrite(c, pkt, 64 + 24 + t3len)) return false;

        uint8_t resp[256];
        int n = nbssRead(c, resp, sizeof(resp));
        if (n < 64 + 8) { g_error = "session-setup#2: no/short response"; return false; }

        uint32_t status = get32(resp, 8);
        return status == 0x00000000;
    }

    void smbTask(void *) {
        WiFiClient c;
        bool ok = c.connect(g_target, 445, 4000);
        if (!ok) { g_error = "tcp connect failed"; g_done = true; g_running = false; g_task = nullptr; vTaskDelete(nullptr); return; }

        if (doNegotiate(c)) {
            uint8_t type2[512]; int type2Len = 0; uint64_t sid = 0;
            if (!g_stopReq && doSessionSetupNegotiate(c, type2, type2Len, sid)) {
                if (!g_stopReq) g_nullSession = doSessionSetupAuth(c, sid);
            }
        }

        c.stop();
        g_done = true;
        g_running = false;
        g_task = nullptr;
        vTaskDelete(nullptr);
    }
}

namespace SmbRecon {

bool start(const IPAddress &target, uint16_t /*port*/) {
    if (g_running) return false;
    g_target = target;
    g_error = g_dialect = g_nbDomain = g_nbComputer = g_dnsDomain = g_dnsComputer = "";
    g_signingRequired = false;
    g_nullSession = false;
    g_done = false;
    g_stopReq = false;
    g_running = true;
    xTaskCreatePinnedToCore(smbTask, "smbrecon", 6144, nullptr, 1, &g_task, 0);
    return true;
}

void stop() { g_stopReq = true; }

String status() {
    JsonDocument doc;
    doc["running"] = g_running;
    doc["done"] = g_done;
    doc["target"] = g_target.toString();
    doc["error"] = g_error;
    doc["dialect"] = g_dialect;
    doc["signingRequired"] = g_signingRequired;
    doc["nullSessionAllowed"] = g_nullSession;
    doc["netbiosDomain"] = g_nbDomain;
    doc["netbiosComputer"] = g_nbComputer;
    doc["dnsDomain"] = g_dnsDomain;
    doc["dnsComputer"] = g_dnsComputer;

    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace SmbRecon
