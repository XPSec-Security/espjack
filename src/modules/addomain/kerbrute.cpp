#include "kerbrute.h"
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

    struct Found { String user; String status; };
    std::vector<Found> g_found;
    SemaphoreHandle_t g_mtx = nullptr;
    TaskHandle_t g_task = nullptr;

    // Classifies the KDC's answer to an AS-REQ sent without pre-authentication:
    //   "valid"           KDC_ERR_PREAUTH_REQUIRED - the account exists
    //   "valid_nopreauth" a bare AS-REP - exists and AS-REP roastable
    //   "valid_disabled"  KDC_ERR_CLIENT_REVOKED - exists but disabled/locked out
    //   "invalid"         KDC_ERR_C_PRINCIPAL_UNKNOWN
    //   ""                anything else (inconclusive); *errCode gets the KRB-ERROR code
    String classify(const uint8_t *msg, int len, int *errCode) {
        if (Krb::isAsRep(msg, len)) return "valid_nopreauth";
        int code = Krb::errorCode(msg, len);
        if (errCode) *errCode = code;
        switch (code) {
            case Krb::ERR_PREAUTH_REQUIRED:    return "valid";
            case Krb::ERR_CLIENT_REVOKED:      return "valid_disabled";
            case Krb::ERR_C_PRINCIPAL_UNKNOWN: return "invalid";
            default:                           return "";
        }
    }

    bool probeUser(WiFiClient &c, const String &user, String &outStatus, int &errCode) {
        static const int ETYPES[] = {18, 17, 23, 3};
        uint8_t pkt[768];
        int len = Krb::buildAsReq(pkt, sizeof(pkt), user, g_realm, ETYPES, 4);
        if (len < 0 || !Krb::sendFramed(c, pkt, len)) return false;

        int rlen = 0;
        uint8_t *resp = Krb::recvFramed(c, rlen, 3000);
        if (!resp) return false;
        errCode = -1;
        outStatus = classify(resp, rlen, &errCode);
        free(resp);
        return true;
    }

    void runKerbrute() {
        g_total = Krb::countWords(g_wordlist.c_str(), 64);
        File f = SD.open(g_wordlist.c_str(), FILE_READ);
        if (!f) { g_error = "wordlist not found: " + g_wordlist; return; }

        String user; bool sawRealmErr = false, sawOther = false; int otherCode = 0;
        while (!g_stopReq && Krb::nextWord(f, user, 64)) {
            WiFiClient c;
            if (c.connect(g_kdc, g_port, 3000)) {
                String status; int err = -1;
                if (probeUser(c, user, status, err)) {
                    if (status == "valid" || status == "valid_nopreauth" || status == "valid_disabled") {
                        if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
                        g_found.push_back({user, status});
                        if (g_mtx) xSemaphoreGive(g_mtx);
                    } else if (status.length() == 0 && err >= 0) {
                        if (err == Krb::ERR_WRONG_REALM) sawRealmErr = true;
                        else { sawOther = true; otherCode = err; }
                    }
                }
                c.stop();
            } else if (g_done == 0) {
                g_error = "cannot connect to the KDC on TCP/" + String(g_port);
            }
            g_done++;
            vTaskDelay(pdMS_TO_TICKS(50)); // be gentle with the KDC
        }
        f.close();

        if (sawRealmErr) g_error = "KDC rejected the realm (KDC_ERR_WRONG_REALM) - check the domain name";
        else if (sawOther && g_found.empty()) g_error = "KDC answered with KRB-ERROR " + String(otherCode) + " (inconclusive)";
    }

    void kerbruteTask(void *) {
        runKerbrute();
        g_running = false;
        g_task = nullptr;
        vTaskDelete(nullptr);
    }
}

namespace Kerbrute {

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
    xTaskCreatePinnedToCore(kerbruteTask, "kerbrute", 12288, nullptr, 1, &g_task, 0);
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
    for (auto &f : g_found) {
        JsonObject o = arr.add<JsonObject>();
        o["user"] = f.user;
        o["status"] = f.status;
    }
    if (g_mtx) xSemaphoreGive(g_mtx);

    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace Kerbrute
