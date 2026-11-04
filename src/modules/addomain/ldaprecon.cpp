#include "ldaprecon.h"
#include <WiFiClient.h>
#include <ArduinoJson.h>
#include <vector>

namespace {
    volatile bool g_running = false;
    volatile bool g_stopReq = false;
    IPAddress g_target;
    String g_error, g_namingContext, g_dnsHostName;
    bool g_bindOk = false;
    bool g_done = false;
    TaskHandle_t g_task = nullptr;
    LdapRecon::Options g_opt;

    std::vector<String> g_users;
    bool g_usersTruncated = false;
    const size_t MAX_USERS = 1500;

    struct PwPolicy {
        bool have = false;
        long minLen = -1, histLen = -1, lockoutThreshold = -1;
        long long maxPwdAge = 0, minPwdAge = 0, lockoutDuration = 0;
        long pwdProperties = -1;
    } g_pol;

    // ---- minimal BER/DER TLV writer ----
    int berLen(uint8_t *out, int len) {
        if (len < 0x80) { out[0] = (uint8_t)len; return 1; }
        if (len < 0x100) { out[0] = 0x81; out[1] = (uint8_t)len; return 2; }
        out[0] = 0x82; out[1] = (uint8_t)(len >> 8); out[2] = (uint8_t)len; return 3;
    }
    int berTlv(uint8_t *out, uint8_t tag, const uint8_t *val, int vlen) {
        out[0] = tag;
        int lp = berLen(out + 1, vlen);
        if (vlen > 0 && val != nullptr) memcpy(out + 1 + lp, val, vlen);
        return 1 + lp + vlen;
    }
    int berTlvStr(uint8_t *out, uint8_t tag, const char *s) {
        return berTlv(out, tag, (const uint8_t *)s, strlen(s));
    }
    int berEqMatch(uint8_t *out, const char *attr, const char *val) {
        uint8_t inner[160]; int ip = 0;
        ip += berTlvStr(inner + ip, 0x04, attr);
        ip += berTlvStr(inner + ip, 0x04, val);
        return berTlv(out, 0xA3, inner, ip);   // equalityMatch [3]
    }

    // ---- minimal BER reader ----
    struct Tlv { uint8_t tag; int len; int valueOff; int nextOff; };
    bool readTlv(const uint8_t *buf, int pos, int bufLen, Tlv &t) {
        if (pos + 2 > bufLen) return false;
        t.tag = buf[pos];
        int lenByte = buf[pos + 1];
        int lp;
        if (lenByte < 0x80) { t.len = lenByte; lp = 1; }
        else {
            int nbytes = lenByte & 0x7F;
            if (nbytes < 1 || nbytes > 3 || pos + 2 + nbytes > bufLen) return false;
            int l = 0;
            for (int i = 0; i < nbytes; ++i) l = (l << 8) | buf[pos + 2 + i];
            t.len = l; lp = 1 + nbytes;
        }
        t.valueOff = pos + 1 + lp;
        t.nextOff = t.valueOff + t.len;
        return t.nextOff <= bufLen;
    }

    // Receive buffer for the whole connection. A DC routinely packs many
    // LDAPMessages (a run of SearchResEntry plus the SearchResDone) into one
    // TCP segment, so bytes read past the current message must be kept for
    // the next call - discarding them loses entries and the final "done".
    const int RX_CAP = 6144;
    uint8_t g_rx[RX_CAP];
    int g_rxHave = 0;

    // Returns true when one complete LDAPMessage was copied to 'buf' (outLen
    // bytes), or when an oversized one was skipped (outLen == 0). False on
    // timeout, connection loss or a message too large to buffer at all.
    bool readLdapMessage(WiFiClient &c, uint8_t *buf, int cap, int &outLen, uint32_t timeoutMs = 5000) {
        uint32_t deadline = millis() + timeoutMs;
        for (;;) {
            if (g_rxHave >= 2) {
                int lenByte = g_rx[1], hdr, len;
                if (lenByte < 0x80) { hdr = 2; len = lenByte; }
                else {
                    int nb = lenByte & 0x7F;
                    if (nb < 1 || nb > 3) return false;                 // not a sane LDAP message
                    hdr = 2 + nb; len = 0;
                    if (g_rxHave >= hdr) for (int i = 0; i < nb; ++i) len = (len << 8) | g_rx[2 + i];
                }
                if (g_rxHave >= hdr) {
                    int total = hdr + len;
                    if (total > RX_CAP) return false;                   // larger than we can hold
                    if (g_rxHave >= total) {
                        if (total <= cap) { memcpy(buf, g_rx, total); outLen = total; }
                        else outLen = 0;                                // skip: doesn't fit the caller's buffer
                        g_rxHave -= total;
                        if (g_rxHave > 0) memmove(g_rx, g_rx + total, g_rxHave);
                        return true;
                    }
                }
            }
            if (millis() > deadline) return false;
            if (c.available()) {
                int n = c.read(g_rx + g_rxHave, RX_CAP - g_rxHave);
                if (n > 0) g_rxHave += n;
            } else {
                if (!c.connected()) return false;
                delay(5);
            }
        }
    }

    // resultCode of an LDAPResult-shaped op (BindResponse, SearchResultDone...).
    int ldapResultCode(const uint8_t *resp, const Tlv &op) {
        Tlv rc;
        if (!readTlv(resp, op.valueOff, op.nextOff, rc) || rc.tag != 0x0A || rc.len < 1) return -1;
        return resp[rc.valueOff];
    }

    const char *searchErrText(int code) {
        switch (code) {
            case 1:  return "the server wants an authenticated bind for this search (use -u/-p)";
            case 10: return "referral: the base DN lives on another server";
            case 32: return "base DN not found";
            case 50: return "insufficient access rights for this account";
            case 53: return "server unwilling to perform";
            default: return nullptr;
        }
    }

    // messageID is a plain small integer; emit as INTEGER TLV.
    int putMsgId(uint8_t *out, int id) {
        uint8_t v = (uint8_t)id;
        return berTlv(out, 0x02, &v, 1);
    }

    // Sends an LDAPMessage{ id, op } and returns false on write failure.
    bool sendMessage(WiFiClient &c, int msgId, const uint8_t *op, int opLen) {
        uint8_t inner[1024];
        int ip = putMsgId(inner, msgId);
        if (ip + opLen > (int)sizeof(inner)) return false;
        memcpy(inner + ip, op, opLen);
        uint8_t pkt[1100];
        int pl = berTlv(pkt, 0x30, inner, ip + opLen);
        return c.write(pkt, pl) == (size_t)pl;
    }

    const char *bindErrText(int code) {
        switch (code) {
            case 49:  return "invalid credentials";
            case 48:  return "inappropriate authentication";
            case 8:   return "stronger auth required (try LDAPS)";
            case 2:   return "protocol error";
            default:  return nullptr;
        }
    }

    bool doBind(WiFiClient &c) {
        g_rxHave = 0;
        uint8_t op[768]; int op_ = 0;
        uint8_t ver = 0x03; op_ += berTlv(op, 0x02, &ver, 1);         // version 3
        if (g_opt.authenticated) {
            op_ += berTlvStr(op + op_, 0x04, g_opt.bindName.c_str());  // name
            op_ += berTlvStr(op + op_, 0x80, g_opt.password.c_str());  // simple [0] password
        } else {
            op_ += berTlv(op + op_, 0x04, nullptr, 0);                 // name ""
            op_ += berTlv(op + op_, 0x80, nullptr, 0);                 // empty password
        }
        uint8_t req[800];
        int rLen = berTlv(req, 0x60, op, op_);                         // bindRequest [APPLICATION 0]
        if (!sendMessage(c, 1, req, rLen)) { g_error = "bind: send failed"; return false; }

        uint8_t resp[512]; int rlen = 0;
        if (!readLdapMessage(c, resp, sizeof(resp), rlen) || rlen == 0) { g_error = "bind: no response"; return false; }
        Tlv msg, mid, bind;
        if (!readTlv(resp, 0, rlen, msg)) return false;
        if (!readTlv(resp, msg.valueOff, rlen, mid)) return false;
        if (!readTlv(resp, mid.nextOff, rlen, bind) || bind.tag != 0x61) { g_error = "bind: bad response"; return false; }
        Tlv rc;
        if (!readTlv(resp, bind.valueOff, rlen, rc)) return false;
        int code = rc.len >= 1 ? resp[rc.valueOff] : -1;
        if (code != 0) {
            const char *t = bindErrText(code);
            g_error = String("bind failed: ") + (t ? t : ("code " + String(code)).c_str());
            return false;
        }
        return true;
    }

    // Finds the first value of attribute 'wantName' inside a searchResEntry.
    void extractAttr(const uint8_t *buf, int entryValueOff, int entryEnd, const char *wantName, String &out) {
        Tlv objectName;
        if (!readTlv(buf, entryValueOff, entryEnd, objectName)) return;
        Tlv attrs;
        if (!readTlv(buf, objectName.nextOff, entryEnd, attrs)) return;
        int pos = attrs.valueOff, end = attrs.nextOff;
        while (pos < end) {
            Tlv attrSeq;
            if (!readTlv(buf, pos, end, attrSeq)) break;
            Tlv typeTlv;
            if (readTlv(buf, attrSeq.valueOff, attrSeq.nextOff, typeTlv)) {
                String name((const char *)(buf + typeTlv.valueOff), typeTlv.len);
                if (name.equalsIgnoreCase(wantName)) {
                    Tlv valsSet;
                    if (readTlv(buf, typeTlv.nextOff, attrSeq.nextOff, valsSet)) {
                        Tlv firstVal;
                        if (readTlv(buf, valsSet.valueOff, valsSet.nextOff, firstVal))
                            out = String((const char *)(buf + firstVal.valueOff), firstVal.len);
                    }
                }
            }
            pos = attrSeq.nextOff;
        }
    }

    // Builds + sends a SearchRequest. filter is a pre-encoded Filter TLV.
    bool sendSearch(WiFiClient &c, int msgId, const char *baseDn, uint8_t scope,
                    const uint8_t *filter, int filterLen, const char **attrs, int nAttrs) {
        uint8_t body[768]; int bp = 0;
        bp += berTlvStr(body + bp, 0x04, baseDn);
        bp += berTlv(body + bp, 0x0A, &scope, 1);
        uint8_t deref = 0; bp += berTlv(body + bp, 0x0A, &deref, 1);
        uint8_t zero = 0; bp += berTlv(body + bp, 0x02, &zero, 1);   // sizeLimit 0
        bp += berTlv(body + bp, 0x02, &zero, 1);                     // timeLimit 0
        bp += berTlv(body + bp, 0x01, &zero, 1);                     // typesOnly false
        memcpy(body + bp, filter, filterLen); bp += filterLen;
        uint8_t ab[256]; int ap = 0;
        for (int i = 0; i < nAttrs; ++i) ap += berTlvStr(ab + ap, 0x04, attrs[i]);
        bp += berTlv(body + bp, 0x30, ab, ap);
        uint8_t req[800];
        int rLen = berTlv(req, 0x63, body, bp);                      // searchRequest [APPLICATION 3]
        return sendMessage(c, msgId, req, rLen);
    }

    bool doRootDse(WiFiClient &c) {
        uint8_t filter[64]; int fl = berTlvStr(filter, 0x87, "objectClass"); // present
        const char *attrs[] = {"defaultNamingContext", "dnsHostName"};
        if (!sendSearch(c, 2, "", 0, filter, fl, attrs, 2)) return false;
        for (int i = 0; i < 6 && !g_stopReq; ++i) {
            uint8_t resp[1536]; int rlen = 0;
            if (!readLdapMessage(c, resp, sizeof(resp), rlen)) return false;
            if (rlen == 0) continue;
            Tlv msg, mid, op;
            if (!readTlv(resp, 0, rlen, msg)) return false;
            if (!readTlv(resp, msg.valueOff, rlen, mid)) return false;
            if (!readTlv(resp, mid.nextOff, rlen, op)) return false;
            if (op.tag == 0x64) {
                extractAttr(resp, op.valueOff, op.nextOff, "defaultNamingContext", g_namingContext);
                extractAttr(resp, op.valueOff, op.nextOff, "dnsHostName", g_dnsHostName);
            } else if (op.tag == 0x65) return true;
        }
        return true;
    }

    bool doUserSearch(WiFiClient &c) {
        if (g_namingContext.length() == 0) { g_error = "no naming context"; return false; }
        // filter = (&(objectCategory=person)(objectClass=user))
        uint8_t f1[160], f2[160];
        int n1 = berEqMatch(f1, "objectCategory", "person");
        int n2 = berEqMatch(f2, "objectClass", "user");
        uint8_t both[360]; int bn = 0;
        memcpy(both + bn, f1, n1); bn += n1;
        memcpy(both + bn, f2, n2); bn += n2;
        uint8_t filter[400]; int fl = berTlv(filter, 0xA0, both, bn);   // and [0]
        const char *attrs[] = {"sAMAccountName"};
        if (!sendSearch(c, 3, g_namingContext.c_str(), 2 /*subtree*/, filter, fl, attrs, 1)) return false;

        int guard = 0;
        while (!g_stopReq && guard++ < 6000) {
            uint8_t resp[1536]; int rlen = 0;
            if (!readLdapMessage(c, resp, sizeof(resp), rlen)) {
                if (g_users.empty() && g_error.length() == 0) g_error = "user search: no response from the server";
                return false;
            }
            if (rlen == 0) continue;
            Tlv msg, mid, op;
            if (!readTlv(resp, 0, rlen, msg)) return false;
            if (!readTlv(resp, msg.valueOff, rlen, mid)) return false;
            if (!readTlv(resp, mid.nextOff, rlen, op)) return false;
            if (op.tag == 0x64) {
                String u;
                extractAttr(resp, op.valueOff, op.nextOff, "sAMAccountName", u);
                if (u.length()) {
                    if (g_users.size() < MAX_USERS) g_users.push_back(u);
                    else { g_usersTruncated = true; }
                }
            } else if (op.tag == 0x65) {
                int code = ldapResultCode(resp, op);
                if (code == 4) {                       // sizeLimitExceeded: AD caps an unpaged search at 1000 entries
                    g_usersTruncated = true;
                } else if (code > 0) {
                    const char *t = searchErrText(code);
                    g_error = String("user search: ") + (t ? t : ("LDAP result code " + String(code)).c_str());
                    return false;
                }
                return true;
            }
        }
        return true;
    }

    long long parseLL(const String &s) { return strtoll(s.c_str(), nullptr, 10); }

    bool doPassPol(WiFiClient &c) {
        if (g_namingContext.length() == 0) { g_error = "no naming context"; return false; }
        uint8_t filter[64]; int fl = berTlvStr(filter, 0x87, "objectClass"); // present
        const char *attrs[] = {"minPwdLength", "pwdHistoryLength", "maxPwdAge",
                               "minPwdAge", "lockoutThreshold", "lockoutDuration", "pwdProperties"};
        if (!sendSearch(c, 4, g_namingContext.c_str(), 0 /*base*/, filter, fl, attrs, 7)) return false;
        for (int i = 0; i < 6 && !g_stopReq; ++i) {
            uint8_t resp[1536]; int rlen = 0;
            if (!readLdapMessage(c, resp, sizeof(resp), rlen)) return false;
            if (rlen == 0) continue;
            Tlv msg, mid, op;
            if (!readTlv(resp, 0, rlen, msg)) return false;
            if (!readTlv(resp, msg.valueOff, rlen, mid)) return false;
            if (!readTlv(resp, mid.nextOff, rlen, op)) return false;
            if (op.tag == 0x64) {
                String v;
                v=""; extractAttr(resp, op.valueOff, op.nextOff, "minPwdLength", v); if (v.length()) g_pol.minLen = v.toInt();
                v=""; extractAttr(resp, op.valueOff, op.nextOff, "pwdHistoryLength", v); if (v.length()) g_pol.histLen = v.toInt();
                v=""; extractAttr(resp, op.valueOff, op.nextOff, "lockoutThreshold", v); if (v.length()) g_pol.lockoutThreshold = v.toInt();
                v=""; extractAttr(resp, op.valueOff, op.nextOff, "pwdProperties", v); if (v.length()) g_pol.pwdProperties = v.toInt();
                v=""; extractAttr(resp, op.valueOff, op.nextOff, "maxPwdAge", v); if (v.length()) g_pol.maxPwdAge = parseLL(v);
                v=""; extractAttr(resp, op.valueOff, op.nextOff, "minPwdAge", v); if (v.length()) g_pol.minPwdAge = parseLL(v);
                v=""; extractAttr(resp, op.valueOff, op.nextOff, "lockoutDuration", v); if (v.length()) g_pol.lockoutDuration = parseLL(v);
                g_pol.have = true;
            } else if (op.tag == 0x65) {
                int code = ldapResultCode(resp, op);
                if (code > 0 && !g_pol.have) {
                    const char *t = searchErrText(code);
                    g_error = String("password policy: ") + (t ? t : ("LDAP result code " + String(code)).c_str());
                    return false;
                }
                return true;
            }
        }
        return true;
    }

    void ldapTask(void *) {
        WiFiClient c;
        if (!c.connect(g_target, 389, 4000)) {
            g_error = "tcp connect failed"; g_done = true; g_running = false; g_task = nullptr; vTaskDelete(nullptr); return;
        }
        g_bindOk = doBind(c);
        if (g_bindOk && !g_stopReq) {
            doRootDse(c);
            if (g_opt.enumUsers && !g_stopReq) doUserSearch(c);
            if (g_opt.passPolicy && !g_stopReq) doPassPol(c);
        }
        c.stop();
        g_done = true; g_running = false; g_task = nullptr;
        vTaskDelete(nullptr);
    }
}

namespace LdapRecon {

bool start(const IPAddress &target, const Options &opt) {
    if (g_running) return false;
    g_target = target;
    g_opt = opt;
    g_error = g_namingContext = g_dnsHostName = "";
    g_bindOk = g_done = g_stopReq = false;
    g_users.clear();
    g_usersTruncated = false;
    g_pol = PwPolicy();
    g_running = true;
    xTaskCreatePinnedToCore(ldapTask, "ldaprecon", 12288, nullptr, 1, &g_task, 0);
    return true;
}

void stop() { g_stopReq = true; }

bool running() { return g_running; }
size_t userCount() { return g_users.size(); }
String userAt(size_t i) { return i < g_users.size() ? g_users[i] : String(); }
bool usersTruncated() { return g_usersTruncated; }

String status(bool includeUsers) {
    JsonDocument doc;
    doc["running"] = g_running;
    doc["done"] = g_done;
    doc["target"] = g_target.toString();
    doc["error"] = g_error;
    doc["bindType"] = g_opt.authenticated ? "authenticated" : "anonymous";
    doc["bindOk"] = g_bindOk;
    doc["defaultNamingContext"] = g_namingContext;
    doc["dnsHostName"] = g_dnsHostName;

    if (g_opt.enumUsers) {
        if (includeUsers) {
            JsonArray arr = doc["users"].to<JsonArray>();
            for (auto &u : g_users) arr.add(u);
        }
        doc["userCount"] = g_users.size();
        doc["usersTruncated"] = g_usersTruncated;
    }
    if (g_opt.passPolicy && g_pol.have) {
        JsonObject p = doc["passwordPolicy"].to<JsonObject>();
        p["minPwdLength"] = g_pol.minLen;
        p["pwdHistoryLength"] = g_pol.histLen;
        p["lockoutThreshold"] = g_pol.lockoutThreshold;
        // AD stores these as negative 100-ns intervals; convert to friendly units.
        p["maxPwdAgeDays"] = g_pol.maxPwdAge ? (double)(-g_pol.maxPwdAge) / 864000000000.0 : 0;
        p["minPwdAgeDays"] = g_pol.minPwdAge ? (double)(-g_pol.minPwdAge) / 864000000000.0 : 0;
        p["lockoutDurationMin"] = g_pol.lockoutDuration ? (double)(-g_pol.lockoutDuration) / 600000000.0 : 0;
        if (g_pol.pwdProperties >= 0)
            p["complexity"] = (g_pol.pwdProperties & 0x1) ? "enabled" : "disabled";
    }

    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace LdapRecon
