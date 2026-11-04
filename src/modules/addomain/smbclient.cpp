#include "smbclient.h"
#include <WiFiClient.h>
#include <esp_random.h>
#include "mbedtls/md.h"
#include "../common/ntcrypto.h"

namespace {
    using NtCrypto::MD4;

    void hmac(mbedtls_md_type_t t, const uint8_t *key, size_t klen,
              const uint8_t *data, size_t dlen, uint8_t *out) {
        const mbedtls_md_info_t *info = mbedtls_md_info_from_type(t);
        mbedtls_md_hmac(info, key, klen, data, dlen, out);
    }
    void hmacMd5(const uint8_t *k, size_t kl, const uint8_t *d, size_t dl, uint8_t *o) {
        hmac(MBEDTLS_MD_MD5, k, kl, d, dl, o);
    }

    // UTF-8 -> UTF16LE; callers size buffers as 2x the input length.
    int toUtf16(const String &s, uint8_t *out) { return NtCrypto::utf8ToUtf16le(s.c_str(), s.length(), out); }

    // Appends one Unicode code point to a String as UTF-8.
    void appendUtf8(String &s, uint32_t cp) {
        if (cp < 0x80) s += (char)cp;
        else if (cp < 0x800) { s += (char)(0xC0 | (cp >> 6)); s += (char)(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) { s += (char)(0xE0 | (cp >> 12)); s += (char)(0x80 | ((cp >> 6) & 0x3F)); s += (char)(0x80 | (cp & 0x3F)); }
        else { s += (char)(0xF0 | (cp >> 18)); s += (char)(0x80 | ((cp >> 12) & 0x3F)); s += (char)(0x80 | ((cp >> 6) & 0x3F)); s += (char)(0x80 | (cp & 0x3F)); }
    }

    void put16(uint8_t *b, int o, uint16_t v) { b[o]=v&0xFF; b[o+1]=(v>>8)&0xFF; }
    void put32(uint8_t *b, int o, uint32_t v) { b[o]=v; b[o+1]=v>>8; b[o+2]=v>>16; b[o+3]=v>>24; }
    uint16_t get16(const uint8_t *b, int o) { return b[o] | (b[o+1] << 8); }
    uint32_t get32(const uint8_t *b, int o) { return (uint32_t)b[o] | ((uint32_t)b[o+1]<<8) | ((uint32_t)b[o+2]<<16) | ((uint32_t)b[o+3]<<24); }
    uint64_t get64(const uint8_t *b, int o) { uint64_t v=0; for (int i=0;i<8;++i) v |= (uint64_t)b[o+i] << (8*i); return v; }

    // SMB2 commands / statuses / flags
    enum { C_NEGOTIATE=0, C_SESSION_SETUP=1, C_LOGOFF=2, C_TREE_CONNECT=3,
           C_TREE_DISCONNECT=4, C_CREATE=5, C_CLOSE=6, C_READ=8, C_WRITE=9,
           C_QUERY_DIRECTORY=0x0E };
    const uint32_t ST_SUCCESS = 0x00000000;
    const uint32_t ST_MORE    = 0xC0000016;
    const uint32_t ST_NOMORE  = 0x80000006;
    const uint32_t FLAGS_SIGNED = 0x00000008;
}

namespace SmbClient {

struct Session::Impl {
    WiFiClient c;
    uint64_t messageId = 0;
    uint64_t sessionId = 0;
    uint32_t treeId = 0;
    uint8_t sessionKey[16] = {0};
    bool sign = false;
    bool haveKey = false;
    uint32_t callId = 1;            // DCE/RPC call_id, per session

    bool nbssWrite(const uint8_t *buf, size_t len) {
        uint8_t h[4] = {0, (uint8_t)((len>>16)&0xFF), (uint8_t)((len>>8)&0xFF), (uint8_t)(len&0xFF)};
        c.write(h, 4);
        return c.write(buf, len) == len;
    }
    int nbssRead(uint8_t *buf, size_t cap, uint32_t timeoutMs = 5000) {
        uint32_t dl = millis() + timeoutMs;
        while (c.available() < 4) { if (millis() > dl || !c.connected()) return -1; delay(5); }
        uint8_t h[4]; c.read(h, 4);
        uint32_t len = ((uint32_t)h[1]<<16) | ((uint32_t)h[2]<<8) | h[3];
        if (len > cap) return -1;
        size_t got = 0;
        while (got < len) {
            if (millis() > dl || !c.connected()) return -1;
            int n = c.available() ? c.read(buf+got, len-got) : (delay(3), 0);
            if (n > 0) got += n;
        }
        return (int)len;
    }

    void header(uint8_t *h, uint16_t cmd, bool useTree) {
        memset(h, 0, 64);
        h[0]=0xFE; h[1]='S'; h[2]='M'; h[3]='B';
        put16(h, 4, 64);
        put16(h, 12, cmd);
        put16(h, 14, 256);              // CreditRequest
        for (int i=0;i<8;++i) h[24+i] = (uint8_t)(messageId >> (8*i));
        if (useTree) put32(h, 36, treeId);
        for (int i=0;i<8;++i) h[40+i] = (uint8_t)(sessionId >> (8*i));
    }

    // Builds header+body, signs if needed, sends, reads the reply into resp.
    // Returns total reply length (incl. 64-byte header) or -1; *st = status.
    int transact(uint16_t cmd, const uint8_t *body, int bodyLen, bool useTree,
                 uint8_t *resp, int respCap, uint32_t *st) {
        int total = 64 + bodyLen;
        uint8_t *msg = (uint8_t *)malloc(total);
        if (!msg) return -1;
        header(msg, cmd, useTree);
        if (bodyLen) memcpy(msg + 64, body, bodyLen);
        if (sign && haveKey) {
            put32(msg, 16, get32(msg,16) | FLAGS_SIGNED);
            memset(msg + 48, 0, 16);
            uint8_t mac[32];
            hmac(MBEDTLS_MD_SHA256, sessionKey, 16, msg, total, mac);
            memcpy(msg + 48, mac, 16);
        }
        messageId++;
        bool wok = nbssWrite(msg, total);
        free(msg);
        if (!wok) return -1;
        int n = nbssRead(resp, respCap);
        // A server that can't answer right away (typical for a named-pipe
        // READ) first sends an interim async response with STATUS_PENDING;
        // the real one follows on the same connection.
        while (n >= 64 && get32(resp, 8) == 0x00000103) n = nbssRead(resp, respCap, 15000);
        if (n < 64) return -1;
        if (st) *st = get32(resp, 8);
        return n;
    }
};

Session::~Session() { close(); }

void Session::close() {
    if (!p) return;
    if (p->c.connected()) {
        uint8_t resp[256]; uint32_t st;
        if (p->treeId) { uint8_t b[4]; put16(b,0,4); put16(b,2,0); p->transact(C_TREE_DISCONNECT, b, 4, true, resp, sizeof(resp), &st); }
        if (p->sessionId) { uint8_t b[4]; put16(b,0,4); put16(b,2,0); p->transact(C_LOGOFF, b, 4, false, resp, sizeof(resp), &st); }
        p->c.stop();
    }
    delete p;
    p = nullptr;
}

bool Session::open(const IPAddress &host, const Creds &creds, String &err) {
    p = new Impl();

    if (!p->c.connect(host, 445, connectTimeoutMs)) { err = "TCP connect failed"; return false; }

    // ---- NEGOTIATE (offer 2.0.2 + 2.1 so signing stays HMAC-SHA256) ----
    uint8_t neg[36 + 4];
    memset(neg, 0, sizeof(neg));
    put16(neg, 0, 36);
    put16(neg, 2, 2);               // DialectCount
    put16(neg, 4, 1);               // SecurityMode: signing enabled
    for (int i=0;i<16;++i) neg[12+i] = (uint8_t)esp_random();
    put16(neg, 36, 0x0202);
    put16(neg, 38, 0x0210);

    uint8_t resp[512]; uint32_t st;
    int n = p->transact(C_NEGOTIATE, neg, sizeof(neg), false, resp, sizeof(resp), &st);
    if (n < 72 || st != ST_SUCCESS) { err = "negotiate failed"; return false; }
    uint16_t secMode = get16(resp + 64, 2);
    uint16_t dial = get16(resp + 64, 4);
    signingRequired = (secMode & 0x0002) != 0;
    p->sign = (secMode & 0x0003) != 0;
    dialect = dial == 0x0202 ? "2.0.2" : dial == 0x0210 ? "2.1" : "unknown";

    // ---- SESSION_SETUP #1 : NTLM Type1 (raw NTLMSSP) ----
    uint8_t t1[32]; memset(t1, 0, 32);
    memcpy(t1, "NTLMSSP\0", 8); t1[8]=1; put32(t1, 12, 0xA0888215u);
    // Domain and workstation fields: length 0, max 0, payload offset 32.
    put16(t1, 16, 0); put16(t1, 18, 0); put32(t1, 20, 32);
    put16(t1, 24, 0); put16(t1, 26, 0); put32(t1, 28, 32);

    uint8_t ss[24 + 32];
    memset(ss, 0, sizeof(ss));
    put16(ss, 0, 25); ss[3]=1; put16(ss, 12, 64+24); put16(ss, 14, 32);
    memcpy(ss + 24, t1, 32);
    n = p->transact(C_SESSION_SETUP, ss, sizeof(ss), false, resp, sizeof(resp), &st);
    if (n < 72 || st != ST_MORE) { err = "session setup rejected"; return false; }
    p->sessionId = get64(resp, 40);

    uint16_t secOff = get16(resp + 64, 4);
    uint16_t secLen = get16(resp + 64, 6);
    if (secOff + secLen > (uint32_t)n || secLen < 48) { err = "bad challenge"; return false; }
    const uint8_t *t2 = resp + secOff;

    uint8_t serverChallenge[8];
    memcpy(serverChallenge, t2 + 24, 8);
    uint16_t tiLen = get16(t2, 40);
    uint32_t tiOff = get32(t2, 44);
    if (tiOff + tiLen > (uint32_t)secLen) { err = "bad target info"; return false; }
    const uint8_t *targetInfo = t2 + tiOff;

    // Pull computer/domain names from the target-info AV pairs (for display
    // and for local-auth, whose NTLMv2 target is the computer name).
    {
        const uint8_t *q = targetInfo; int rem = tiLen;
        while (rem >= 4) {
            uint16_t id = get16(q, 0), ln = get16(q, 2);
            if (4 + ln > rem) break;
            String s; for (int i=0;i+1<ln;i+=2) s += (char)q[4+i];
            if (id == 1) computerName = s; else if (id == 2) domainName = s;
            if (id == 0) break;
            q += 4 + ln; rem -= 4 + ln;
        }
    }

    // Which domain goes into the NTLMv2 hash and the Type3 message:
    //   --local-auth  the target's own computer name (its local SAM)
    //   -d <domain>   exactly what the user typed
    //   neither       the NetBIOS domain the server announced in its
    //                 challenge. A domain-joined host or a DC announces the
    //                 AD domain (so this is a domain login), a standalone
    //                 box announces its own name (so it is a local login) -
    //                 no need to know in advance which one the target is.
    authDomain = creds.localAuth ? computerName
               : (creds.domain.length() ? creds.domain : domainName);

    // ---- compute NTLMv2 response ----
    uint8_t ntHash[16];
    if (creds.haveHash) memcpy(ntHash, creds.ntHash, 16);
    else {
        NtCrypto::ntHash(creds.password, ntHash);
    }

    String userUp = creds.user; userUp.toUpperCase();
    uint8_t idbuf[256]; int il = toUtf16(userUp + authDomain, idbuf);
    uint8_t ntlmv2Hash[16];
    hmacMd5(ntHash, 16, idbuf, il, ntlmv2Hash);

    uint8_t clientChallenge[8];
    for (int i=0;i<8;++i) clientChallenge[i] = (uint8_t)esp_random();
    uint64_t ts = (uint64_t)11644473600ULL * 10000000ULL; // epoch-ish filetime; servers accept any

    // blob = 0x01 0x01 00*6 timestamp(8) clientChallenge(8) 00*4 targetInfo 00*4
    int blobLen = 8 + 8 + 8 + 4 + tiLen + 4;
    uint8_t *blob = (uint8_t *)malloc(blobLen);
    int bp = 0;
    blob[bp++]=1; blob[bp++]=1; blob[bp++]=0; blob[bp++]=0; blob[bp++]=0; blob[bp++]=0; blob[bp++]=0; blob[bp++]=0;
    for (int i=0;i<8;++i) blob[bp++] = (uint8_t)(ts >> (8*i));
    memcpy(blob+bp, clientChallenge, 8); bp += 8;
    put32(blob, bp, 0); bp += 4;
    memcpy(blob+bp, targetInfo, tiLen); bp += tiLen;
    put32(blob, bp, 0); bp += 4;

    // ntProof = HMAC_MD5(ntlmv2Hash, serverChallenge + blob)
    uint8_t *tmp = (uint8_t *)malloc(8 + blobLen);
    memcpy(tmp, serverChallenge, 8); memcpy(tmp+8, blob, blobLen);
    uint8_t ntProof[16];
    hmacMd5(ntlmv2Hash, 16, tmp, 8 + blobLen, ntProof);
    free(tmp);

    // sessionBaseKey = HMAC_MD5(ntlmv2Hash, ntProof); no key exch -> that's it
    // The key is only used to sign requests *after* the session is
    // established: the final SESSION_SETUP itself must go out unsigned
    // (servers that require signing, e.g. Windows 11 24H2, answer
    // STATUS_INVALID_PARAMETER to a signed one). haveKey flips on below.
    hmacMd5(ntlmv2Hash, 16, ntProof, 16, p->sessionKey);

    int ntRespLen = 16 + blobLen;
    uint8_t *ntResp = (uint8_t *)malloc(ntRespLen);
    memcpy(ntResp, ntProof, 16); memcpy(ntResp + 16, blob, blobLen);
    free(blob);

    // LMv2 = HMAC_MD5(ntlmv2Hash, serverChallenge + clientChallenge) + clientChallenge
    uint8_t lmCat[16], lmResp[24];
    { uint8_t t[16]; memcpy(t, serverChallenge, 8); memcpy(t+8, clientChallenge, 8);
      hmacMd5(ntlmv2Hash, 16, t, 16, lmCat); }
    memcpy(lmResp, lmCat, 16); memcpy(lmResp + 16, clientChallenge, 8);

    // ---- build NTLM Type3 ----
    uint8_t dom[128], usr[128], ws[32];
    int domL = toUtf16(authDomain, dom);
    int usrL = toUtf16(creds.user, usr);
    int wsL  = toUtf16("ESPJACK", ws);

    int payload = 64;
    int t3cap = payload + domL + usrL + wsL + 24 + ntRespLen;
    uint8_t *t3 = (uint8_t *)malloc(t3cap);
    memset(t3, 0, 64);
    memcpy(t3, "NTLMSSP\0", 8); t3[8] = 3;
    int off = payload;
    // LM (24)
    put16(t3, 12, 24); put16(t3, 14, 24); put32(t3, 16, off); memcpy(t3+off, lmResp, 24); off += 24;
    // NT
    put16(t3, 20, ntRespLen); put16(t3, 22, ntRespLen); put32(t3, 24, off); memcpy(t3+off, ntResp, ntRespLen); off += ntRespLen;
    // Domain
    put16(t3, 28, domL); put16(t3, 30, domL); put32(t3, 32, off); memcpy(t3+off, dom, domL); off += domL;
    // User
    put16(t3, 36, usrL); put16(t3, 38, usrL); put32(t3, 40, off); memcpy(t3+off, usr, usrL); off += usrL;
    // Workstation
    put16(t3, 44, wsL); put16(t3, 46, wsL); put32(t3, 48, off); memcpy(t3+off, ws, wsL); off += wsL;
    // Session key (none)
    put16(t3, 52, 0); put16(t3, 54, 0); put32(t3, 56, off);
    put32(t3, 60, 0xA0888215u);
    free(ntResp);

    // ---- SESSION_SETUP #2 (unsigned; signing starts with the next request) ----
    int ss2Len = 24 + off;
    uint8_t *ss2 = (uint8_t *)malloc(ss2Len);
    memset(ss2, 0, 24);
    put16(ss2, 0, 25); ss2[3]=1; put16(ss2, 12, 64+24); put16(ss2, 14, off);
    memcpy(ss2 + 24, t3, off);
    free(t3);
    n = p->transact(C_SESSION_SETUP, ss2, ss2Len, false, resp, sizeof(resp), &st);
    free(ss2);
    if (n < 64) { err = "session setup #2 no reply"; return false; }
    if (st != ST_SUCCESS) {
        err = (st == 0xC000006D || st == 0xC000006A) ? "auth failed (bad credentials)"
            : (st == 0xC0000234) ? "account locked"
            : (st == 0xC0000072) ? "account disabled"
            : "auth failed (status " + String(st, 16) + ")";
        return false;
    }
    p->haveKey = true;      // from here on every request is signed (if signing is on)
    // Some servers map bad/empty creds to a guest or anonymous session and
    // still return SUCCESS; that isn't a real credential validation.
    uint16_t sessionFlags = get16(resp + 64, 2);
    if (sessionFlags & 0x0003) {
        err = (sessionFlags & 0x0002) ? "mapped to null session (creds not accepted)"
                                       : "mapped to guest (creds not accepted)";
        return false;
    }
    return true;
}

bool Session::treeConnect(const String &share, String &err) {
    if (!p) { err = "not connected"; return false; }
    String path = "\\\\" + p->c.remoteIP().toString() + "\\" + share;
    uint8_t up[512]; int ul = toUtf16(path, up);
    // TREE_CONNECT: 8-byte fixed part (StructureSize=9 per SMB2 convention),
    // then the path. PathOffset is measured from the SMB2 header start.
    uint8_t body[8 + 512];
    put16(body, 0, 9); put16(body, 2, 0);
    put16(body, 4, 64 + 8); put16(body, 6, ul);
    memcpy(body + 8, up, ul);
    uint8_t resp[256]; uint32_t st;
    int n = p->transact(C_TREE_CONNECT, body, 8 + ul, true, resp, sizeof(resp), &st);
    if (n < 64 || st != ST_SUCCESS) {
        err = (st == 0xC00000CC) ? "no such share" :
              (st == 0xC0000022) ? "access denied" : "tree connect failed (" + String(st,16) + ")";
        return false;
    }
    p->treeId = get32(resp, 36);
    return true;
}

// Admin rights on the target = the administrative share opens. ADMIN$ (and
// C$) carry an ACL that only lets Administrators in, so a successful tree
// connect is the standard "is this account admin here" probe. It only reads
// the tree-connect status - nothing is opened, read or written.
int Session::checkAdmin(String &detail) {
    static const char *shares[] = { "ADMIN$", "C$" };
    for (const char *sh : shares) {
        String e;
        if (treeConnect(sh, e)) { detail = String(sh) + " accessible"; return 1; }
        if (e == "access denied") { detail = String(sh) + " access denied"; return 0; }
        if (e == "no such share") { detail = String(sh) + " does not exist"; continue; }   // try the next one
        detail = e; return -1;
    }
    detail += " (administrative shares are disabled)";
    return -1;
}

namespace {
    // Build a CREATE request into body; returns length. name may be empty
    // (share root). Paths use backslashes.
    int buildCreate(uint8_t *body, const String &name, uint32_t access,
                    uint32_t disposition, uint32_t options) {
        memset(body, 0, 56);
        put16(body, 0, 57);
        put32(body, 4, 2);                 // ImpersonationLevel
        put32(body, 24, access);
        put32(body, 32, 7);                // ShareAccess R|W|D
        put32(body, 36, disposition);
        put32(body, 40, options);
        uint8_t nm[512]; int nl = toUtf16(name, nm);
        put16(body, 44, 64 + 56);           // NameOffset from header
        put16(body, 46, nl);
        if (nl == 0) { body[56] = 0; return 57; }   // 1 filler byte
        memcpy(body + 56, nm, nl);
        return 56 + nl;
    }
}

bool Session::list(const String &path, std::vector<DirEntry> &out, String &err) {
    if (!p) { err = "not connected"; return false; }
    String name = path; name.replace("/", "\\");
    while (name.startsWith("\\")) name.remove(0, 1);
    while (name.endsWith("\\")) name.remove(name.length()-1);

    uint8_t body[600]; uint32_t st;
    int bl = buildCreate(body, name, 0x81 /*LIST_DIRECTORY|READ_ATTR*/, 1 /*OPEN*/, 0x01 /*DIRECTORY*/);
    uint8_t cresp[512];
    int n = p->transact(C_CREATE, body, bl, true, cresp, sizeof(cresp), &st);
    if (n < 64 || st != ST_SUCCESS) {
        err = (st == 0xC0000022) ? "access denied" :
              (st == 0xC000003A || st == 0xC0000034) ? "no such directory" : "open failed (" + String(st,16) + ")";
        return false;
    }
    uint8_t fileId[16]; memcpy(fileId, cresp + 64 + 64, 16);

    const int OUTBUF = 8192;
    uint8_t *qresp = (uint8_t *)malloc(64 + OUTBUF + 128);
    bool first = true;
    while (true) {
        uint8_t pat[4]; int pl = toUtf16("*", pat);
        // Fixed part is 32 bytes (StructureSize 33 counts 1 byte of the
        // variable buffer), so the pattern starts at body offset 32.
        uint8_t qb[32 + 8];
        memset(qb, 0, sizeof(qb));
        put16(qb, 0, 33);
        qb[2] = 3;                          // FileBothDirectoryInformation
        qb[3] = first ? 0x01 : 0x00;        // RESTART_SCANS
        memcpy(qb + 8, fileId, 16);
        put16(qb, 24, 64 + 32);
        put16(qb, 26, pl);
        put32(qb, 28, OUTBUF);
        memcpy(qb + 32, pat, pl);
        uint32_t qst;
        int qn = p->transact(C_QUERY_DIRECTORY, qb, 32 + pl, true, qresp, 64 + OUTBUF + 128, &qst);
        first = false;
        if (qn < 64 || qst == ST_NOMORE) break;
        if (qst != ST_SUCCESS) break;
        uint16_t off = get16(qresp + 64, 2);
        uint32_t blen = get32(qresp + 64, 4);
        const uint8_t *e = qresp + off;
        uint32_t pos = 0;
        while (pos + 94 <= blen) {
            const uint8_t *rec = e + pos;
            uint32_t next = get32(rec, 0);
            uint64_t size = get64(rec, 40);
            uint32_t attr = get32(rec, 56);
            uint32_t nlen = get32(rec, 60);
            String nm;
            for (uint32_t i = 0; i + 1 < nlen && 94 + i + 1 < (blen - pos); i += 2) nm += (char)rec[94 + i];
            if (nm != "." && nm != "..") {
                DirEntry de; de.name = nm; de.isDir = (attr & 0x10) != 0; de.size = size;
                out.push_back(de);
            }
            if (next == 0) break;
            pos += next;
        }
    }
    free(qresp);

    uint8_t cb[24]; memset(cb, 0, 24); put16(cb, 0, 24); memcpy(cb + 8, fileId, 16);
    uint8_t tmp[128]; uint32_t cst;
    p->transact(C_CLOSE, cb, 24, true, tmp, sizeof(tmp), &cst);
    return true;
}

namespace {
    // ---- NDR (DCE/RPC transfer syntax) writer/reader --------------------
    // Little-endian, every primitive aligned to its own size relative to
    // the start of the stub - the reader aligns before each read, so
    // padding after strings/arrays is handled implicitly.
    struct NdrW {
        std::vector<uint8_t> b;
        void align(size_t n) { while (b.size() % n) b.push_back(0); }
        void u16(uint16_t v) { align(2); b.push_back(v & 0xFF); b.push_back(v >> 8); }
        void u32(uint32_t v) { align(4); for (int i = 0; i < 4; ++i) b.push_back((uint8_t)(v >> (8 * i))); }
        void raw(const uint8_t *d, size_t n) { b.insert(b.end(), d, d + n); }
        // RPC_UNICODE_STRING passed inline (Length, MaximumLength, Buffer
        // referent) whose deferred conformant-varying WCHAR array is
        // appended right after it - correct when it is the stub's last
        // pointer-bearing parameter, which is how it is used here.
        void unicodeString(const String &s) {
            uint16_t bytes = (uint16_t)(s.length() * 2);
            u16(bytes); u16(bytes); u32(0x00020000);
            u32(s.length()); u32(0); u32(s.length());
            for (size_t i = 0; i < s.length(); ++i) { b.push_back((uint8_t)s[i]); b.push_back(0); }
        }
    };

    struct NdrR {
        const uint8_t *d; size_t n; size_t o = 0; bool ok = true;
        NdrR(const std::vector<uint8_t> &v) : d(v.data()), n(v.size()) {}
        void align(size_t a) { o = (o + a - 1) & ~(a - 1); }
        uint8_t u8() { if (o + 1 > n) { ok = false; return 0; } return d[o++]; }
        uint16_t u16() { align(2); if (o + 2 > n) { ok = false; return 0; } uint16_t v = d[o] | (d[o + 1] << 8); o += 2; return v; }
        uint32_t u32() { align(4); if (o + 4 > n) { ok = false; return 0; } uint32_t v = get32(d, o); o += 4; return v; }
        const uint8_t *raw(size_t len) { if (o + len > n) { ok = false; return nullptr; } const uint8_t *p = d + o; o += len; return p; }
        // Conformant-varying WCHAR array: max_count, offset, actual_count,
        // then actual_count UTF-16LE units, returned as UTF-8 (so accented
        // names/remarks print correctly) with any trailing NUL dropped.
        String wstr() {
            String s;
            u32(); u32();
            uint32_t actual = u32();
            for (uint32_t i = 0; i < actual; ++i) {
                if (o + 2 > n) { ok = false; break; }
                uint32_t cp = d[o] | (d[o + 1] << 8);
                o += 2;
                if (cp >= 0xD800 && cp < 0xDC00 && i + 1 < actual && o + 2 <= n) {   // surrogate pair
                    uint32_t lo = d[o] | (d[o + 1] << 8);
                    if (lo >= 0xDC00 && lo < 0xE000) { cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00); o += 2; ++i; }
                }
                if (cp) appendUtf8(s, cp);
            }
            return s;
        }
    };

    String ntStatusText(uint32_t st) {
        switch (st) {
            case 0xC0000022: return "access denied";
            case 0xC000006D: return "logon failure";
            case 0xC00000BB: return "not supported";
            case 0xC0000034: return "object name not found";
            default: return "status 0x" + String(st, 16);
        }
    }

    // SAMPR_ENUMERATION_BUFFER behind a unique pointer: used by both
    // SamrEnumerateDomainsInSamServer and SamrEnumerateUsersInDomain.
    bool readRidEnumeration(NdrR &r, std::vector<std::pair<uint32_t, String>> &out) {
        if (!r.u32()) return r.ok;                 // Buffer pointer NULL
        uint32_t entries = r.u32();
        uint32_t arrRef = r.u32();
        if (!arrRef || entries == 0) return r.ok;
        if (entries > 4096) return false;
        r.u32();                                   // conformant max_count
        struct E { uint32_t rid; uint32_t ref; };
        std::vector<E> es;
        for (uint32_t i = 0; i < entries && r.ok; ++i) {
            E e; e.rid = r.u32(); r.u16(); r.u16(); e.ref = r.u32();   // RID + RPC_UNICODE_STRING
            es.push_back(e);
        }
        for (auto &e : es) out.push_back({e.rid, e.ref ? r.wstr() : String()});
        return r.ok;
    }

    const uint8_t UUID_SRVSVC[16] = {0xC8,0x4F,0x32,0x4B,0x70,0x16,0xD3,0x01,0x12,0x78,0x5A,0x47,0xBF,0x6E,0xE1,0x88};
    const uint8_t UUID_SAMR[16]   = {0x78,0x57,0x34,0x12,0x34,0x12,0xCD,0xAB,0xEF,0x00,0x01,0x23,0x45,0x67,0x89,0xAC};
    const uint8_t UUID_NDR[16]    = {0x04,0x5D,0x88,0x8A,0xEB,0x1C,0xC9,0x11,0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60};
}

// ---- named pipe + DCE/RPC plumbing ---------------------------------------

bool Session::openPipe(const char *name, uint8_t fid[16], String &err) {
    uint8_t body[128]; uint32_t st;
    int bl = buildCreate(body, name, 0x0012019F, 1 /*OPEN*/, 0);
    uint8_t cresp[512];
    int n = p->transact(C_CREATE, body, bl, true, cresp, sizeof(cresp), &st);
    if (n < 64 || st != ST_SUCCESS) { err = String("open \\") + name + " failed (" + ntStatusText(st) + ")"; return false; }
    memcpy(fid, cresp + 64 + 64, 16);
    return true;
}

void Session::closeHandle(const uint8_t fid[16]) {
    uint8_t cb[24]; memset(cb, 0, 24); put16(cb, 0, 24); memcpy(cb + 8, fid, 16);
    uint8_t t[128]; uint32_t cs;
    p->transact(C_CLOSE, cb, 24, true, t, sizeof(t), &cs);
}

bool Session::pipeWrite(const uint8_t fid[16], const uint8_t *data, size_t len) {
    // Fixed part is 48 bytes (StructureSize 49 counts 1 byte of buffer).
    uint8_t *w = (uint8_t *)malloc(48 + len);
    if (!w) return false;
    memset(w, 0, 48);
    put16(w, 0, 49); put16(w, 2, 64 + 48); put32(w, 4, len);
    memcpy(w + 16, fid, 16);
    memcpy(w + 48, data, len);
    uint8_t r[128]; uint32_t ws;
    int rn = p->transact(C_WRITE, w, 48 + len, true, r, sizeof(r), &ws);
    free(w);
    return rn >= 64 && ws == ST_SUCCESS;
}

// Reads one whole pipe message (one DCE/RPC fragment). BUFFER_OVERFLOW
// means the message continues, so keep reading and appending.
bool Session::pipeRead(const uint8_t fid[16], std::vector<uint8_t> &out) {
    out.clear();
    const uint32_t WANT = 8192;
    uint8_t *resp = (uint8_t *)malloc(64 + WANT + 128);
    if (!resp) return false;
    bool ok = false;
    for (int guard = 0; guard < 16; ++guard) {
        uint8_t rb[49]; memset(rb, 0, 49);
        put16(rb, 0, 49); put32(rb, 4, WANT); memcpy(rb + 16, fid, 16);
        uint32_t rs;
        int rn = p->transact(C_READ, rb, 49, true, resp, 64 + WANT + 128, &rs);
        if (rn < 64 || (rs != ST_SUCCESS && rs != 0x80000005)) break;
        uint16_t doff = resp[64 + 2];
        uint32_t dlen = get32(resp + 64, 4);
        if (doff + dlen > (uint32_t)rn) dlen = rn > doff ? rn - doff : 0;
        out.insert(out.end(), resp + doff, resp + doff + dlen);
        if (rs == ST_SUCCESS) { ok = true; break; }
    }
    free(resp);
    return ok;
}

bool Session::rpcBind(const uint8_t fid[16], const uint8_t uuid[16], uint16_t verMajor, uint16_t verMinor, String &err) {
    NdrW w;
    const uint8_t hdr[] = {0x05, 0x00, 0x0B, 0x03, 0x10, 0x00, 0x00, 0x00};   // v5.0, bind, first+last, LE
    w.raw(hdr, sizeof(hdr));
    w.u16(72); w.u16(0); w.u32(p->callId++);           // frag_length, auth_length, call_id
    w.u16(4280); w.u16(4280); w.u32(0);                 // max_xmit, max_recv, assoc_group
    w.b.push_back(1); w.b.push_back(0); w.u16(0);       // one context
    w.u16(0); w.b.push_back(1); w.b.push_back(0);       // context id 0, one transfer syntax
    w.raw(uuid, 16); w.u16(verMajor); w.u16(verMinor);
    w.raw(UUID_NDR, 16); w.u16(2); w.u16(0);
    std::vector<uint8_t> ack;
    if (!pipeWrite(fid, w.b.data(), w.b.size()) || !pipeRead(fid, ack) || ack.size() < 24 || ack[2] != 0x0C) {
        err = "RPC bind failed";
        return false;
    }
    return true;
}

bool Session::rpcCall(const uint8_t fid[16], uint16_t opnum, const std::vector<uint8_t> &stub,
                      std::vector<uint8_t> &reply, String &err) {
    NdrW w;
    const uint8_t hdr[] = {0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00};   // request, first+last
    w.raw(hdr, sizeof(hdr));
    w.u16(24 + stub.size()); w.u16(0); w.u32(p->callId++);
    w.u32(stub.size()); w.u16(0); w.u16(opnum);         // alloc_hint, context id, opnum
    w.raw(stub.data(), stub.size());
    if (!pipeWrite(fid, w.b.data(), w.b.size())) { err = "RPC send failed"; return false; }

    reply.clear();
    std::vector<uint8_t> pdu;
    for (int frag = 0; frag < 64; ++frag) {
        if (!pipeRead(fid, pdu) || pdu.size() < 24) { err = "RPC read failed"; return false; }
        uint8_t ptype = pdu[2], flags = pdu[3];
        if (ptype == 3) {
            uint32_t fs = get32(pdu.data(), 24);
            err = (fs == 5) ? String("access denied (RPC fault 5)") : "RPC fault 0x" + String(fs, 16);
            return false;
        }
        if (ptype != 2) { err = "unexpected RPC reply"; return false; }
        size_t fragLen = get16(pdu.data(), 8), authLen = get16(pdu.data(), 10);
        size_t end = fragLen - (authLen ? authLen + 8 : 0);
        if (end > pdu.size()) end = pdu.size();
        if (end > 24) reply.insert(reply.end(), pdu.begin() + 24, pdu.begin() + end);
        if (flags & 0x02) return true;                   // last fragment
    }
    err = "RPC reply too long";
    return false;
}

// ---- SRVSVC: share enumeration --------------------------------------------

bool Session::listShares(std::vector<ShareInfo> &out, String &err) {
    if (!p) { err = "not connected"; return false; }
    if (!treeConnect("IPC$", err)) return false;
    uint8_t fid[16];
    if (!openPipe("srvsvc", fid, err)) return false;
    if (!rpcBind(fid, UUID_SRVSVC, 3, 0, err)) { closeHandle(fid); return false; }

    // NetrShareEnum (opnum 15): NULL server name, level 1, empty container,
    // PreferedMaximumLength 0xFFFFFFFF, NULL resume handle.
    NdrW w;
    w.u32(0); w.u32(1); w.u32(1); w.u32(0x00020000); w.u32(0); w.u32(0); w.u32(0xFFFFFFFF); w.u32(0);
    std::vector<uint8_t> reply;
    bool ok = rpcCall(fid, 15, w.b, reply, err);
    closeHandle(fid);
    if (!ok) return false;

    NdrR r(reply);
    r.u32(); r.u32();                       // level, union discriminant
    uint32_t cref = r.u32();
    uint32_t entries = r.u32();
    uint32_t bufref = r.u32();
    if (!r.ok) { err = "short NetrShareEnum reply"; return false; }
    if (!cref || !bufref || entries == 0) return true;
    if (entries > 512) entries = 512;
    r.u32();                                // conformant max_count
    struct Row { uint32_t nameRef, type, remarkRef; };
    std::vector<Row> rows;
    for (uint32_t i = 0; i < entries && r.ok; ++i) {
        Row row; row.nameRef = r.u32(); row.type = r.u32(); row.remarkRef = r.u32();
        rows.push_back(row);
    }
    for (auto &row : rows) {                // deferred strings: netname, remark
        ShareInfo si;
        if (row.nameRef) si.name = r.wstr();
        si.type = row.type;
        if (row.remarkRef) si.remark = r.wstr();
        out.push_back(si);
    }
    return true;
}

// ---- SAMR: users + password/lockout policy --------------------------------

bool Session::samrQuery(bool wantUsers, std::vector<SamrUser> &users,
                        bool wantPolicy, PassPolicy &policy,
                        String &domain, String &err) {
    if (!p) { err = "not connected"; return false; }
    if (!treeConnect("IPC$", err)) return false;
    uint8_t fid[16];
    if (!openPipe("samr", fid, err)) return false;
    if (!rpcBind(fid, UUID_SAMR, 1, 0, err)) { closeHandle(fid); return false; }

    const uint32_t MAXIMUM_ALLOWED = 0x02000000;
    std::vector<uint8_t> reply;
    uint8_t serverH[20], domainH[20];
    bool haveServer = false, haveDomain = false, ok = false;

    auto closeSamr = [&](const uint8_t h[20]) {
        NdrW c; c.raw(h, 20);
        std::vector<uint8_t> rr; String e;
        rpcCall(fid, 1 /*SamrCloseHandle*/, c.b, rr, e);
    };

    do {
        // SamrConnect2 (57): NULL server name.
        { NdrW w; w.u32(0); w.u32(MAXIMUM_ALLOWED);
          if (!rpcCall(fid, 57, w.b, reply, err)) break;
          if (reply.size() < 24) { err = "short SamrConnect2 reply"; break; }
          uint32_t st = get32(reply.data(), 20);
          if (st) { err = "SamrConnect2: " + ntStatusText(st); break; }
          memcpy(serverH, reply.data(), 20); haveServer = true; }

        // SamrEnumerateDomainsInSamServer (6): the account domain + Builtin.
        { NdrW w; w.raw(serverH, 20); w.u32(0); w.u32(0x1000);
          if (!rpcCall(fid, 6, w.b, reply, err)) break;
          NdrR r(reply);
          r.u32();                                         // enumeration context
          std::vector<std::pair<uint32_t, String>> doms;
          readRidEnumeration(r, doms);
          r.u32();                                         // count returned
          uint32_t st = r.u32();
          if (!r.ok || st) { err = "SamrEnumerateDomains: " + (r.ok ? ntStatusText(st) : String("bad reply")); break; }
          for (auto &dm : doms) if (!dm.second.equalsIgnoreCase("Builtin")) { domain = dm.second; break; }
          if (!domain.length()) { err = "no account domain found"; break; } }

        // SamrLookupDomainInSamServer (5): domain name -> SID.
        std::vector<uint8_t> sid; uint8_t subCount = 0;
        { NdrW w; w.raw(serverH, 20); w.unicodeString(domain);
          if (!rpcCall(fid, 5, w.b, reply, err)) break;
          NdrR r(reply);
          if (!r.u32()) { err = "SamrLookupDomain: no SID"; break; }
          r.u32();                                         // conformant max_count
          size_t start = r.o;
          r.u8(); subCount = r.u8(); r.raw(6);             // revision, count, authority
          r.raw(4 * subCount);
          uint32_t st = r.u32();
          if (!r.ok || st) { err = "SamrLookupDomain: " + (r.ok ? ntStatusText(st) : String("bad reply")); break; }
          sid.assign(reply.begin() + start, reply.begin() + start + 8 + 4 * subCount); }

        // SamrOpenDomain (7).
        { NdrW w; w.raw(serverH, 20); w.u32(MAXIMUM_ALLOWED); w.u32(subCount); w.raw(sid.data(), sid.size());
          if (!rpcCall(fid, 7, w.b, reply, err)) break;
          if (reply.size() < 24) { err = "short SamrOpenDomain reply"; break; }
          uint32_t st = get32(reply.data(), 20);
          if (st) { err = "SamrOpenDomain: " + ntStatusText(st); break; }
          memcpy(domainH, reply.data(), 20); haveDomain = true; }

        // SamrEnumerateUsersInDomain (13), normal accounts, paged.
        if (wantUsers) {
            uint32_t ctx = 0, st = 0;
            bool failed = false;
            do {
                NdrW w; w.raw(domainH, 20); w.u32(ctx); w.u32(0x10 /*USER_NORMAL_ACCOUNT*/); w.u32(0x1000);
                if (!rpcCall(fid, 13, w.b, reply, err)) { failed = true; break; }
                NdrR r(reply);
                ctx = r.u32();
                std::vector<std::pair<uint32_t, String>> page;
                readRidEnumeration(r, page);
                r.u32();                                   // count returned
                st = r.u32();
                if (!r.ok) { err = "SamrEnumerateUsers: bad reply"; failed = true; break; }
                for (auto &u : page) users.push_back({u.second, u.first});
            } while (st == 0x00000105 /*STATUS_MORE_ENTRIES*/ && users.size() < 5000);
            if (failed) break;
            if (st && st != 0x00000105) { err = "SamrEnumerateUsers: " + ntStatusText(st); break; }
        }

        // SamrQueryInformationDomain (8). Reply stub: buffer referent (u32),
        // union tag (u16), pad to 8, the 24-byte arm, NTSTATUS. The arm is
        // read at offset 8 when the tag matches the class asked for, else
        // located from the end of the stub as a fallback.
        auto armOf = [&](uint16_t cls) -> const uint8_t * {
            if (reply.size() < 36 || get32(reply.data(), reply.size() - 4) != 0) return nullptr;
            if (get16(reply.data(), 4) == cls) return reply.data() + 8;
            return reply.data() + reply.size() - 4 - 24;
        };
        if (wantPolicy) {
            NdrW w; w.raw(domainH, 20); w.u16(1 /*DomainPasswordInformation*/);
            const uint8_t *a = nullptr;
            if (rpcCall(fid, 8, w.b, reply, err) && (a = armOf(1)) != nullptr) {
                policy.minLength = get16(a, 0);
                policy.historyLength = get16(a, 2);
                policy.properties = get32(a, 4);
                policy.maxAge = (int64_t)(((uint64_t)get32(a, 12) << 32) | get32(a, 8));
                policy.minAge = (int64_t)(((uint64_t)get32(a, 20) << 32) | get32(a, 16));
                policy.have = true;
            }
            NdrW w2; w2.raw(domainH, 20); w2.u16(12 /*DomainLockoutInformation*/);
            const uint8_t *la = nullptr;
            String lerr;
            if (rpcCall(fid, 8, w2.b, reply, lerr) && reply.size() >= 32 && get32(reply.data(), reply.size() - 4) == 0) {
                la = (reply.size() >= 36 && get16(reply.data(), 4) == 12) ? reply.data() + 8
                                                                         : reply.data() + reply.size() - 24;
                policy.lockoutDuration = (int64_t)get64(la, 0);
                policy.lockoutWindow = (int64_t)get64(la, 8);
                policy.lockoutThreshold = get16(la, 16);
                policy.haveLockout = true;
            }
            if (!policy.have && !policy.haveLockout) { if (!err.length()) err = "password policy not readable"; break; }
            err = "";
        }
        ok = true;
    } while (false);

    if (haveDomain) closeSamr(domainH);
    if (haveServer) closeSamr(serverH);
    closeHandle(fid);
    if (!ok && !haveServer && err.startsWith("access denied"))
        err += ": Windows 10/11 and member servers only let administrators call SAMR remotely - try a domain controller or an admin account";
    return ok;
}

bool Session::readFile(const String &path, std::vector<uint8_t> &out, size_t maxBytes, String &err) {
    if (!p) { err = "not connected"; return false; }
    String name = path; name.replace("/", "\\");
    while (name.startsWith("\\")) name.remove(0, 1);

    uint8_t body[600]; uint32_t st;
    int bl = buildCreate(body, name, 0x81 /*READ_DATA|READ_ATTR*/, 1 /*OPEN*/, 0x40 /*NON_DIRECTORY*/);
    uint8_t cresp[512];
    int n = p->transact(C_CREATE, body, bl, true, cresp, sizeof(cresp), &st);
    if (n < 64 || st != ST_SUCCESS) {
        err = (st == 0xC0000022) ? "access denied" :
              (st == 0xC000003A || st == 0xC0000034) ? "no such file" : "open failed (" + String(st,16) + ")";
        return false;
    }
    uint8_t fileId[16]; memcpy(fileId, cresp + 64 + 64, 16);
    uint64_t eof = get64(cresp + 64, 48);
    if (eof > maxBytes) eof = maxBytes;

    const int CHUNK = 8192;
    uint8_t *rresp = (uint8_t *)malloc(64 + CHUNK + 128);
    uint64_t offset = 0;
    bool okAll = true;
    while (offset < eof) {
        uint32_t want = (uint32_t)((eof - offset) < CHUNK ? (eof - offset) : CHUNK);
        uint8_t rb[49]; memset(rb, 0, 49);
        put16(rb, 0, 49); put32(rb, 4, want);
        for (int i=0;i<8;++i) rb[8+i] = (uint8_t)(offset >> (8*i));
        memcpy(rb + 16, fileId, 16); rb[48]=0;
        uint32_t rst;
        int rn = p->transact(C_READ, rb, 49, true, rresp, 64 + CHUNK + 128, &rst);
        if (rn < 64 || rst != ST_SUCCESS) { okAll = (rst == 0x80000005 /*BUFFER_OVERFLOW*/); break; }
        uint16_t doff = rresp[64 + 2];
        uint32_t dlen = get32(rresp + 64, 4);
        if (doff + dlen > (uint32_t)rn) break;
        for (uint32_t i = 0; i < dlen; ++i) out.push_back(rresp[doff + i]);
        offset += dlen;
        if (dlen == 0) break;
    }
    free(rresp);

    uint8_t cb[24]; memset(cb, 0, 24); put16(cb, 0, 24); memcpy(cb + 8, fileId, 16);
    uint8_t tmp[128]; uint32_t cst;
    p->transact(C_CLOSE, cb, 24, true, tmp, sizeof(tmp), &cst);
    (void)okAll;
    return true;
}

bool Session::writeFile(const String &path, const uint8_t *data, size_t len, String &err) {
    if (!p) { err = "not connected"; return false; }
    String name = path; name.replace("/", "\\");
    while (name.startsWith("\\")) name.remove(0, 1);

    uint8_t body[600]; uint32_t st;
    int bl = buildCreate(body, name, 0x2 /*WRITE_DATA*/, 5 /*OVERWRITE_IF*/, 0x40 /*NON_DIRECTORY*/);
    uint8_t cresp[512];
    int n = p->transact(C_CREATE, body, bl, true, cresp, sizeof(cresp), &st);
    if (n < 64 || st != ST_SUCCESS) {
        err = (st == 0xC0000022) ? "access denied" : "create failed (" + String(st,16) + ")";
        return false;
    }
    uint8_t fileId[16]; memcpy(fileId, cresp + 64 + 64, 16);

    const int CHUNK = 8192;
    uint8_t *wmsg = (uint8_t *)malloc(49 + CHUNK);
    uint8_t wresp[128];
    size_t offset = 0;
    bool ok = true;
    while (offset < len) {
        uint32_t chunk = (uint32_t)((len - offset) < CHUNK ? (len - offset) : CHUNK);
        memset(wmsg, 0, 49);
        put16(wmsg, 0, 49); put16(wmsg, 2, 64 + 49); put32(wmsg, 4, chunk);
        for (int i=0;i<8;++i) wmsg[8+i] = (uint8_t)((uint64_t)offset >> (8*i));
        memcpy(wmsg + 16, fileId, 16);
        memcpy(wmsg + 49, data + offset, chunk);
        uint32_t wst;
        int wn = p->transact(C_WRITE, wmsg, 49 + chunk, true, wresp, sizeof(wresp), &wst);
        if (wn < 64 || wst != ST_SUCCESS) { err = "write failed (" + String(wst,16) + ")"; ok = false; break; }
        offset += chunk;
    }
    free(wmsg);
    uint8_t cb[24]; memset(cb, 0, 24); put16(cb, 0, 24); memcpy(cb + 8, fileId, 16);
    uint32_t cst;
    p->transact(C_CLOSE, cb, 24, true, wresp, sizeof(wresp), &cst);
    return ok;
}

bool Session::deleteFile(const String &path, String &err) {
    if (!p) { err = "not connected"; return false; }
    String name = path; name.replace("/", "\\");
    while (name.startsWith("\\")) name.remove(0, 1);
    uint8_t body[600]; uint32_t st;
    // DELETE access + FILE_DELETE_ON_CLOSE -> CLOSE removes it.
    int bl = buildCreate(body, name, 0x10000, 1 /*OPEN*/, 0x40 | 0x1000);
    uint8_t cresp[512];
    int n = p->transact(C_CREATE, body, bl, true, cresp, sizeof(cresp), &st);
    if (n < 64 || st != ST_SUCCESS) {
        err = (st == 0xC0000022) ? "access denied" :
              (st == 0xC000003A || st == 0xC0000034) ? "no such file" : "delete failed (" + String(st,16) + ")";
        return false;
    }
    uint8_t fileId[16]; memcpy(fileId, cresp + 64 + 64, 16);
    uint8_t cb[24]; memset(cb, 0, 24); put16(cb, 0, 24); memcpy(cb + 8, fileId, 16);
    uint8_t tmp[128]; uint32_t cst;
    p->transact(C_CLOSE, cb, 24, true, tmp, sizeof(tmp), &cst);
    return true;
}

bool Session::makeDir(const String &path, String &err) {
    if (!p) { err = "not connected"; return false; }
    String name = path; name.replace("/", "\\");
    while (name.startsWith("\\")) name.remove(0, 1);
    uint8_t body[600]; uint32_t st;
    int bl = buildCreate(body, name, 0x80 /*READ_ATTR*/, 2 /*CREATE*/, 0x01 /*DIRECTORY*/);
    uint8_t cresp[512];
    int n = p->transact(C_CREATE, body, bl, true, cresp, sizeof(cresp), &st);
    if (n < 64 || st != ST_SUCCESS) {
        err = (st == 0xC0000035) ? "already exists" :
              (st == 0xC0000022) ? "access denied" : "mkdir failed (" + String(st,16) + ")";
        return false;
    }
    uint8_t fileId[16]; memcpy(fileId, cresp + 64 + 64, 16);
    uint8_t cb[24]; memset(cb, 0, 24); put16(cb, 0, 24); memcpy(cb + 8, fileId, 16);
    uint8_t tmp[128]; uint32_t cst;
    p->transact(C_CLOSE, cb, 24, true, tmp, sizeof(tmp), &cst);
    return true;
}

bool Session::removeDir(const String &path, String &err) {
    if (!p) { err = "not connected"; return false; }
    String name = path; name.replace("/", "\\");
    while (name.startsWith("\\")) name.remove(0, 1);
    uint8_t body[600]; uint32_t st;
    int bl = buildCreate(body, name, 0x10000 /*DELETE*/, 1 /*OPEN*/, 0x01 | 0x1000);
    uint8_t cresp[512];
    int n = p->transact(C_CREATE, body, bl, true, cresp, sizeof(cresp), &st);
    if (n < 64 || st != ST_SUCCESS) {
        err = (st == 0xC0000022) ? "access denied" :
              (st == 0xC000003A || st == 0xC0000034) ? "no such directory" :
              (st == 0xC0000101) ? "directory not empty" : "rmdir failed (" + String(st,16) + ")";
        return false;
    }
    uint8_t fileId[16]; memcpy(fileId, cresp + 64 + 64, 16);
    uint8_t cb[24]; memset(cb, 0, 24); put16(cb, 0, 24); memcpy(cb + 8, fileId, 16);
    uint8_t tmp[128]; uint32_t cst;
    p->transact(C_CLOSE, cb, 24, true, tmp, sizeof(tmp), &cst);
    return true;
}

} // namespace SmbClient
