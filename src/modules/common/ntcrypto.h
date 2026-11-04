#pragma once
// Small crypto/text helpers shared by the AD modules (SMB NTLM, Kerberos
// RC4-HMAC). This build's mbedTLS ships without MD4 and ARC4, so both are
// implemented here. They are not constant-time and not meant for anything
// but protocol compatibility.
#include <Arduino.h>

namespace NtCrypto {

    // UTF-8 -> UTF-16LE (BMP + surrogate pairs). Never produces more UTF-16
    // units than the input has bytes, so a buffer of 2*len bytes is always
    // enough. Returns the number of bytes written.
    inline int utf8ToUtf16le(const char *s, size_t len, uint8_t *out) {
        int n = 0;
        for (size_t i = 0; i < len;) {
            uint8_t c = (uint8_t)s[i];
            uint32_t cp; int extra;
            if (c < 0x80)       { cp = c;        extra = 0; }
            else if (c >= 0xF0) { cp = c & 0x07; extra = 3; }
            else if (c >= 0xE0) { cp = c & 0x0F; extra = 2; }
            else if (c >= 0xC0) { cp = c & 0x1F; extra = 1; }
            else                { cp = c;        extra = 0; }   // stray byte: pass through as Latin-1
            ++i;
            for (int k = 0; k < extra && i < len; ++k, ++i) cp = (cp << 6) | ((uint8_t)s[i] & 0x3F);
            if (cp >= 0x10000) {
                cp -= 0x10000;
                uint16_t hi = 0xD800 | (cp >> 10), lo = 0xDC00 | (cp & 0x3FF);
                out[n++] = hi & 0xFF; out[n++] = hi >> 8; out[n++] = lo & 0xFF; out[n++] = lo >> 8;
            } else {
                out[n++] = cp & 0xFF; out[n++] = (cp >> 8) & 0xFF;
            }
        }
        return n;
    }

    // ---------------- MD4 (RFC 1320) : NT hash = MD4(UTF16LE(password)) ----
    struct MD4 {
        uint32_t a, b, c, d, len;
        uint8_t buf[64];
        static uint32_t rol(uint32_t x, int s) { return (x << s) | (x >> (32 - s)); }
        void init() { a = 0x67452301; b = 0xefcdab89; c = 0x98badcfe; d = 0x10325476; len = 0; }
        void block(const uint8_t *m) {
            uint32_t x[16];
            for (int i = 0; i < 16; ++i)
                x[i] = m[i*4] | (m[i*4+1] << 8) | (m[i*4+2] << 16) | ((uint32_t)m[i*4+3] << 24);
            uint32_t A = a, B = b, C = c, D = d;
            auto ff = [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); };
            auto gg = [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (x & z) | (y & z); };
            auto hh = [](uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; };
            const int s1[] = {3,7,11,19}, s2[] = {3,5,9,13}, s3[] = {3,9,11,15};
            for (int i = 0; i < 16; ++i) {
                int k = i; int s = s1[i & 3];
                A = rol(A + ff(B,C,D) + x[k], s); uint32_t t=A; A=D; D=C; C=B; B=t;
            }
            const int ord2[] = {0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15};
            for (int i = 0; i < 16; ++i) {
                int k = ord2[i]; int s = s2[i & 3];
                A = rol(A + gg(B,C,D) + x[k] + 0x5a827999u, s); uint32_t t=A; A=D; D=C; C=B; B=t;
            }
            const int ord3[] = {0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15};
            for (int i = 0; i < 16; ++i) {
                int k = ord3[i]; int s = s3[i & 3];
                A = rol(A + hh(B,C,D) + x[k] + 0x6ed9eba1u, s); uint32_t t=A; A=D; D=C; C=B; B=t;
            }
            a += A; b += B; c += C; d += D;
        }
        void compute(const uint8_t *msg, uint32_t n, uint8_t out[16]) {
            init();
            uint32_t full = n / 64;
            for (uint32_t i = 0; i < full; ++i) block(msg + i * 64);
            uint8_t tail[128]; uint32_t rem = n % 64;
            memcpy(tail, msg + full * 64, rem);
            tail[rem] = 0x80;
            uint32_t padLen = (rem < 56) ? (56 - rem) : (120 - rem);
            memset(tail + rem + 1, 0, padLen - 1);
            uint64_t bits = (uint64_t)n * 8;
            for (int i = 0; i < 8; ++i) tail[rem + padLen + i] = (uint8_t)(bits >> (8 * i));
            uint32_t tn = rem + padLen + 8;
            for (uint32_t i = 0; i < tn; i += 64) block(tail + i);
            uint32_t v[4] = {a, b, c, d};
            for (int i = 0; i < 4; ++i) { out[i*4]=v[i]; out[i*4+1]=v[i]>>8; out[i*4+2]=v[i]>>16; out[i*4+3]=v[i]>>24; }
        }
    };

    // NT hash of a UTF-8 password (the RC4-HMAC Kerberos key is the same value).
    // Passwords are capped at 128 characters (256 UTF-16 bytes).
    inline void ntHash(const String &password, uint8_t out[16]) {
        uint8_t w[512];
        size_t len = password.length() > 256 ? 256 : password.length();
        int n = utf8ToUtf16le(password.c_str(), len, w);
        MD4 md; md.compute(w, n, out);
    }

    // RC4 (ARCFOUR). In-place safe (in == out is fine).
    inline void rc4(const uint8_t *key, size_t keyLen, const uint8_t *in, size_t len, uint8_t *out) {
        uint8_t S[256];
        for (int i = 0; i < 256; ++i) S[i] = (uint8_t)i;
        uint8_t j = 0;
        for (int i = 0; i < 256; ++i) {
            j = (uint8_t)(j + S[i] + key[i % keyLen]);
            uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
        }
        uint8_t i = 0; j = 0;
        for (size_t n = 0; n < len; ++n) {
            i = (uint8_t)(i + 1);
            j = (uint8_t)(j + S[i]);
            uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
            out[n] = in[n] ^ S[(uint8_t)(S[i] + S[j])];
        }
    }

} // namespace NtCrypto
