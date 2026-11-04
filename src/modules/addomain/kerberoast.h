#pragma once
#include <Arduino.h>
#include <IPAddress.h>

// Kerberoasting: authenticates with real domain credentials, then requests
// a TGS (service ticket) for every SPN in a wordlist. Service tickets are
// encrypted with the *target service account's* key, so if that account's
// password is weak it's crackable offline from the captured ticket —
// without ever touching the service itself.
//
// EXPERIMENTAL / unverified against a real Active Directory lab: this
// implements RFC 4757 RC4-HMAC (etype 23) Kerberos preauth, AS-REP
// decryption and Authenticator encryption by hand (MD4 key derivation +
// HMAC-MD5 + RC4), since no Kerberos crypto library exists for Arduino.
// Only etype 23 is supported; if the KDC/service is AES-only (etype
// 17/18), this module cannot produce a usable hash. The device's clock
// must be roughly correct (NTP) for the AS-REQ preauth to be accepted —
// start() attempts a best-effort NTP sync and fails fast with a clear
// error if the clock still looks unset.
//
// Requires MD4 + ARC4 support in the ESP32 Arduino core's bundled mbedtls
// (MBEDTLS_MD4_C / MBEDTLS_ARC4_C). If either is missing from this build,
// start() always fails with an explanatory error instead of breaking the
// build.
namespace Kerberoast {
    bool start(const IPAddress &kdc, const String &realm, const String &username,
               const String &password, const String &spnWordlistPath, uint16_t port = 88);
    void stop();

    // JSON: {running, done, total, kdc, realm, user, error,
    //        found:[{spn, etype, hash}]}   hash is "" when etype != 23
    String status();
}
