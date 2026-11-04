#pragma once
#include <Arduino.h>
#include <IPAddress.h>

// AS-REP Roasting: for each candidate username, sends an AS-REQ with no
// PA-DATA (same as Kerbrute). Accounts flagged "Do not require Kerberos
// preauthentication" (UF_DONT_REQUIRE_PREAUTH) answer directly with a valid
// AS-REP instead of a KDC_ERR_PREAUTH_REQUIRED error. The AS-REP's
// enc-part is encrypted with the account's own long-term key, so it's
// crackable offline — zero credentials and zero crypto needed on our side,
// we only capture the raw ciphertext.
//
// Scope: only RC4-HMAC (etype 23) tickets are formatted into a crackable
// line (hashcat -m 18200, classic `$krb5asrep$23$...` format). An account
// returning an AES-encrypted AS-REP (etype 17/18) is reported as found but
// without a hash line (that format isn't implemented here).
namespace AsRepRoast {
    bool start(const IPAddress &kdc, const String &realm, const String &wordlistPath, uint16_t port = 88);
    void stop();

    // JSON: {running, done, total, kdc, realm, error,
    //        found:[{user, etype, hash}]}   hash is "" when etype != 23
    String status();
}
