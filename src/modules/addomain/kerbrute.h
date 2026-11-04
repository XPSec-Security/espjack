#pragma once
#include <Arduino.h>
#include <IPAddress.h>

// Kerberos pre-authentication username enumeration (the "kerbrute"/NetExec
// --kerberos technique): sends an AS-REQ with no PA-DATA for each candidate
// username. The KDC's response classifies the account with zero
// credentials and without generating a Windows logon-failure event (unlike
// SMB/LDAP bind attempts):
//   - KRB-ERROR KDC_ERR_PREAUTH_REQUIRED (25) -> username exists
//   - KRB-ERROR KDC_ERR_C_PRINCIPAL_UNKNOWN (6) -> username does not exist
//   - AS-REP returned directly                 -> username exists AND
//     does not require pre-authentication (classic AS-REP "roastable"
//     account; this module only flags it, it does not request/parse the
//     encrypted part — that would need the raw AS-REP bytes saved offline).
//
// Reads candidate usernames, one per line, from a wordlist file on the SD
// card.
namespace Kerbrute {
    bool start(const IPAddress &kdc, const String &realm, const String &wordlistPath, uint16_t port = 88);
    void stop();

    // JSON: {running, done, total, kdc, realm, error,
    //        found:[{user,status}]}   status: "valid" | "valid_nopreauth"
    String status();
}
