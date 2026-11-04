#pragma once
#include <Arduino.h>
#include <IPAddress.h>

// Zero-credential SMB recon, in the spirit of NetExec's default smb banner
// grab: connects, negotiates SMB2, and reads the OS/domain info that a
// Windows server discloses in its NTLM CHALLENGE message during session
// setup — before any credential is actually checked. It then attempts a
// null session (empty username/password) to see if anonymous access is
// permitted.
//
// Protocol scope: SMB2 only (dialects 2.0.2/2.1/3.0), raw NTLMSSP in the
// security buffer per the MS-SMB2 §3.3.5.4 interop fallback (no SPNEGO
// wrapping). This targets mainstream Windows SMB servers; exotic/older
// SMB1-only targets are not supported.
namespace SmbRecon {
    bool start(const IPAddress &target, uint16_t port = 445);
    void stop();

    // JSON: {running, done, target, error, dialect, signingRequired,
    //        nullSessionAllowed, netbiosDomain, netbiosComputer,
    //        dnsDomain, dnsComputer}
    String status();
}
