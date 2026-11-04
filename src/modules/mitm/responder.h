#pragma once
#include <Arduino.h>

// Responder-style LLMNR / NBT-NS poisoner with an integrated HTTP and SMB
// NTLMv2 / Basic credential trap.
//
// WARNING: Use only on networks you are explicitly authorized to test.
//
// How it works:
//  1. Listens for LLMNR (UDP 5355, multicast 224.0.0.252) and NBT-NS
//     (UDP 137) name queries on the local segment and answers every one of
//     them with this device's own IP — this is exactly what Responder does:
//     LLMNR/NBT-NS are DNS fallbacks, so poisoning them hijacks any lookup
//     that normal DNS did not resolve (mistyped shares, WPAD, etc).
//  2. A minimal raw-socket HTTP server on TCP 80 challenges any request
//     with WWW-Authenticate: NTLM and parses the response (Type 3 message)
//     into a crackable line. A plain HTTP Basic prompt is also captured
//     opportunistically for clients that fall back to it. There is no
//     routing — every request gets the same treatment, by design.
//  3. In parallel, a minimal SMB2 server on TCP 445 runs the same NTLM
//     challenge/response trap over the far more common SMB auth path
//     (Windows constantly probes SMB shares/printers on its own). The
//     login is always failed on purpose once the hash is captured, so the
//     client cleanly gives up instead of expecting a working session.
//
// Scope / honesty notes:
//  - Only NTLMv2-style capture is attempted (Type2 challenge advertises
//    NTLMSSP_NEGOTIATE_TARGET_INFO so compliant clients compute NTLMv2).
//    A client that still answers with a 24-byte NTLMv1 response is reported
//    as such (the hash blob is kept for the record, but it isn't a valid
//    netntlmv2 line since it has no client blob).
//  - The SMB server only ever reaches NTLM authentication (NEGOTIATE +
//    SESSION_SETUP); it never advertises a share or answers anything past
//    that, by design.
//  - The server correlates Type3 responses to the server challenge it
//    last issued; this assumes a single capture flow in flight at a time,
//    which is adequate for a single-target pentest session.
//  - Captured hashes are also appended, one ready-to-crack line per
//    capture, to /responder_hashes.txt on the SD card when one is present.
namespace Responder {
    bool start();
    void stop();
    bool isRunning();

    // JSON: {running, queriesAnswered, captures:[{time,type,user,domain,
    //         client,hash}]}
    String status();

    void clearCaptures();
}
