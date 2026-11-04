#pragma once
#include <Arduino.h>
#include <IPAddress.h>

// TCP port scanner with multiple modes (nmap-style). Modes 0-2 are TCP
// connect scans; mode 3 is a SYN (half-open) scan over an lwIP raw socket.
namespace PortScan {
    enum Mode {
        MODE_CONNECT = 0,  // only checks open/closed
        MODE_BANNER  = 1,  // connect and grab banner
        MODE_VERSION = 2,  // connect, send probes and try to identify service/version
        MODE_SYN     = 3   // half-open: send a SYN, classify by the reply, never finish the
                           // handshake. Open/closed/filtered only (no banner or version).
    };

    // Start a scan.
    //   top=true    -> ignores start/end and scans the common-ports list.
    //   hostCount>1 -> scans every host in ['target', 'target' + hostCount)
    //                  instead of just 'target' (see cli.cpp's use of
    //                  parseIpRange() for the "<ip>[/prefix]" syntax).
    // Returns false if a scan is already running or parameters are invalid.
    bool start(const IPAddress &target, uint16_t startPort, uint16_t endPort,
               Mode mode, bool top, uint16_t timeoutMs = 400, uint32_t hostCount = 1);

    void stop();

    // Cheap polling for progress bars (no JSON): avoids rebuilding the whole
    // result list on every tick.
    bool running();
    void progress(uint32_t &done, uint32_t &total);

    // JSON: {running, target, mode, done, total, closed, filtered, error,
    //        results:[{ip,port,service,banner,version}]}
    // closed/filtered are only counted by the SYN mode (RST / no reply).
    String status();
}
