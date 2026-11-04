#pragma once
#include <Arduino.h>
#include <IPAddress.h>

// TCP port scanner with multiple modes (nmap-style, within what the
// Arduino/lwIP stack allows — always a TCP connect scan; no SYN/raw scan).
namespace PortScan {
    enum Mode {
        MODE_CONNECT = 0,  // only checks open/closed
        MODE_BANNER  = 1,  // connect and grab banner
        MODE_VERSION = 2   // connect, send probes and try to identify service/version
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

    // JSON: {running, target, mode, done, total,
    //        results:[{ip,port,service,banner,version}]}
    String status();
}
