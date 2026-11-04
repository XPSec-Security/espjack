#pragma once
#include <Arduino.h>
#include <IPAddress.h>

// SNMP v1 sanity check: a GET for sysDescr.0 with a community string
// (default "public"). A reply means SNMP is open with that community - a
// classic quick win that often leaks device model/OS.
namespace Snmp {
    // Returns JSON {ok, error, sysDescr}. 'community' defaults to "public".
    // 'timeoutMs' is how long to wait for the reply; a sweep passes a short
    // one so silent addresses don't dominate the run time.
    String get(const IPAddress &target, const String &community, uint32_t timeoutMs = 2500);
}
