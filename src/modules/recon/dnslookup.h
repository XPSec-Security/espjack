#pragma once
#include <Arduino.h>

// Minimal DNS resolver (nslookup-style). Sends a single query to a resolver
// over UDP/53 and formats the answer records. Supports the common record
// types by name; unknown types are printed as hex rdata.
namespace DnsLookup {
    // Runs one synchronous query. 'name' is the host to look up (or, for a
    // PTR query, either an IP like 1.2.3.4 or an already-formed
    // 4.3.2.1.in-addr.arpa). 'type' is a record type name (A, AAAA, CNAME,
    // MX, NS, TXT, PTR, SOA, SRV, CAA, ANY) in any case. 'server' is the
    // resolver to ask; pass IPAddress(0,0,0,0) to use the DHCP-assigned one.
    // Returns JSON:
    //   {ok, error, query, type, server, answers:[{name,type,ttl,data}]}
    String query(const String &name, const String &type, const IPAddress &server);
}
