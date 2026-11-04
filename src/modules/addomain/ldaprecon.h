#pragma once
#include <Arduino.h>
#include <IPAddress.h>

// LDAP recon against a domain controller (TCP/389). Anonymous by default
// (reads the RootDSE, which AD publishes without auth); with credentials it
// does an authenticated simple bind and can enumerate domain users and the
// password policy via LDAP searches. Mirrors `nxc ldap` style enumeration.
namespace LdapRecon {
    struct Options {
        bool authenticated = false;
        String bindName;      // UPN (user@domain), DOMAIN\user, or a full DN
        String password;
        bool enumUsers = false;
        bool passPolicy = false;
    };

    bool start(const IPAddress &target, const Options &opt);
    void stop();

    // Cheap accessors for progress polling and for printing the user list
    // without building a (large) JSON document.
    bool running();
    size_t userCount();
    String userAt(size_t i);
    bool usersTruncated();

    // JSON: {running, done, target, error, bindType, bindOk,
    //        defaultNamingContext, dnsHostName,
    //        users:[...] (only if includeUsers), userCount, usersTruncated,
    //        passwordPolicy:{...}}  (last two only when requested)
    String status(bool includeUsers = true);
}
