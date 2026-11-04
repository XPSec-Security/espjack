# snmp

Category: recon

Summary: SNMP v1 sysDescr check (default community public)

Usage:

```
snmp <target>[/prefix] [community]
```

Manual:

```
DESCRIPTION
    Sends an SNMP v1 GET for sysDescr.0 with a community string and
    prints the reply. A response means SNMP is reachable with that
    community (devices are very often left on 'public'), which usually
    leaks the exact model/OS/firmware - handy for targeting.

    Give it a CIDR block to sweep a whole subnet: every address is
    asked with a short reply window and only the ones that answer are
    listed, one row each (IP + sysDescr) - a quick way to find every
    SNMP device left on the default community.

OPTIONS
    <target>[/prefix]  One SNMP device (UDP/161), or a CIDR block to
                       sweep (e.g. 192.168.1.0/24, max /20).
    [community]        Community string. Default 'public'.

EXAMPLES
    root@espjack# snmp 192.168.1.1
    SNMP GET sysDescr @ 192.168.1.1 (community 'public')...
    OPEN (community 'public'):
      RouterOS RB750Gr3 6.48.6 (long-term)

    root@espjack# snmp 192.168.1.0/24
    SNMP sweep of 256 hosts (community 'public')... (Ctrl+C to stop)
    IP               SYSDESCR
    192.168.1.1      RouterOS RB750Gr3 6.48.6 (long-term)
    192.168.1.40     HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT

    2 host(s) answered SNMP with community 'public'.
```
