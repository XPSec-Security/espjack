# nslookup

Category: recon

Summary: DNS lookup of any record type

Usage:

```
nslookup <name> [-type <A|AAAA|MX|TXT|NS|PTR|SOA|SRV|CAA|ANY>] [-server <ip>]
```

Manual:

```
DESCRIPTION
    Looks up DNS records of any type by querying a resolver directly
    over UDP/53, so you can ask for records 'ping' can't (MX, TXT, NS,
    SOA, SRV...). By default it asks the DHCP-assigned resolver; -server
    points it at any other one.

OPTIONS
    <name>        Host to look up. For -type PTR you may pass an IP
                  directly (it is turned into an in-addr.arpa query).
    -type <t>     Record type: A (default), AAAA, CNAME, MX, NS, TXT,
                  PTR, SOA, SRV, CAA or ANY.
    -server <ip>  Resolver to ask. Default: the network's own DNS.

EXAMPLES
    root@espjack# nslookup example.com
    Querying example.com for A record(s)...
    Server: 192.168.1.1

    NAME                         TYPE   TTL      DATA
    example.com                  A      3600     93.184.216.34

    root@espjack# nslookup corp.local -type MX
    Querying corp.local for MX record(s)...
    Server: 192.168.1.1

    NAME                         TYPE   TTL      DATA
    corp.local                   MX     3600     10 mail.corp.local

    root@espjack# nslookup 8.8.8.8 -type PTR -server 1.1.1.1
    Querying 8.8.8.8 for PTR record(s)...
    Server: 1.1.1.1

    NAME                         TYPE   TTL      DATA
    8.8.8.8.in-addr.arpa         PTR    3600     dns.google
```
