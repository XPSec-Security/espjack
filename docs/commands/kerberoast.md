# kerberoast

Category: active directory

Summary: Kerberoasting (needs valid creds; experimental)

Usage:

```
kerberoast <kdc> <realm> <user> <pass> [wordlist]
```

Manual:

```
DESCRIPTION
    Logs in as <user> and requests a service ticket for each SPN in the
    wordlist. Tickets are encrypted with the service account's password
    hash and can be cracked offline (hashcat -m 13100). Needs any valid
    domain account. This device can't list SPNs itself, so provide
    candidates in the wordlist. RC4 (etype 23) only: the account's TGT
    is requested with RC4 and so are the service tickets, so services
    whose accounts have RC4 disabled return no ticket. Needs the
    device clock to be within 5 minutes of the DC (it syncs over NTP
    first) and a TGT under about 3KB. A wrong password, an unknown
    user, a locked account or a clock problem is reported by name.

OPTIONS
    <kdc>       IP of a domain controller (Kerberos, TCP/88).
    <realm>     The AD DNS domain in upper case, e.g. CORP.LOCAL
                (ldaprecon/smbrecon show it).
    <user>      A valid domain username.
    <pass>      Its password.
    [wordlist]  One SPN per line on the SD card.
                Default /wordlists/spns.txt.

EXAMPLE
    root@espjack# kerberoast 192.168.1.10 CORP.LOCAL jsmith P@ssw0rd
    Requesting service tickets... (Ctrl+C to stop)
      [########################] 100%

    SPN                              ETYPE  HASH (hashcat -m 13100)
    MSSQLSvc/sql01.corp.local:1433   23     $krb5tgs$23$*jsmith$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$5d1e...$a07c...
```
