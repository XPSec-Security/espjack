# kerbrute

Category: active directory

Summary: Kerberos AS-REQ username enumeration

Usage:

```
kerbrute <kdc> <realm> [wordlist]
```

Manual:

```
DESCRIPTION
    Username enumeration against a domain controller. For each name in
    the wordlist it sends an AS-REQ without pre-authentication and
    classifies the reply. No passwords are sent, so it can't lock
    accounts.

    STATUS valid            the account exists
           valid_nopreauth  exists AND has pre-auth disabled - it is
                            AS-REP roastable, run asreproast next
           valid_disabled   exists but is disabled or locked out

    The realm is upper-cased automatically. If the KDC rejects it (a
    mistyped domain) the run ends with an 'Error:' line instead of an
    empty result. The wordlist is streamed from the SD card, so large
    lists are fine.

OPTIONS
    <kdc>       IP of a domain controller (Kerberos, TCP/88).
    <realm>     The AD DNS domain in upper case, e.g. CORP.LOCAL
                (ldaprecon/smbrecon show it).
    [wordlist]  One username per line on the SD card.
                Default /wordlists/users.txt.

EXAMPLE
    root@espjack# kerbrute 192.168.1.10 CORP.LOCAL
    Enumerating... (Ctrl+C to stop)
      [########################] 100% - 3 found

    USER                     STATUS
    administrator            valid
    jsmith                   valid
    svc_backup               valid_nopreauth
```
