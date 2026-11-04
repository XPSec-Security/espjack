# asreproast

Category: active directory

Summary: AS-REP roasting (no credentials needed)

Usage:

```
asreproast <kdc> <realm> [wordlist]
```

Manual:

```
DESCRIPTION
    For each username, requests a ticket without pre-authentication.
    Accounts with 'Do not require Kerberos preauthentication' set reply
    with an AS-REP that can be cracked offline. Prints hashcat-ready
    hashes (-m 18200). No credentials needed. The request asks for
    RC4 (etype 23), the format hashcat/john crack. If RC4 is disabled
    for an account, it is retried with AES just to report that the
    user is roastable; that entry has no crackable hash. The realm is
    upper-cased automatically; the wordlist is streamed from the SD.

OPTIONS
    <kdc>       IP of a domain controller (Kerberos, TCP/88).
    <realm>     The AD DNS domain in upper case, e.g. CORP.LOCAL
                (ldaprecon/smbrecon show it).
    [wordlist]  One username per line on the SD card.
                Default /wordlists/users.txt.

EXAMPLE
    root@espjack# asreproast 192.168.1.10 CORP.LOCAL
    Roasting... (Ctrl+C to stop)
      [########################] 100% - 1 found

    USER                     ETYPE  HASH (hashcat -m 18200)
    svc_backup               23     $krb5asrep$23$svc_backup@CORP.LOCAL:9f3c1a...$4be2d0...
```
