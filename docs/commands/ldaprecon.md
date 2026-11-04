# ldaprecon

Category: active directory

Summary: LDAP recon: anonymous RootDSE, or authed user/password-policy enum

Usage:

```
ldaprecon <target>[/prefix] [-u user -p pass -d domain] [--users] [--pass-pol]
```

Manual:

```
DESCRIPTION
    LDAP recon on TCP/389. With no credentials it does an anonymous
    bind and reads the RootDSE (default naming context + DNS host
    name) - enough to confirm a domain controller and learn the domain
    name for kerbrute/asreproast. With -u/-p it does an authenticated
    simple bind and can then enumerate domain users (--users) and the
    domain password policy (--pass-pol).

OPTIONS
    <target>[/prefix]  One host, or a CIDR block to sweep for DCs
                       (e.g. 192.168.1.0/24, max /20).
    -u <user>          Username (enables authenticated bind).
    -p <pass>          Password. LDAP needs a password; -H (pass-the-
                       hash) is not supported here.
    -d <domain>        Domain; combined with -u as user@domain (UPN).
    --users            Enumerate domain user accounts (sAMAccountName).
    --pass-pol         Read the domain password policy.

EXAMPLES
    root@espjack# ldaprecon 192.168.1.10
      bind:          ok (anonymous)
      namingContext: DC=corp,DC=local
      dnsHostName:   DC01.corp.local

    root@espjack# ldaprecon 192.168.1.10 -u jsmith -p P@ssw0rd -d corp.local --users --pass-pol
      bind:          ok (authenticated)
      namingContext: DC=corp,DC=local
      dnsHostName:   DC01.corp.local
      password policy:
        min length:      7
        complexity:      enabled
        history:         24
        lockout thresh:  5
        max age (days):  42.0
        min age (days):  1.0
        lockout (min):   30.0
      users (3):
        Administrator
        jsmith
        svc_backup

NOTES
    Active Directory returns at most 1000 entries for an unpaged search,
    so --users on a larger domain is cut at 1000 and marked truncated.
    A search the server refuses (anonymous, or no read access) now ends
    with a 'note:' line explaining why, instead of an empty list.
```
