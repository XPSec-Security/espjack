# smbrecon

Category: active directory

Summary: SMB2 recon; anonymous banner, authed check/spray, SAMR users + password policy

Usage:

```
smbrecon <target>[/prefix] [-u user -p pass | -H nthash] [-d domain] [--local-auth] [--users] [--pass-pol] [-t ms]
```

Manual:

```
DESCRIPTION
    Two modes. With no credentials: connects to TCP/445, negotiates
    SMB2 and does an anonymous session setup to read what the server
    reveals before any login - NetBIOS/DNS domain and computer names,
    the dialect, whether signing is required, and whether a null
    session is accepted ('signingRequired no' marks an NTLM relay
    target). With -u/-H: validates the credentials (NTLMv2, or
    pass-the-hash) against every host in the target - a single host or
    a whole CIDR range - and reports whether they authenticate on each.
    Against a range this doubles as a CrackMapExec-style credential
    spray: paced with -t (default 250ms/host) since every wrong-
    password attempt counts toward that account's domain lockout on
    each host it hits - check the lockout threshold first if the
    credential might be wrong (smbrecon <dc> ... --pass-pol).

    Every successful login is also checked for admin rights on that
    host: it tries to open ADMIN$ (then C$), which only Administrators
    can. Only the tree-connect status is read; nothing is opened or
    written. A single host prints 'local admin: YES/no/unknown', and a
    range marks the host '(ADMIN)'. A local account that is not the
    built-in Administrator is UAC-filtered over the network (unless
    LocalAccountTokenFilterPolicy=1), so it can read 'no' even if it
    is in the Administrators group; domain admins and RID-500 are not
    affected.

    --users and --pass-pol add SAMR (MS-SAMR, the samr pipe on IPC$)
    enumeration to an authenticated run: the domain's normal user
    accounts with their RIDs, and the password + lockout policy
    (min length, complexity, history, max/min age, lockout threshold,
    window and duration). Point it at a domain controller for the AD
    domain; on a member server it reads the machine's local accounts.
    On one host it prints the full lists; across a range it appends a
    short summary per host (users=N minlen=N lockout=N).

OPTIONS
    <target>[/prefix]  One host, or a CIDR block to sweep (e.g.
                       192.168.1.0/24, max /20) - one line per host.
    -t <ms>            Authenticated mode only: delay between hosts.
                       Default 250. Raise it on a lockout-sensitive
                       domain.
    --users            Authenticated: enumerate domain user accounts
                       (name + RID) over SAMR.
    --pass-pol         Authenticated: read the password and lockout
                       policy over SAMR.
    -u <user>     Username for authenticated mode.
    -p <pass>     Password (used unless -H is given).
    -H <nthash>   Pass-the-hash: 32-hex-char NT hash (or LM:NT - the NT
                  half is used). Use instead of -p.
    -d <domain>   Logon domain (AD), NetBIOS name or FQDN. Do not put it in
                  -u (no DOMAIN\user form). Omit it and the domain the
                  server announces is used: a domain member or DC means a
                  domain login, a standalone box means a local login.
    --local-auth  Force the target's local SAM, e.g. a local admin on a
                  domain-joined host (domain = the target's computer name).

EXAMPLES
    root@espjack# smbrecon 192.168.1.10
      running                no
      done                   yes
      target                 192.168.1.10
      error                  -
      dialect                3.0
      signingRequired        yes
      nullSessionAllowed     no
      netbiosDomain          CORP
      netbiosComputer        DC01
      dnsDomain              corp.local
      dnsComputer            DC01.corp.local

    root@espjack# smbrecon 192.168.1.10 -u jsmith -p P@ssw0rd -d CORP
    Authenticating... (Ctrl+C to stop)
      target:        192.168.1.10
      dialect:       2.1
      signing req:   yes
      domain:        CORP
      computer:      DC01
      auth as:       CORP\jsmith
      authenticated: YES
      local admin:   no  (ADMIN$ access denied)

    root@espjack# smbrecon 192.168.1.10 -u jsmith -p P@ssw0rd
    Authenticating... (Ctrl+C to stop)
      target:        192.168.1.10
      dialect:       2.1
      signing req:   yes
      domain:        CORP
      computer:      DC01
      auth as:       CORP\jsmith  (domain announced by the server)
      authenticated: YES
      local admin:   no  (ADMIN$ access denied)

    root@espjack# smbrecon 192.168.1.10 -u jsmith -p P@ssw0rd -d CORP --users --pass-pol
    Authenticating... (Ctrl+C to stop)
      target:        192.168.1.10
      dialect:       2.1
      signing req:   yes
      domain:        CORP
      computer:      DC01
      auth as:       CORP\jsmith
      authenticated: YES
      local admin:   no  (ADMIN$ access denied)
    Querying SAMR over IPC$...
      account domain: CORP
      password policy (SAMR):
        min length:      7
        complexity:      required
        history:         24
        max age:         42.0 days
        min age:         1.0 days
        lockout thresh:  5 bad attempts
        lockout window:  30 min
        lockout length:  30 min
      users (4):
        500    Administrator
        501    Guest
        1104   jsmith
        1107   svc_backup

    root@espjack# smbrecon 192.168.1.0/24 -u jsmith -p P@ssw0rd -d CORP
    Scanning 254 hosts... (Ctrl+C to stop)
    [!] Each wrong-password attempt counts toward this account's domain lockout - check '<dc> --pass-pol' first if unsure.
    IP               COMPUTER           DOMAIN     SIGNING  AUTH
    192.168.1.10     DC01               CORP       yes      [+] AUTH (ADMIN)
    192.168.1.23     WS01               CORP       no       [+] AUTH

NOTES
    SAMR enumeration also works where LDAP is closed, and takes -H
    (pass-the-hash), which an LDAP simple bind can't. Domain users can
    usually run it against a domain controller. Windows 10/11 and
    member servers only let administrators call SAMR remotely, so
    there it fails with 'access denied (RPC fault 5)' even though
    the login itself worked. ldaprecon reads the same data over LDAP:
      ldaprecon <dc> -u <user> -p <pass> -d <domain> --users --pass-pol
```
