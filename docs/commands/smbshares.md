# smbshares

Category: active directory

Summary: List the server's SMB shares (SRVSVC)

Usage:

```
smbshares <target>[/prefix] [-u user -p pass | -H nthash] [-d domain] [--local-auth] [-t ms]
```

Manual:

```
DESCRIPTION
    Lists the shares a server exports, via the SRVSVC NetrShareEnum RPC
    over \\<host>\IPC$\srvsvc. Needs an authenticated session (give
    credentials; a null session works only where the server allows it).
    Shows each share's name, type (disk/print/ipc, '$' = hidden) and
    remark - the map of what to browse with 'ls //host/share ...'.

    Takes one host or a CIDR block. Across a block it logs in to every
    address that has SMB open and prints one row per share, prefixed
    with the host, as each host finishes; a host that refuses the login
    gets a single '[-]' row. Addresses with no SMB are skipped. As with
    smbrecon, every wrong-password attempt counts toward the account's
    lockout on each host it reaches, so the sweep is paced with -t and
    you should check the policy first (smbrecon <dc> ... --pass-pol).

OPTIONS
    <target>[/prefix]  One SMB server, or a CIDR block to sweep (e.g.
                       192.168.1.0/24, max /20).
    -t <ms>            Sweep with credentials only: delay between hosts
                       that answer. Default 250.
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
    root@espjack# smbshares 192.168.1.10 -u jsmith -p P@ssw0rd -d CORP

    SHARE                    TYPE       REMARK
    ADMIN$                   disk$      Remote Admin
    C$                       disk$      Default share
    IPC$                     ipc$       Remote IPC
    Finance                  disk       Finance team files
    4 share(s).

    root@espjack# smbshares 192.168.1.0/24 -u jsmith -p P@ssw0rd -d CORP
    Scanning 256 hosts... (Ctrl+C to stop)
    [!] Each wrong-password attempt counts toward this account's domain lockout - check the policy first with smbrecon --pass-pol if unsure.
    IP               SHARE                    TYPE       REMARK
    192.168.1.10     ADMIN$                   disk$      Remote Admin
    192.168.1.10     C$                       disk$      Default share
    192.168.1.10     IPC$                     ipc$       Remote IPC
    192.168.1.10     Finance                  disk       Finance team files
    192.168.1.23     [-] SMB: auth failed (bad credentials)

    2 host(s) answered SMB, 1 listed their shares.
```
