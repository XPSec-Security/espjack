#pragma once
#include <Arduino.h>
#include <IPAddress.h>
#include <vector>

// Minimal authenticated SMB2 client: NTLMv2 session setup (password or
// pass-the-hash), tree connect, and the file operations the CLI exposes
// over AD shares (list / read / write / delete / mkdir / rmdir). Message
// signing (HMAC-SHA256) is implemented so it works against servers that
// require it; only dialects 2.0.2 and 2.1 are offered, so signing stays on
// that one algorithm.
namespace SmbClient {

    struct Creds {
        String user;
        String domain;      // user's domain; empty = the domain the server announces;
                            // ignored when localAuth is set
        String password;    // used unless haveHash
        uint8_t ntHash[16]; // pass-the-hash input, used when haveHash
        bool haveHash = false;
        bool localAuth = false; // authenticate against the target's local SAM
    };

    struct DirEntry {
        String name;
        bool isDir = false;
        uint64_t size = 0;
    };

    struct ShareInfo {
        String name;
        uint32_t type = 0;   // 0=disk 1=print 2=device 3=IPC; 0x80000000 bit = hidden
        String remark;
    };

    struct SamrUser {
        String name;
        uint32_t rid = 0;
    };

    // Domain password + lockout policy as returned by SAMR. Ages/durations
    // are in 100ns units, negative (Windows convention); INT64_MIN means
    // "never" (no expiry / locked until an admin unlocks).
    struct PassPolicy {
        bool have = false;
        int minLength = -1;
        int historyLength = -1;
        uint32_t properties = 0;          // bit 0x1 = complexity required
        int64_t maxAge = 0, minAge = 0;
        bool haveLockout = false;
        int lockoutThreshold = -1;        // 0 = accounts never lock out
        int64_t lockoutDuration = 0, lockoutWindow = 0;
    };

    // One connected+authenticated session to \\host. Not thread-safe; use
    // from a single task. Call close() when done (the destructor also does).
    class Session {
    public:
        ~Session();

        // TCP connect + NEGOTIATE + NTLMv2 SESSION_SETUP. On false, err holds
        // the reason ("auth failed", a status code, etc).
        bool open(const IPAddress &host, const Creds &creds, String &err);

        // Connect a tree to \\host\<share>. Must precede file ops.
        bool treeConnect(const String &share, String &err);

        // Does the authenticated account have admin rights on the target?
        // Probes ADMIN$ then C$ (tree connect only). Returns 1 = yes,
        // 0 = access denied, -1 = could not tell (shares missing / error);
        // 'detail' says which share and why. Changes the active tree.
        int checkAdmin(String &detail);

        // Path is relative to the share root, '/' or '\\' separated.
        bool list(const String &path, std::vector<DirEntry> &out, String &err);

        // Enumerates the server's shares via SRVSVC NetrShareEnum (level 1)
        // over \\IPC$\srvsvc. Changes the active tree to IPC$.
        bool listShares(std::vector<ShareInfo> &out, String &err);

        // SAMR over \\IPC$\samr: picks the server's account domain (the AD
        // domain on a DC, the computer name on a member), then optionally
        // enumerates its normal user accounts and/or reads its password and
        // lockout policy. 'domain' receives the account domain's name.
        // Changes the active tree to IPC$.
        bool samrQuery(bool wantUsers, std::vector<SamrUser> &users,
                       bool wantPolicy, PassPolicy &policy,
                       String &domain, String &err);

        bool readFile(const String &path, std::vector<uint8_t> &out, size_t maxBytes, String &err);
        bool writeFile(const String &path, const uint8_t *data, size_t len, String &err);
        bool deleteFile(const String &path, String &err);
        bool makeDir(const String &path, String &err);
        bool removeDir(const String &path, String &err);

        void close();

        // TCP connect timeout used by open(). 5 s suits a single host; a
        // sweep sets it low so dead addresses don't stall the whole range.
        uint32_t connectTimeoutMs = 5000;

        // Populated by open(): what the server reported.
        String dialect;
        bool signingRequired = false;
        String computerName, domainName;
        // The domain actually sent in the NTLM exchange (see open()).
        String authDomain;

    private:
        struct Impl;
        Impl *p = nullptr;

        // Named-pipe DCE/RPC plumbing (on the current tree, normally IPC$).
        bool openPipe(const char *name, uint8_t fid[16], String &err);
        void closeHandle(const uint8_t fid[16]);
        bool pipeWrite(const uint8_t fid[16], const uint8_t *data, size_t len);
        bool pipeRead(const uint8_t fid[16], std::vector<uint8_t> &out);
        bool rpcBind(const uint8_t fid[16], const uint8_t uuid[16], uint16_t verMajor, uint16_t verMinor, String &err);
        // Sends one request PDU and returns the reassembled response stub
        // (all fragments, headers stripped). An RPC fault becomes 'err'.
        bool rpcCall(const uint8_t fid[16], uint16_t opnum, const std::vector<uint8_t> &stub,
                     std::vector<uint8_t> &reply, String &err);
    };

} // namespace SmbClient
