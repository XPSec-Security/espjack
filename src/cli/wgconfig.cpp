#include "wgconfig.h"
#include <SD.h>

namespace {
    String trimmed(const String &s) {
        String t = s;
        t.trim();
        return t;
    }

    // Splits "Endpoint = host:port" style values on the last colon (hosts
    // here are plain DNS names or IPv4 addresses, never IPv6 literals).
    void splitHostPort(const String &v, String &host, uint16_t &port) {
        int colon = v.lastIndexOf(':');
        if (colon < 0) { host = v; port = 51820; return; }
        host = v.substring(0, colon);
        port = (uint16_t)v.substring(colon + 1).toInt();
        if (port == 0) port = 51820;
    }
}

namespace WgConfig {

bool loadFromFile(const String &path, WireGuardPivot::Config &out, String &error) {
    File f = SD.open(path.c_str(), FILE_READ);
    if (!f) { error = "file not found: " + path; return false; }

    enum Section { NONE, IFACE, PEER };
    Section section = NONE;
    out = WireGuardPivot::Config();
    out.endpointPort = 51820;

    while (f.available()) {
        String line = trimmed(f.readStringUntil('\n'));
        if (line.length() == 0 || line.startsWith("#") || line.startsWith(";")) continue;

        if (line.startsWith("[")) {
            String s = line;
            s.toLowerCase();
            if (s.indexOf("interface") >= 0) section = IFACE;
            else if (s.indexOf("peer") >= 0) section = PEER;
            else section = NONE;
            continue;
        }

        int eq = line.indexOf('=');
        if (eq < 0) continue;
        String key = trimmed(line.substring(0, eq));
        String val = trimmed(line.substring(eq + 1));
        String keyLower = key; keyLower.toLowerCase();

        if (section == IFACE) {
            if (keyLower == "privatekey") out.privateKey = val;
            else if (keyLower == "address") {
                int slash = val.indexOf('/');
                out.localIp = slash >= 0 ? val.substring(0, slash) : val;
            }
        } else if (section == PEER) {
            if (keyLower == "publickey") out.endpointPublicKey = val;
            else if (keyLower == "presharedkey") out.presharedKey = val;
            else if (keyLower == "endpoint") splitHostPort(val, out.endpoint, out.endpointPort);
            // AllowedIPs intentionally ignored - see WireGuardPivot's scope note.
        }
    }
    f.close();

    if (out.privateKey.length() == 0) { error = "missing [Interface] PrivateKey"; return false; }
    if (out.localIp.length() == 0) { error = "missing [Interface] Address"; return false; }
    if (out.endpointPublicKey.length() == 0) { error = "missing [Peer] PublicKey"; return false; }
    if (out.endpoint.length() == 0) { error = "missing [Peer] Endpoint"; return false; }
    return true;
}

} // namespace WgConfig
