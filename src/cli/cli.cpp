#include "cli.h"
#include "manpages.h"
#include "wgconfig.h"
#include "../config.h"

#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
extern "C" {
#include "esp_wifi.h"   // esp_wifi_set_mac for the MAC override
}
#include <SD.h>
#include <ArduinoJson.h>
#include <vector>
#include <functional>
#include <cstring>
#include <time.h>

#include "../modules/common/iprange.h"
#include "../modules/recon/netinfo.h"
#include "../modules/recon/dnslookup.h"
#include "../modules/recon/discover.h"
#include "../modules/recon/snmp.h"
#include "../modules/recon/portscan.h"
#include "../modules/recon/hostscan.h"
#include "../modules/recon/arpscan.h"
#include "../modules/recon/nbtscan.h"
#include "../modules/addomain/smbrecon.h"
#include "../modules/addomain/smbclient.h"
#include "../modules/addomain/ldaprecon.h"
#include "../modules/addomain/kerbrute.h"
#include "../modules/addomain/asreproast.h"
#include "../modules/addomain/kerberoast.h"
#include "../modules/mitm/arpspoof.h"
#include "../modules/mitm/responder.h"
#include "../modules/mitm/nettap.h"
#include "../modules/capture/pcap.h"
#include "../modules/pivot/wireguard.h"
#include "../modules/pivot/socks5.h"
#include "../modules/system/usbdrive.h"

namespace {
    // ---------------------------------------------------------------
    // small shared helpers
    // ---------------------------------------------------------------

    std::vector<String> tokenize(const String &line) {
        std::vector<String> out;
        String cur;
        bool inQuotes = false;
        for (size_t i = 0; i < line.length(); ++i) {
            char c = line[i];
            if (c == '"') { inQuotes = !inQuotes; continue; }
            if (!inQuotes && (c == ' ' || c == '\t')) {
                if (cur.length()) { out.push_back(cur); cur = ""; }
                continue;
            }
            cur += c;
        }
        if (cur.length()) out.push_back(cur);
        return out;
    }

    // Drains any buffered serial input, returning true if a Ctrl+C (0x03)
    // was among it. Used to make long-running commands interruptible.
    bool checkInterrupt() {
        bool hit = false;
        while (Serial.available()) {
            if (Serial.read() == 3) hit = true;
        }
        return hit;
    }

    // Blocks until 'stillRunning' returns false, calling 'onTick' every
    // ~300ms (so progress feels live, not stalled), polling for Ctrl+C the
    // whole time. On interrupt, calls 'onStop' and waits briefly for the
    // task to actually exit. Returns true if it was interrupted, false if
    // it finished on its own. Always leaves the cursor on a fresh line.
    bool pollUntilDone(std::function<bool()> stillRunning, std::function<void()> onTick,
                        std::function<void()> onStop) {
        uint32_t last = 0;
        while (stillRunning()) {
            if (checkInterrupt()) {
                onStop();
                Serial.println("\n^C - stopping...");
                uint32_t deadline = millis() + 3000;
                while (stillRunning() && millis() < deadline) delay(100);
                return true;
            }
            uint32_t now = millis();
            if (now - last >= 300) { onTick(); last = now; }
            delay(60);
        }
        onTick();        // one last update so the bar visibly reaches its end state
        Serial.println();
        return false;
    }

    // A single-line, in-place progress bar: "[####------------] 40%",
    // redrawn over itself via '\r' instead of scrolling a new line per
    // tick. Shared by every scanning/enumeration command.
    void printProgress(unsigned done, unsigned total, const String &suffix = "") {
        unsigned pct = total ? (done * 100 / total) : 0;
        if (pct > 100) pct = 100;
        const int width = 24;
        int filled = width * pct / 100;
        String bar;
        bar.reserve(width);
        for (int i = 0; i < width; ++i) bar += (i < filled) ? '#' : '-';

        String line = "  [" + bar + "] " + String(pct) + "%";
        if (suffix.length()) line += " - " + suffix;
        // Pad with plain spaces to blank out any longer previous line,
        // instead of an ANSI "erase to end of line" - some serial terminals
        // (e.g. plain miniterm with no ANSI support) print escape codes
        // literally instead of acting on them.
        while (line.length() < 60) line += ' ';
        Serial.print("\r" + line);
    }

    // Blanks the in-place progress line so a result row can be printed where
    // the bar was; the next printProgress() redraws the bar below it. Plain
    // spaces, same portable approach as printProgress().
    void clearProgressLine() {
        String blank = "\r";
        for (int i = 0; i < 60; ++i) blank += ' ';
        Serial.print(blank + "\r");
    }

    // For quick one-shot operations with no meaningful done/total (SMB and
    // LDAP recon): an in-place spinner instead of a scrolling "working..."
    // on every tick.
    void printSpinner() {
        static const char frames[] = {'|', '/', '-', '\\'};
        static int i = 0;
        Serial.printf("\r  %c working...                    ", frames[i]);
        i = (i + 1) % 4;
    }

    // Indeterminate progress bar (no known total): a lit segment bounces back
    // and forth across the track. Same portable '\r' redraw as printProgress.
    void printBusyBar(const char *label) {
        static int pos = 0;
        static bool fwd = true;
        const int width = 24, seg = 4;
        String bar;
        bar.reserve(width);
        for (int i = 0; i < width; ++i) bar += (i >= pos && i < pos + seg) ? '#' : '-';
        String line = "  [" + bar + "] " + String(label);
        while (line.length() < 60) line += ' ';
        Serial.print("\r" + line);
        if (fwd) { if (++pos + seg >= width) fwd = false; }
        else { if (--pos <= 0) fwd = true; }
    }

    // Status markers. Plain text only - some serial terminals render ANSI
    // escape codes literally instead of acting on them, so no color here.
    String mOk()   { return "[+]"; }
    String mErr()  { return "[-]"; }
    String mWarn() { return "[!]"; }
    String mInfo() { return "[*]"; }

    String valueToString(JsonVariantConst v) {
        if (v.isNull()) return "-";
        if (v.is<bool>()) return v.as<bool>() ? "yes" : "no";
        if (v.is<JsonArrayConst>()) return "[" + String(v.as<JsonArrayConst>().size()) + " items]";
        if (v.is<const char *>()) { String s(v.as<const char *>()); return s.length() ? s : "-"; }
        if (v.is<long long>()) return String((long)v.as<long long>());
        if (v.is<double>()) return String(v.as<double>(), 2);
        return "-";
    }

    // Generic flat {key: value, ...} status printer.
    void printKV(const String &json) {
        JsonDocument d;
        deserializeJson(d, json);
        for (JsonPair kv : d.as<JsonObject>()) {
            Serial.printf("  %-22s %s\n", kv.key().c_str(), valueToString(kv.value()).c_str());
        }
    }

    // Every network module assumes an active STA connection (sockets, ARP/
    // lwIP calls, multicast joins); some of that fails deep inside the WiFi/
    // lwIP stack rather than returning a clean error when there's no
    // connection at all, which can crash the device instead of just failing
    // the command. Call this first in any command that touches the network.
    bool requireWifi() {
        if (WiFi.status() == WL_CONNECTED) return true;
        Serial.println(mErr() + " Not connected to WiFi. Use 'wifi connect <ssid> <password>' first.");
        return false;
    }

    // Prints the command's one-line usage plus a pointer to its manual.
    // Defined after the command table.
    void printUsage(const char *name);

    // SD filesystem guard (card present and not exported over USB). Defined
    // in the files section; forward-declared for the commands above it.
    bool sdFsReady();

    // Parses "AA:BB:CC:DD:EE:FF" into 6 bytes. Rejects anything malformed or
    // a multicast/broadcast address (first byte's low bit set).
    bool parseMac(const String &s, uint8_t out[6]) {
        int vals[6];
        if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x", &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) != 6)
            return false;
        for (int i = 0; i < 6; ++i) { if (vals[i] < 0 || vals[i] > 255) return false; out[i] = (uint8_t)vals[i]; }
        if (out[0] & 0x01) return false;   // must be a unicast MAC
        return true;
    }

    // ---------------------------------------------------------------
    // wifi
    // ---------------------------------------------------------------

    void cmdWifi(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("wifi"); return; }
        String sub = a[1]; sub.toLowerCase();

        if (sub == "scan") {
            WiFi.mode(WIFI_STA);
            Serial.println("Scanning...");
            int n = WiFi.scanNetworks();
            if (n <= 0) { Serial.println("No networks found."); return; }
            Serial.printf("%-32s %-6s %-4s %-6s %s\n", "SSID", "RSSI", "CH", "ENC", "BSSID");
            for (int i = 0; i < n; ++i) {
                Serial.printf("%-32s %-6d %-4d %-6s %s\n", WiFi.SSID(i).c_str(), WiFi.RSSI(i), WiFi.channel(i),
                              WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "OPEN" : "WPA", WiFi.BSSIDstr(i).c_str());
            }
            WiFi.scanDelete();

        } else if (sub == "connect") {
            if (a.size() < 3) { Serial.println("Usage: wifi connect <ssid> [password]"); return; }
            String ssid = a[2];
            String pass = a.size() > 3 ? a[3] : "";
            WiFi.mode(WIFI_STA);
            // Apply stealth overrides (if set) before associating.
            if (netMac().length()) {
                uint8_t m[6];
                if (parseMac(netMac(), m)) {
                    esp_err_t e = esp_wifi_set_mac(WIFI_IF_STA, m);
                    Serial.printf(e == ESP_OK ? "Using MAC %s\n" : "MAC override failed (%s), using real MAC\n",
                                  e == ESP_OK ? netMac().c_str() : esp_err_to_name(e));
                } else {
                    Serial.println("Configured MAC is invalid, using real MAC.");
                }
            }
            if (netHostname().length()) WiFi.setHostname(netHostname().c_str());
            WiFi.begin(ssid.c_str(), pass.length() ? pass.c_str() : nullptr);
            Serial.printf("Connecting to '%s' (Ctrl+C to abort)", ssid.c_str());

            uint32_t deadline = millis() + 20000;
            bool interrupted = false;
            while (WiFi.status() != WL_CONNECTED && millis() < deadline) {
                if (checkInterrupt()) { interrupted = true; break; }
                Serial.print(".");
                delay(400);
            }
            if (WiFi.status() == WL_CONNECTED) {
                Serial.println("\n" + mOk() + " Connected. IP " + WiFi.localIP().toString() +
                               "  Gateway " + WiFi.gatewayIP().toString());
                // Sync the clock so pcap/loot timestamps are real (UTC).
                configTime(0, 0, "pool.ntp.org", "time.google.com");
            } else {
                // Without this, esp_wifi keeps retrying the association on
                // its own (NO_AP_FOUND/STA_LEAVING events) and floods the
                // console long after this command has returned.
                WiFi.disconnect(true);
                Serial.println("\n" + mErr() + (interrupted ? " Aborted." : " Failed to connect (timeout)."));
            }

        } else if (sub == "disconnect") {
            if (WiFi.status() != WL_CONNECTED) { Serial.println("Not connected."); return; }
            String ssid = WiFi.SSID();
            WiFi.disconnect(true);   // also stops esp_wifi auto-reconnect attempts
            Serial.println("Disconnected from '" + ssid + "'.");
        } else if (sub == "status") {
            printKV(netinfoJson());
        } else {
            Serial.println("Unknown 'wifi' subcommand. Try 'wifi -h'.");
        }
    }

    // ---------------------------------------------------------------
    // download
    // ---------------------------------------------------------------

    void cmdDownload(std::vector<String> &a) {
        if (a.size() < 3) { printUsage("download"); return; }
        if (!sdFsReady()) return;
        if (!requireWifi()) return;

        String url = a[1];
        String path = a[2];
        if (!path.startsWith("/")) path = "/" + path;

        HTTPClient http;
        WiFiClientSecure secureClient;
        WiFiClient plainClient;
        bool https = url.startsWith("https://");
        bool began = https ? (secureClient.setInsecure(), http.begin(secureClient, url))
                            : http.begin(plainClient, url);
        if (!began) { Serial.println("Could not open connection to that URL."); return; }

        Serial.printf("GET %s\n", url.c_str());
        int code = http.GET();
        if (code != HTTP_CODE_OK) {
            Serial.printf("HTTP error: %d\n", code);
            http.end();
            return;
        }

        int total = http.getSize();
        File f = SD.open(path.c_str(), FILE_WRITE);
        if (!f) { Serial.println("Could not open " + path + " for writing."); http.end(); return; }

        WiFiClient *stream = http.getStreamPtr();
        uint8_t buf[512];
        int written = 0;
        uint32_t lastPrint = millis();
        bool interrupted = false;

        while (http.connected() && (total < 0 || written < total)) {
            if (checkInterrupt()) { interrupted = true; break; }
            size_t avail = stream->available();
            if (avail) {
                size_t chunk = avail > sizeof(buf) ? sizeof(buf) : avail;
                int n = stream->readBytes(buf, chunk);
                if (n > 0) { f.write(buf, n); written += n; }
            } else if (!stream->connected()) {
                break;
            } else {
                delay(5);
            }
            if (millis() - lastPrint > 500) {
                String prog = String(written) + " bytes";
                if (total > 0) prog += " / " + String(total);
                Serial.print("\r" + prog + "   ");
                lastPrint = millis();
            }
        }
        f.close();
        http.end();
        Serial.println();
        if (interrupted) Serial.println("Aborted (partial file kept).");
        else Serial.printf("Saved %d bytes to %s\n", written, path.c_str());
    }

    // ---------------------------------------------------------------
    // recon
    // ---------------------------------------------------------------

    void cmdPortscan(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("portscan"); return; }
        IPAddress base; uint32_t hostCount; String err;
        if (!parseIpRange(a[1], base, hostCount, err)) { Serial.println(err); return; }
        if (!requireWifi()) return;

        uint16_t startPort = 1, endPort = 1024, timeout = 400;
        bool top = false;
        int mode = 2;
        for (size_t i = 2; i < a.size(); ++i) {
            if (a[i] == "-top") top = true;
            else if (a[i] == "-p" && i + 1 < a.size()) {
                String r = a[++i];
                int dash = r.indexOf('-');
                if (dash > 0) { startPort = r.substring(0, dash).toInt(); endPort = r.substring(dash + 1).toInt(); }
            } else if (a[i] == "-m" && i + 1 < a.size()) mode = a[++i].toInt();
            else if (a[i] == "-t" && i + 1 < a.size()) timeout = a[++i].toInt();
        }

        if (!PortScan::start(base, startPort, endPort, (PortScan::Mode)mode, top, timeout, hostCount)) {
            Serial.println("Failed to start (already running or bad params).");
            return;
        }
        Serial.println(hostCount > 1 ? "Scanning range... (Ctrl+C to stop)" : "Scanning... (Ctrl+C to stop)");
        pollUntilDone(
            []() { return PortScan::running(); },
            []() { uint32_t done, total; PortScan::progress(done, total); printProgress(done, total); },
            []() { PortScan::stop(); });

        JsonDocument d;
        deserializeJson(d, PortScan::status());
        JsonArray results = d["results"];
        Serial.printf("\n%u open port(s):\n", results.size());
        Serial.printf("%-16s %-8s %-16s %s\n", "IP", "PORT", "SERVICE", "VERSION/BANNER");
        for (JsonObject r : results) {
            String v = r["version"].as<String>();
            if (!v.length()) v = r["banner"].as<String>();
            Serial.printf("%-16s %-8u %-16s %s\n", r["ip"].as<const char *>(), r["port"].as<unsigned>(),
                          r["service"].as<const char *>(), v.c_str());
        }
    }

    void cmdHostscan(std::vector<String> &a) {
        IPAddress base(0, 0, 0, 0); uint32_t hostCount = 0;
        if (a.size() > 1) {
            String err;
            if (!parseIpRange(a[1], base, hostCount, err)) { Serial.println(err); return; }
        }
        if (!requireWifi()) return;
        if (!HostScan::start(base, hostCount)) { Serial.println("Failed to start (already running or WiFi not connected)."); return; }
        Serial.println("Sweeping... (Ctrl+C to stop)");
        pollUntilDone(
            []() { JsonDocument d; deserializeJson(d, HostScan::status()); return d["running"].as<bool>(); },
            []() { JsonDocument d; deserializeJson(d, HostScan::status());
                   printProgress(d["done"].as<unsigned>(), d["total"].as<unsigned>()); },
            []() { HostScan::stop(); });

        JsonDocument d;
        deserializeJson(d, HostScan::status());
        JsonArray hosts = d["hosts"];
        Serial.printf("\n%u live host(s):\n", hosts.size());
        for (JsonVariant h : hosts) Serial.println("  " + h.as<String>());
    }

    void cmdArpscan(std::vector<String> &a) {
        IPAddress base(0, 0, 0, 0); uint32_t hostCount = 0;
        if (a.size() > 1) {
            String err;
            if (!parseIpRange(a[1], base, hostCount, err)) { Serial.println(err); return; }
        }
        if (!requireWifi()) return;
        if (!ArpScan::start(base, hostCount)) { Serial.println("Failed to start (already running or WiFi not connected)."); return; }
        Serial.println("Sweeping... (Ctrl+C to stop)");
        pollUntilDone(
            []() { JsonDocument d; deserializeJson(d, ArpScan::status()); return d["running"].as<bool>(); },
            []() { JsonDocument d; deserializeJson(d, ArpScan::status());
                   printProgress(d["done"].as<unsigned>(), d["total"].as<unsigned>()); },
            []() { ArpScan::stop(); });

        JsonDocument d;
        deserializeJson(d, ArpScan::status());
        JsonArray hosts = d["hosts"];
        Serial.printf("\n%-16s %s\n", "IP", "MAC");
        for (JsonObject h : hosts) Serial.printf("%-16s %s\n", h["ip"].as<const char *>(), h["mac"].as<const char *>());
    }

    void cmdNbtscan(std::vector<String> &a) {
        IPAddress base(0, 0, 0, 0); uint32_t hostCount = 0;
        if (a.size() > 1) {
            String err;
            if (!parseIpRange(a[1], base, hostCount, err)) { Serial.println(err); return; }
        }
        if (!requireWifi()) return;
        if (!NbtScan::start(base, hostCount)) { Serial.println("Failed to start (already running or WiFi not connected)."); return; }
        Serial.println("Sweeping... (Ctrl+C to stop)");
        pollUntilDone(
            []() { JsonDocument d; deserializeJson(d, NbtScan::status()); return d["running"].as<bool>(); },
            []() { JsonDocument d; deserializeJson(d, NbtScan::status());
                   printProgress(d["done"].as<unsigned>(), d["total"].as<unsigned>()); },
            []() { NbtScan::stop(); });

        JsonDocument d;
        deserializeJson(d, NbtScan::status());
        JsonArray hosts = d["hosts"];
        Serial.printf("\n%-16s %-20s %s\n", "IP", "NAME", "MAC");
        for (JsonObject h : hosts)
            Serial.printf("%-16s %-20s %s\n", h["ip"].as<const char *>(), h["name"].as<const char *>(), h["mac"].as<const char *>());
    }

    void cmdNslookup(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("nslookup"); return; }
        String name = a[1];
        String type = "A";
        IPAddress server(0, 0, 0, 0);
        for (size_t i = 2; i < a.size(); ++i) {
            if (a[i] == "-type" && i + 1 < a.size()) type = a[++i];
            else if (a[i] == "-server" && i + 1 < a.size()) server.fromString(a[++i]);
        }
        if (!requireWifi()) return;

        Serial.printf("Querying %s for %s record(s)...\n", name.c_str(), type.c_str());
        JsonDocument d;
        deserializeJson(d, DnsLookup::query(name, type, server));
        Serial.printf("Server: %s\n", d["server"].as<const char *>());
        if (!d["ok"].as<bool>()) { Serial.printf("Error: %s\n", d["error"].as<const char *>()); return; }

        JsonArray answers = d["answers"];
        if (answers.size() == 0) { Serial.println("No records of that type."); return; }
        Serial.printf("\n%-28s %-6s %-8s %s\n", "NAME", "TYPE", "TTL", "DATA");
        for (JsonObject r : answers)
            Serial.printf("%-28s %-6s %-8u %s\n", r["name"].as<const char *>(), r["type"].as<const char *>(),
                          r["ttl"].as<unsigned>(), r["data"].as<const char *>());
    }

    void cmdDiscover(std::vector<String> &a) {
        if (!requireWifi()) return;
        Serial.println("Discovering (SSDP + mDNS, ~6s)...");
        JsonDocument d;
        deserializeJson(d, Discover::run());
        JsonArray ssdp = d["ssdp"], mdns = d["mdns"];
        Serial.printf("\nSSDP/UPnP (%u):\n", ssdp.size());
        for (JsonObject o : ssdp) Serial.printf("  %-16s %s\n", o["ip"].as<const char *>(), o["info"].as<const char *>());
        Serial.printf("mDNS/Bonjour (%u):\n", mdns.size());
        for (JsonObject o : mdns) Serial.printf("  %-16s %s\n", o["ip"].as<const char *>(), o["name"].as<const char *>());
    }

    void cmdSnmp(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("snmp"); return; }
        IPAddress t; uint32_t count; String rerr;
        if (!parseIpRange(a[1], t, count, rerr)) { Serial.println(rerr); return; }
        String community = a.size() > 2 ? a[2] : "public";
        if (!requireWifi()) return;

        if (count > 1) {
            // Sweep: a short reply window per host (devices on a LAN answer in
            // milliseconds), one row per host that answers.
            Serial.printf("SNMP sweep of %u hosts (community '%s')... (Ctrl+C to stop)\n",
                          (unsigned)count, community.c_str());
            uint32_t b = ipToU32(t);
            unsigned found = 0;
            bool interrupted = false, header = false;
            for (uint32_t i = 0; i < count && !interrupted; ++i) {
                if (checkInterrupt()) { interrupted = true; break; }
                printProgress(i, count, String(found) + " found");
                IPAddress host = u32ToIp(b + i);
                JsonDocument d;
                deserializeJson(d, Snmp::get(host, community, 600));
                if (!d["ok"].as<bool>()) continue;
                ++found;
                clearProgressLine();
                if (!header) { Serial.printf("%-16s %s\n", "IP", "SYSDESCR"); header = true; }
                Serial.printf("%-16s %s\n", host.toString().c_str(), d["sysDescr"].as<const char *>());
            }
            printProgress(count, count, String(found) + " found");
            Serial.println();
            Serial.printf("%u host(s) answered SNMP with community '%s'.\n", found, community.c_str());
            if (interrupted) Serial.println("^C - stopped.");
            return;
        }
        Serial.printf("SNMP GET sysDescr @ %s (community '%s')...\n", t.toString().c_str(), community.c_str());
        JsonDocument d;
        deserializeJson(d, Snmp::get(t, community));
        if (!d["ok"].as<bool>()) { Serial.printf("No: %s\n", d["error"].as<const char *>()); return; }
        Serial.printf("OPEN (community '%s'):\n  %s\n", d["community"].as<const char *>(), d["sysDescr"].as<const char *>());
    }

    void cmdDhcp(std::vector<String> &a) {
        if (!requireWifi()) return;
        Serial.println("Current DHCP lease (this station):");
        Serial.printf("  ip:       %s\n", WiFi.localIP().toString().c_str());
        Serial.printf("  mask:     %s\n", WiFi.subnetMask().toString().c_str());
        Serial.printf("  gateway:  %s\n", WiFi.gatewayIP().toString().c_str());
        Serial.printf("  dns1:     %s\n", WiFi.dnsIP(0).toString().c_str());
        Serial.printf("  dns2:     %s\n", WiFi.dnsIP(1).toString().c_str());
        Serial.println("  (sniffing other hosts' DHCP needs the MITM relay + pcap on WPA nets)");
    }

    // ---------------------------------------------------------------
    // active directory
    // ---------------------------------------------------------------

    // Parses SMB auth flags (-u user, -p pass, -H nthash, -d domain,
    // --local-auth) from the argument list, starting at 'from'. Returns true
    // if a username was supplied (i.e. authenticated mode requested).
    bool parseSmbCreds(std::vector<String> &a, size_t from, SmbClient::Creds &c, String &err) {
        bool haveUser = false;
        for (size_t i = from; i < a.size(); ++i) {
            if (a[i] == "-u" && i + 1 < a.size()) { c.user = a[++i]; haveUser = true; }
            else if (a[i] == "-p" && i + 1 < a.size()) c.password = a[++i];
            else if (a[i] == "-d" && i + 1 < a.size()) c.domain = a[++i];
            else if (a[i] == "--local-auth") c.localAuth = true;
            else if (a[i] == "-H" && i + 1 < a.size()) {
                String h = a[++i];
                int colon = h.indexOf(':');          // accept LM:NT, keep the NT half
                if (colon >= 0) h = h.substring(colon + 1);
                if (h.length() != 32) { err = "-H needs a 32-hex-char NT hash (or LM:NT)."; return haveUser; }
                for (int b = 0; b < 16; ++b) c.ntHash[b] = (uint8_t)strtol(h.substring(b*2, b*2+2).c_str(), nullptr, 16);
                c.haveHash = true;
            }
        }
        return haveUser;
    }

    // Splits //host/share/a/b or \\host\share\a\b into its parts. 'item' is
    // the path within the share ("" for the share root). Returns false if the
    // string isn't a UNC path.
    bool parseUnc(const String &in, IPAddress &host, String &share, String &item) {
        String s = in; s.replace("\\", "/");
        if (!s.startsWith("//")) return false;
        s = s.substring(2);
        int s1 = s.indexOf('/');
        if (s1 < 0) return false;                     // need at least //host/share
        String hostStr = s.substring(0, s1);
        if (!host.fromString(hostStr)) return false;
        String rest = s.substring(s1 + 1);
        int s2 = rest.indexOf('/');
        if (s2 < 0) { share = rest; item = ""; }
        else { share = rest.substring(0, s2); item = rest.substring(s2 + 1); }
        return share.length() > 0;
    }

    // Opens + authenticates + tree-connects a remote session. Prints the
    // error and returns nullptr on failure. Caller deletes the session.
    SmbClient::Session *smbConnect(const IPAddress &host, const String &share, std::vector<String> &a, size_t credsFrom) {
        SmbClient::Creds creds; String err;
        if (!parseSmbCreds(a, credsFrom, creds, err)) {
            if (err.length()) Serial.println(err);
            else Serial.println("Remote access needs credentials: -u <user> -p <pass> | -H <nthash> [-d domain] [--local-auth]");
            return nullptr;
        }
        if (err.length()) { Serial.println(err); return nullptr; }
        if (!requireWifi()) return nullptr;

        SmbClient::Session *s = new SmbClient::Session();
        if (!s->open(host, creds, err)) { Serial.println("SMB: " + err); delete s; return nullptr; }
        if (!s->treeConnect(share, err)) { Serial.println("SMB: " + err); delete s; return nullptr; }
        return s;
    }

    // Blocks until 'running' goes false or Ctrl+C, printing nothing. Returns
    // false if interrupted. For per-host loops where a spinner would be noise.
    bool waitQuiet(std::function<bool()> running, std::function<void()> stop) {
        while (running()) {
            if (checkInterrupt()) {
                stop();
                uint32_t dl = millis() + 3000;
                while (running() && millis() < dl) delay(50);
                return false;
            }
            delay(40);
        }
        return true;
    }

    // Blocks up to 'ms', bailing out early on Ctrl+C. Returns false if
    // interrupted. Used to pace credential attempts across hosts.
    bool interruptibleDelay(uint32_t ms) {
        uint32_t until = millis() + ms;
        while ((long)(until - millis()) > 0) {
            if (checkInterrupt()) return false;
            delay(5);
        }
        return true;
    }

    // Formats a SAMR delta time (negative 100ns units; INT64_MIN = never,
    // 0 = none) as days or minutes.
    String samrAge(int64_t v, bool minutes) {
        if (v == INT64_MIN) return "never";
        if (v == 0) return "none";
        double secs = (double)(v < 0 ? -v : v) / 1e7;
        char buf[24];
        if (minutes) snprintf(buf, sizeof(buf), "%.0f min", secs / 60.0);
        else snprintf(buf, sizeof(buf), "%.1f days", secs / 86400.0);
        return String(buf);
    }

    void printSamrPolicy(const SmbClient::PassPolicy &p) {
        Serial.println("  password policy (SAMR):");
        if (p.have) {
            Serial.printf("    min length:      %d\n", p.minLength);
            Serial.printf("    complexity:      %s\n", (p.properties & 0x1) ? "required" : "off");
            Serial.printf("    history:         %d\n", p.historyLength);
            Serial.printf("    max age:         %s\n", samrAge(p.maxAge, false).c_str());
            Serial.printf("    min age:         %s\n", samrAge(p.minAge, false).c_str());
            if (p.properties & 0x10) Serial.println("    reversible encryption: ENABLED");
        }
        if (p.haveLockout) {
            if (p.lockoutThreshold == 0) Serial.println("    lockout thresh:  0 (accounts never lock out)");
            else {
                Serial.printf("    lockout thresh:  %d bad attempts\n", p.lockoutThreshold);
                Serial.printf("    lockout window:  %s\n", samrAge(p.lockoutWindow, true).c_str());
                Serial.printf("    lockout length:  %s\n", samrAge(p.lockoutDuration, true).c_str());
            }
        }
    }

    // SAMR enumeration on an already-authenticated session. Prints the
    // account domain, the policy and/or the user list.
    void runSamr(SmbClient::Session &s, bool wantUsers, bool wantPol) {
        std::vector<SmbClient::SamrUser> users;
        SmbClient::PassPolicy pol;
        String domain, err;
        Serial.println("Querying SAMR over IPC$...");
        bool ok = s.samrQuery(wantUsers, users, wantPol, pol, domain, err);
        if (domain.length()) Serial.println("  account domain: " + domain);
        if (!ok) { Serial.println(mErr() + " SAMR: " + err); }
        if (wantPol && (pol.have || pol.haveLockout)) printSamrPolicy(pol);
        if (wantUsers && ok) {
            Serial.printf("  users (%u%s):\n", (unsigned)users.size(), users.size() >= 5000 ? ", truncated" : "");
            for (auto &u : users) Serial.printf("    %-6u %s\n", (unsigned)u.rid, u.name.c_str());
        }
    }

    void smbReconDetailed(const IPAddress &t, SmbClient::Creds &creds, bool authMode, bool wantUsers, bool wantPol) {
        if (authMode) {
            String err;
            Serial.println("Authenticating... (Ctrl+C to stop)");
            SmbClient::Session s;
            bool ok = s.open(t, creds, err);
            Serial.printf("  target:        %s\n", t.toString().c_str());
            Serial.printf("  dialect:       %s\n", s.dialect.length() ? s.dialect.c_str() : "-");
            Serial.printf("  signing req:   %s\n", s.signingRequired ? "yes" : "no");
            Serial.printf("  domain:        %s\n", s.domainName.length() ? s.domainName.c_str() : "-");
            Serial.printf("  computer:      %s\n", s.computerName.length() ? s.computerName.c_str() : "-");
            if (s.authDomain.length() || creds.user.length())
                Serial.println("  auth as:       " + (s.authDomain.length() ? s.authDomain + "\\" : String("")) + creds.user +
                               (creds.localAuth ? "  (local account)" : (creds.domain.length() ? "" : "  (domain announced by the server)")));
            Serial.println("  authenticated: " + String(ok ? "YES" : "no"));
            if (!ok) { Serial.println("  reason:        " + err); return; }
            {
                String why;
                int adm = s.checkAdmin(why);
                Serial.println("  local admin:   " + String(adm == 1 ? "YES" : adm == 0 ? "no" : "unknown") + "  (" + why + ")");
                // Local accounts other than the built-in Administrator get a
                // filtered (non-admin) token over the network unless
                // LocalAccountTokenFilterPolicy=1, so "no" can be a false negative.
                if (adm == 0 && s.authDomain.equalsIgnoreCase(s.computerName)) {
                    Serial.println("                 (a local account that is not the built-in Administrator is");
                    Serial.println("                  UAC-filtered over the network: it may be admin but still read 'no')");
                }
            }
            if (wantUsers || wantPol) { runSamr(s, wantUsers, wantPol); return; }
            Serial.println("  (browse shares with: ls //" + t.toString() + "/<share> " +
                           (creds.haveHash ? "-H ...)" : "-u ... -p ...)"));
            return;
        }
        if (!SmbRecon::start(t)) { Serial.println("Failed to start."); return; }
        pollUntilDone(
            []() { JsonDocument d; deserializeJson(d, SmbRecon::status()); return d["running"].as<bool>(); },
            []() { printBusyBar("negotiating SMB..."); },
            []() { SmbRecon::stop(); });
        printKV(SmbRecon::status());
    }

    // One compact result line for a block scan, or "" if the host didn't
    // answer. Sets 'interrupted' if Ctrl+C was hit during this host.
    String smbReconLine(const IPAddress &host, SmbClient::Creds &creds, bool authMode, bool &interrupted,
                        bool wantUsers = false, bool wantPol = false) {
        char buf[96];
        if (authMode) {
            String err;
            SmbClient::Session s;
            s.connectTimeoutMs = 1500;                     // sweep: don't wait 5 s on every dead address
            bool ok = s.open(host, creds, err);
            if (!ok && err.startsWith("TCP")) return "";   // host not up / no 445
            snprintf(buf, sizeof(buf), "%-16s %-18s %-10s %-8s ", host.toString().c_str(),
                     s.computerName.length() ? s.computerName.c_str() : "-",
                     s.domainName.length() ? s.domainName.c_str() : "-",
                     s.signingRequired ? "yes" : "no");
            String line = String(buf) + (ok ? mOk() + " AUTH" : mErr() + " fail");
            if (ok) {
                String why;
                if (s.checkAdmin(why) == 1) line += " (ADMIN)";
            }
            if (ok && (wantUsers || wantPol)) {
                // Concise SAMR summary; use a single-host run for the full lists.
                std::vector<SmbClient::SamrUser> users;
                SmbClient::PassPolicy pol;
                String dom, serr;
                if (s.samrQuery(wantUsers, users, wantPol, pol, dom, serr)) {
                    if (wantUsers) line += "  users=" + String((unsigned)users.size());
                    if (wantPol && pol.have) line += "  minlen=" + String(pol.minLength);
                    if (wantPol && pol.haveLockout) line += "  lockout=" + String(pol.lockoutThreshold);
                }
            }
            return line;
        }
        if (!SmbRecon::start(host)) return "";
        if (!waitQuiet(
                []() { JsonDocument d; deserializeJson(d, SmbRecon::status()); return d["running"].as<bool>(); },
                []() { SmbRecon::stop(); })) interrupted = true;
        JsonDocument d; deserializeJson(d, SmbRecon::status());
        if (d["error"].as<String>().indexOf("connect") >= 0) return "";  // only hosts that answered 445
        snprintf(buf, sizeof(buf), "%-16s %-18s %-10s %-8s %s", host.toString().c_str(),
                 d["netbiosComputer"].as<const char *>(), d["netbiosDomain"].as<const char *>(),
                 d["signingRequired"].as<bool>() ? "yes" : "no",
                 d["nullSessionAllowed"].as<bool>() ? "null-session" : "-");
        return String(buf);
    }

    void cmdSmbrecon(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("smbrecon"); return; }
        IPAddress base; uint32_t count; String rerr;
        if (!parseIpRange(a[1], base, count, rerr)) { Serial.println(rerr); return; }

        SmbClient::Creds creds; String err;
        bool authMode = parseSmbCreds(a, 2, creds, err) || creds.haveHash;
        if (err.length()) { Serial.println(err); return; }
        // Only matters in authMode: paces credential attempts across hosts
        // (every wrong-password attempt counts toward that account's domain
        // lockout on each host it hits). No delay for anonymous banner recon.
        uint32_t delayMs = 250;
        bool wantUsers = false, wantPol = false;
        for (size_t i = 2; i < a.size(); ++i) {
            if (a[i] == "-t" && i + 1 < a.size()) delayMs = (uint32_t)a[++i].toInt();
            else if (a[i] == "--users") wantUsers = true;
            else if (a[i] == "--pass-pol") wantPol = true;
        }
        if ((wantUsers || wantPol) && !authMode) {
            Serial.println("--users / --pass-pol need credentials: -u <user> -p <pass> | -H <nthash>");
            return;
        }
        if (!requireWifi()) return;

        if (count == 1) {
            smbReconDetailed(base, creds, authMode, wantUsers, wantPol);
            return;
        }

        Serial.printf("Scanning %u hosts... (Ctrl+C to stop)\n", (unsigned)count);
        if (authMode) Serial.println(mWarn() + " Each wrong-password attempt counts toward this account's domain"
                                     " lockout - check the policy first with --pass-pol if unsure.");
        std::vector<String> rows;
        uint32_t b = ipToU32(base);
        bool interrupted = false;
        for (uint32_t i = 0; i < count && !interrupted; ++i) {
            if (checkInterrupt()) { interrupted = true; break; }
            printProgress(i, count, String(rows.size()) + " found");
            String line = smbReconLine(u32ToIp(b + i), creds, authMode, interrupted, wantUsers, wantPol);
            if (line.length()) rows.push_back(line);
            if (authMode && !interrupted && !interruptibleDelay(delayMs)) interrupted = true;
        }
        printProgress(count, count, String(rows.size()) + " found");
        Serial.println();
        Serial.printf("%-16s %-18s %-10s %-8s %s\n", "IP", "COMPUTER", "DOMAIN", "SIGNING", authMode ? "AUTH" : "SESSION");
        for (auto &r : rows) Serial.println(r);
        if (interrupted) Serial.println("^C - stopped.");
    }

    // Builds LdapRecon::Options from -u/-p/-d/--users/--pass-pol flags.
    LdapRecon::Options parseLdapOpts(std::vector<String> &a) {
        LdapRecon::Options opt;
        String user, domain;
        for (size_t i = 2; i < a.size(); ++i) {
            if (a[i] == "-u" && i + 1 < a.size()) user = a[++i];
            else if (a[i] == "-p" && i + 1 < a.size()) opt.password = a[++i];
            else if (a[i] == "-d" && i + 1 < a.size()) domain = a[++i];
            else if (a[i] == "--users") opt.enumUsers = true;
            else if (a[i] == "--pass-pol") opt.passPolicy = true;
            else if (a[i] == "-H") Serial.println("Note: LDAP needs a password; -H (pass-the-hash) isn't supported here, ignoring it.");
        }
        if (user.length()) {
            opt.authenticated = true;
            if (user.indexOf('@') >= 0 || user.indexOf('\\') >= 0) opt.bindName = user; // UPN or DOMAIN\user
            else if (domain.length()) opt.bindName = user + "@" + domain;                 // build a UPN
            else opt.bindName = user;
        }
        return opt;
    }

    void printLdapPolicy(JsonObjectConst p) {
        Serial.println("  password policy:");
        Serial.printf("    min length:      %d\n", p["minPwdLength"].as<int>());
        Serial.printf("    complexity:      %s\n", p["complexity"].is<const char *>() ? p["complexity"].as<const char *>() : "-");
        Serial.printf("    history:         %d\n", p["pwdHistoryLength"].as<int>());
        Serial.printf("    lockout thresh:  %d\n", p["lockoutThreshold"].as<int>());
        Serial.printf("    max age (days):  %.1f\n", p["maxPwdAgeDays"].as<double>());
        Serial.printf("    min age (days):  %.1f\n", p["minPwdAgeDays"].as<double>());
        Serial.printf("    lockout (min):   %.1f\n", p["lockoutDurationMin"].as<double>());
    }

    void printLdapDetailed(const String &json) {
        JsonDocument d;
        deserializeJson(d, json);
        Serial.printf("  bind:          %s (%s)\n", d["bindOk"].as<bool>() ? "ok" : "FAILED", d["bindType"].as<const char *>());
        if (!d["bindOk"].as<bool>()) { Serial.println("  error:         " + d["error"].as<String>()); return; }
        Serial.printf("  namingContext: %s\n", d["defaultNamingContext"].as<const char *>());
        Serial.printf("  dnsHostName:   %s\n", d["dnsHostName"].as<const char *>());
        if (d["passwordPolicy"].is<JsonObjectConst>()) printLdapPolicy(d["passwordPolicy"]);
        if (d["userCount"].is<unsigned>()) {
            Serial.printf("  users (%u%s):\n", (unsigned)LdapRecon::userCount(),
                          LdapRecon::usersTruncated() ? ", truncated: server returns at most 1000 per unpaged search" : "");
            for (size_t i = 0; i < LdapRecon::userCount(); ++i) Serial.println("    " + LdapRecon::userAt(i));
        }
        if (d["error"].as<String>().length()) Serial.println("  note:          " + d["error"].as<String>());
    }

    void cmdSmbshares(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("smbshares"); return; }
        IPAddress t; uint32_t count; String err;
        if (!parseIpRange(a[1], t, count, err)) { Serial.println(err); return; }
        SmbClient::Creds creds;
        bool authed = parseSmbCreds(a, 2, creds, err) || creds.haveHash;
        if (err.length()) { Serial.println(err); return; }
        uint32_t delayMs = 250;     // sweep only: pause between hosts that answer
        for (size_t i = 2; i < a.size(); ++i)
            if (a[i] == "-t" && i + 1 < a.size()) delayMs = (uint32_t)a[++i].toInt();
        if (!requireWifi()) return;

        // "disk", "print", "ipc" or "device"; a trailing '$' marks a hidden share.
        auto typeName = [](uint32_t type) {
            uint32_t base = type & 0xFF;
            const char *ty = base == 0 ? "disk" : base == 1 ? "print" : base == 3 ? "ipc" : "device";
            return String(ty) + ((type & 0x80000000) ? "$" : "");
        };

        if (count == 1) {
            SmbClient::Session s;
            if (!s.open(t, creds, err)) { Serial.println("SMB: " + err); return; }
            std::vector<SmbClient::ShareInfo> shares;
            if (!s.listShares(shares, err)) { Serial.println("SMB: " + err); return; }
            Serial.printf("\n%-24s %-10s %s\n", "SHARE", "TYPE", "REMARK");
            for (auto &sh : shares)
                Serial.printf("%-24s %-10s %s\n", sh.name.c_str(), typeName(sh.type).c_str(), sh.remark.c_str());
            Serial.printf("%u share(s).\n", (unsigned)shares.size());
            return;
        }

        // Sweep: one row per share, prefixed with the host, printed as each
        // host finishes (nothing is buffered). Addresses with no SMB are skipped.
        Serial.printf("Scanning %u hosts... (Ctrl+C to stop)\n", (unsigned)count);
        if (authed) Serial.println(mWarn() + " Each wrong-password attempt counts toward this account's domain"
                                   " lockout - check the policy first with smbrecon --pass-pol if unsure.");
        uint32_t b = ipToU32(t);
        unsigned answered = 0, listed = 0;
        bool interrupted = false, header = false;
        for (uint32_t i = 0; i < count && !interrupted; ++i) {
            if (checkInterrupt()) { interrupted = true; break; }
            printProgress(i, count, String(listed) + " listed");
            IPAddress host = u32ToIp(b + i);

            SmbClient::Session s;
            s.connectTimeoutMs = 1500;                       // sweep: don't wait 5 s on every dead address
            bool ok = s.open(host, creds, err);
            if (!ok && err.startsWith("TCP")) continue;      // no SMB on this address
            ++answered;
            std::vector<SmbClient::ShareInfo> shares;
            if (ok && !s.listShares(shares, err)) ok = false;

            clearProgressLine();
            if (!header) { Serial.printf("%-16s %-24s %-10s %s\n", "IP", "SHARE", "TYPE", "REMARK"); header = true; }
            if (!ok) {
                Serial.printf("%-16s %s SMB: %s\n", host.toString().c_str(), mErr().c_str(), err.c_str());
            } else {
                ++listed;
                for (auto &sh : shares)
                    Serial.printf("%-16s %-24s %-10s %s\n", host.toString().c_str(), sh.name.c_str(),
                                  typeName(sh.type).c_str(), sh.remark.c_str());
            }
            if (authed && !interruptibleDelay(delayMs)) interrupted = true;
        }
        printProgress(count, count, String(listed) + " listed");
        Serial.println();
        Serial.printf("%u host(s) answered SMB, %u listed their shares.\n", answered, listed);
        if (interrupted) Serial.println("^C - stopped.");
    }


    void cmdLdaprecon(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("ldaprecon"); return; }
        IPAddress base; uint32_t count; String rerr;
        if (!parseIpRange(a[1], base, count, rerr)) { Serial.println(rerr); return; }
        LdapRecon::Options opt = parseLdapOpts(a);
        if (!requireWifi()) return;

        if (count == 1) {
            if (!LdapRecon::start(base, opt)) { Serial.println("Failed to start."); return; }
            pollUntilDone(
                []() { return LdapRecon::running(); },
                []() { printBusyBar("querying LDAP..."); },
                []() { LdapRecon::stop(); });
            printLdapDetailed(LdapRecon::status(false));
            return;
        }

        // Block scan: progress bar during, one line per host that answers.
        Serial.printf("Scanning %u hosts for LDAP... (Ctrl+C to stop)\n", (unsigned)count);
        std::vector<String> rows;
        uint32_t b = ipToU32(base);
        bool interrupted = false;
        for (uint32_t i = 0; i < count && !interrupted; ++i) {
            if (checkInterrupt()) { interrupted = true; break; }
            printProgress(i, count, String(rows.size()) + " found");
            IPAddress host = u32ToIp(b + i);
            if (!LdapRecon::start(host, opt)) continue;
            if (!waitQuiet(
                    []() { return LdapRecon::running(); },
                    []() { LdapRecon::stop(); })) interrupted = true;
            JsonDocument d; deserializeJson(d, LdapRecon::status(false));
            if (d["error"].as<String>().indexOf("connect") >= 0) continue;
            char buf[96];
            snprintf(buf, sizeof(buf), "%-16s %-6s %-28s %s", host.toString().c_str(),
                     d["bindOk"].as<bool>() ? "ok" : "-",
                     d["dnsHostName"].as<const char *>(), d["defaultNamingContext"].as<const char *>());
            String line(buf);
            if (opt.enumUsers && d["bindOk"].as<bool>()) line += "  users=" + String((unsigned)d["userCount"].as<unsigned>());
            rows.push_back(line);
        }
        printProgress(count, count, String(rows.size()) + " found");
        Serial.println();
        Serial.printf("%-16s %-6s %-28s %s\n", "IP", "BIND", "DNSHOSTNAME", "NAMINGCONTEXT");
        for (auto &r : rows) Serial.println(r);
        if (interrupted) Serial.println("^C - stopped.");
    }

    void cmdKerbrute(std::vector<String> &a) {
        if (a.size() < 3) { printUsage("kerbrute"); return; }
        IPAddress kdc;
        if (!kdc.fromString(a[1])) { Serial.println("Invalid KDC IP."); return; }
        String realm = a[2];
        String wl = a.size() > 3 ? a[3] : "/wordlists/users.txt";
        if (!requireWifi()) return;
        if (!Kerbrute::start(kdc, realm, wl)) { Serial.println("Failed to start."); return; }
        Serial.println("Enumerating... (Ctrl+C to stop)");
        pollUntilDone(
            []() { JsonDocument d; deserializeJson(d, Kerbrute::status()); return d["running"].as<bool>(); },
            []() { JsonDocument d; deserializeJson(d, Kerbrute::status());
                   printProgress(d["done"].as<unsigned>(), d["total"].as<unsigned>(),
                                 String(d["found"].as<JsonArray>().size()) + " found"); },
            []() { Kerbrute::stop(); });

        JsonDocument d;
        deserializeJson(d, Kerbrute::status());
        String err = d["error"].as<String>();
        if (err.length()) Serial.println("Error: " + err);
        Serial.printf("\n%-24s %s\n", "USER", "STATUS");
        for (JsonObject r : d["found"].as<JsonArray>())
            Serial.printf("%-24s %s\n", r["user"].as<const char *>(), r["status"].as<const char *>());
    }

    void cmdAsreproast(std::vector<String> &a) {
        if (a.size() < 3) { printUsage("asreproast"); return; }
        IPAddress kdc;
        if (!kdc.fromString(a[1])) { Serial.println("Invalid KDC IP."); return; }
        String realm = a[2];
        String wl = a.size() > 3 ? a[3] : "/wordlists/users.txt";
        if (!requireWifi()) return;
        if (!AsRepRoast::start(kdc, realm, wl)) { Serial.println("Failed to start."); return; }
        Serial.println("Roasting... (Ctrl+C to stop)");
        pollUntilDone(
            []() { JsonDocument d; deserializeJson(d, AsRepRoast::status()); return d["running"].as<bool>(); },
            []() { JsonDocument d; deserializeJson(d, AsRepRoast::status());
                   printProgress(d["done"].as<unsigned>(), d["total"].as<unsigned>(),
                                 String(d["found"].as<JsonArray>().size()) + " found"); },
            []() { AsRepRoast::stop(); });

        JsonDocument d;
        deserializeJson(d, AsRepRoast::status());
        String err = d["error"].as<String>();
        if (err.length()) Serial.println("Error: " + err);
        Serial.printf("\n%-24s %-6s %s\n", "USER", "ETYPE", "HASH (hashcat -m 18200)");
        for (JsonObject r : d["found"].as<JsonArray>()) {
            String hash = r["hash"].as<String>();
            if (!hash.length()) hash = "(roastable, but RC4 is disabled for it: AES-only, no crackable hash)";
            Serial.printf("%-24s %-6d %s\n", r["user"].as<const char *>(), r["etype"].as<int>(), hash.c_str());
        }
    }

    void cmdKerberoast(std::vector<String> &a) {
        if (a.size() < 5) { printUsage("kerberoast"); return; }
        IPAddress kdc;
        if (!kdc.fromString(a[1])) { Serial.println("Invalid KDC IP."); return; }
        String realm = a[2], user = a[3], pass = a[4];
        String wl = a.size() > 5 ? a[5] : "/wordlists/spns.txt";
        if (!requireWifi()) return;
        if (!Kerberoast::start(kdc, realm, user, pass, wl)) { Serial.println("Failed to start."); return; }
        Serial.println("Requesting service tickets... (Ctrl+C to stop)");
        pollUntilDone(
            []() { JsonDocument d; deserializeJson(d, Kerberoast::status()); return d["running"].as<bool>(); },
            []() { JsonDocument d; deserializeJson(d, Kerberoast::status());
                   printProgress(d["done"].as<unsigned>(), d["total"].as<unsigned>()); },
            []() { Kerberoast::stop(); });

        JsonDocument d;
        deserializeJson(d, Kerberoast::status());
        String err = d["error"].as<String>();
        if (err.length()) Serial.println("Error: " + err);
        Serial.printf("\n%-32s %-6s %s\n", "SPN", "ETYPE", "HASH (hashcat -m 13100)");
        for (JsonObject r : d["found"].as<JsonArray>()) {
            String hash = r["hash"].as<String>();
            if (!hash.length()) hash = "(unsupported etype)";
            Serial.printf("%-32s %-6d %s\n", r["spn"].as<const char *>(), r["etype"].as<int>(), hash.c_str());
        }
    }

    // ---------------------------------------------------------------
    // mitm & poisoning
    // ---------------------------------------------------------------

    void printArpStatus() {
        JsonDocument d;
        deserializeJson(d, ArpSpoof::status());
        Serial.printf("  running:     %s\n", d["running"].as<bool>() ? "yes" : "no");
        Serial.printf("  mode:        %s\n", d["mode"].as<const char *>());
        Serial.printf("  phase:       %s\n", d["phase"].as<const char *>());
        if (String(d["phase"].as<const char *>()) == "discovering") {
            unsigned done = d["discoverDone"].as<unsigned>(), total = d["discoverTotal"].as<unsigned>();
            unsigned pct = total ? (done * 100 / total) : 0;
            Serial.printf("  progress:    %u%% (%u/%u hosts probed)\n", pct, done, total);
        }
        Serial.printf("  gateway:     %s (%s)\n", d["gateway"].as<const char *>(), d["gatewayMac"].as<const char *>());
        Serial.printf("  frames sent: %u\n", d["sent"].as<unsigned>());
        Serial.printf("  relay:       %s (%u frames forwarded)\n",
                      d["relay"].as<bool>() ? "on - victims stay online" : "off", d["forwarded"].as<unsigned>());
        JsonArray victims = d["victims"];
        Serial.printf("  victims (%u):\n", victims.size());
        for (JsonObject v : victims) Serial.printf("    %-16s %s\n", v["ip"].as<const char *>(), v["mac"].as<const char *>());
    }

    void cmdArpspoof(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("arpspoof"); printArpStatus(); return; }
        String sub = a[1]; sub.toLowerCase();
        if (sub == "on") {
            if (!requireWifi()) return;
            bool ok;
            if (a.size() >= 4) {
                IPAddress v, g;
                if (!v.fromString(a[2]) || !g.fromString(a[3])) { Serial.println("Invalid IP(s)."); return; }
                ok = ArpSpoof::start(v, g);
            } else {
                ok = ArpSpoof::startAll();
            }
            Serial.println(ok ? "ARP spoofing started in background. Use 'arpspoof status' or 'arpspoof off'."
                               : "Failed to start (already running, WiFi not connected, or MAC resolve failed).");
        } else if (sub == "off") {
            ArpSpoof::stop();
            Serial.println("Stopping (ARP caches will be healed)...");
        } else if (sub == "status") {
            printArpStatus();
        } else {
            Serial.println("Unknown 'arpspoof' subcommand. Try 'arpspoof -h'.");
        }
    }

    void printResponderStatus() {
        JsonDocument d;
        deserializeJson(d, Responder::status());
        Serial.printf("  running:          %s\n", d["running"].as<bool>() ? "yes" : "no");
        Serial.printf("  queries answered: %u\n", d["queriesAnswered"].as<unsigned>());
        JsonArray caps = d["captures"];
        Serial.printf("  captures (%u):\n", caps.size());
        if (caps.size()) {
            Serial.printf("    %-8s %-18s %-14s %-20s %s\n", "TYPE", "USER", "DOMAIN", "CLIENT", "HASH");
            for (JsonObject c : caps)
                Serial.printf("    %-8s %-18s %-14s %-20s %s\n", c["type"].as<const char *>(), c["user"].as<const char *>(),
                              c["domain"].as<const char *>(), c["client"].as<const char *>(), c["hash"].as<const char *>());
        }
    }

    void cmdResponder(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("responder"); printResponderStatus(); return; }
        String sub = a[1]; sub.toLowerCase();
        if (sub == "on") {
            if (!requireWifi()) return;
            Serial.println(Responder::start() ? "Responder started in background." : "Failed to start.");
        }
        else if (sub == "off") { Responder::stop(); Serial.println("Stopped."); }
        else if (sub == "status") printResponderStatus();
        else if (sub == "clear") { Responder::clearCaptures(); Serial.println("Captures cleared."); }
        else Serial.println("Unknown 'responder' subcommand. Try 'responder -h'.");
    }

    void cmdDnsspoof(std::vector<String> &a) {
        if (a.size() < 2) {
            printUsage("dnsspoof");
            Serial.printf("  active: %s, %u answer(s) forged\n",
                          NetTap::dnsSpoofActive() ? "yes" : "no", (unsigned)NetTap::dnsSpoofed());
            return;
        }
        String sub = a[1]; sub.toLowerCase();
        if (sub == "on") {
            uint32_t ip = 0; String shown = "this device's IP";
            if (a.size() > 2) { IPAddress x; if (x.fromString(a[2])) { ip = ipToU32(x); shown = a[2]; } }
            NetTap::setDnsSpoof(true, ip);
            Serial.println("DNS spoof on -> " + shown);
            if (!NetTap::relayActive()) Serial.println("NOTE: run 'arpspoof on' too, or victim DNS won't reach us.");
        } else if (sub == "off") {
            NetTap::setDnsSpoof(false, 0);
            Serial.println("DNS spoof off.");
        } else if (sub == "status") {
            Serial.printf("active: %s, %u answer(s) forged\n",
                          NetTap::dnsSpoofActive() ? "yes" : "no", (unsigned)NetTap::dnsSpoofed());
        } else {
            Serial.println("Unknown 'dnsspoof' subcommand. Try 'dnsspoof -h'.");
        }
    }

    void cmdSocks5(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("socks5"); printKV(Socks5::status()); return; }
        String sub = a[1]; sub.toLowerCase();
        if (sub == "on") {
            if (!requireWifi()) return;
            uint16_t port = a.size() > 2 ? (uint16_t)a[2].toInt() : 1080;
            if (Socks5::start(port))
                Serial.printf("SOCKS5 proxy up on :%u. Reach it via the WireGuard tunnel IP to pivot into the LAN.\n", port);
            else
                Serial.println("Failed to start (already running or WiFi down).");
        } else if (sub == "off") {
            Socks5::stop();
            Serial.println("Stopping...");
        } else if (sub == "status") {
            printKV(Socks5::status());
        } else {
            Serial.println("Unknown 'socks5' subcommand. Try 'socks5 -h'.");
        }
    }

    // ---------------------------------------------------------------
    // capture
    // ---------------------------------------------------------------

    void cmdPcap(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("pcap"); printKV(Pcap::status()); return; }
        String sub = a[1]; sub.toLowerCase();
        if (sub == "start") {
            if (UsbDrive::isMounted()) { Serial.println("SD is exported over USB (run 'unmount' first)."); return; }
            String fn = "capture";
            bool wifi = false;
            for (size_t i = 2; i < a.size(); ++i) {
                if (a[i] == "-w" || a[i] == "-80211") wifi = true;
                else fn = a[i];
            }
            if (!wifi && !ArpSpoof::status().isEmpty()) {
                JsonDocument d; deserializeJson(d, ArpSpoof::status());
                if (!d["relay"].as<bool>())
                    Serial.println("Tip: run 'arpspoof on' too, or this Ethernet capture only sees our own + broadcast traffic.");
            }
            bool ok = Pcap::start(fn, wifi);
            Serial.println(ok ? (wifi ? "Capturing 802.11 (promiscuous) in background. 'pcap status' / 'pcap stop'."
                                       : "Capturing Ethernet in background. 'pcap status' / 'pcap stop'.")
                              : "Failed to start (SD unavailable or already running).");
        } else if (sub == "stop") { Pcap::stop(); Serial.println("Stopping..."); }
        else if (sub == "status") printKV(Pcap::status());
        else Serial.println("Unknown 'pcap' subcommand. Try 'pcap -h'.");
    }

    // ---------------------------------------------------------------
    // pivot
    // ---------------------------------------------------------------

    void cmdWireguard(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("wireguard"); printKV(WireGuardPivot::status()); return; }
        String sub = a[1]; sub.toLowerCase();
        if (sub == "up") {
            if (a.size() < 3) { Serial.println("Usage: wireguard up <file>"); return; }
            if (!requireWifi()) return;
            if (!sdFsReady()) return;
            WireGuardPivot::Config cfg;
            String err;
            String path = a[2];
            if (!path.startsWith("/")) path = "/" + path;
            if (!WgConfig::loadFromFile(path, cfg, err)) { Serial.println("Config error: " + err); return; }
            Serial.println(WireGuardPivot::start(cfg) ? "WireGuard tunnel up." : "Failed to bring the tunnel up (check WiFi connection / config).");
        } else if (sub == "down") { WireGuardPivot::stop(); Serial.println("Tunnel stopped."); }
        else if (sub == "status") printKV(WireGuardPivot::status());
        else Serial.println("Unknown 'wireguard' subcommand. Try 'wireguard -h'.");
    }

    // ---------------------------------------------------------------
    // system
    // ---------------------------------------------------------------

    String withSlash(const String &p) { return p.startsWith("/") ? p : "/" + p; }

    bool isUnc(const String &p) { return p.startsWith("//") || p.startsWith("\\\\"); }

    // Guard for local-SD filesystem commands: the card must be present AND
    // not currently exported to a host over USB (the host owns the FAT while
    // mounted, so the firmware must not touch it).
    bool sdFsReady() {
        if (UsbDrive::isMounted()) { Serial.println("SD is exported over USB (run 'unmount' first)."); return false; }
        if (!sdReady()) { Serial.println("SD card not available."); return false; }
        return true;
    }

    // ---- remote (SMB share) variants of the file commands --------------
    // Each is reached when the path argument is a //host/share/... UNC.

    void remoteLs(std::vector<String> &a) {
        IPAddress host; String share, item;
        if (!parseUnc(a[1], host, share, item)) { Serial.println("Bad UNC path (use //host/share/dir)."); return; }
        SmbClient::Session *s = smbConnect(host, share, a, 2);
        if (!s) return;
        std::vector<SmbClient::DirEntry> entries; String err;
        if (!s->list(item, entries, err)) { Serial.println("SMB: " + err); delete s; return; }
        Serial.printf("%-40s %12s\n", "NAME", "SIZE");
        for (auto &e : entries) {
            if (e.isDir) Serial.printf("%-40s %12s\n", (e.name + "/").c_str(), "<DIR>");
            else Serial.printf("%-40s %12llu\n", e.name.c_str(), (unsigned long long)e.size);
        }
        delete s;
    }

    void remoteCat(std::vector<String> &a) {
        IPAddress host; String share, item;
        if (!parseUnc(a[1], host, share, item) || item.length() == 0) { Serial.println("Bad UNC path (use //host/share/file)."); return; }
        SmbClient::Session *s = smbConnect(host, share, a, 2);
        if (!s) return;
        std::vector<uint8_t> data; String err;
        if (!s->readFile(item, data, 256 * 1024, err)) { Serial.println("SMB: " + err); delete s; return; }
        for (uint8_t b : data) Serial.write(b);
        Serial.println();
        delete s;
    }

    void remoteRm(std::vector<String> &a) {
        IPAddress host; String share, item;
        if (!parseUnc(a[1], host, share, item) || item.length() == 0) { Serial.println("Bad UNC path (use //host/share/file)."); return; }
        SmbClient::Session *s = smbConnect(host, share, a, 2);
        if (!s) return;
        String err;
        Serial.println(s->deleteFile(item, err) ? "Removed." : "SMB: " + err);
        delete s;
    }

    void remoteMkdir(std::vector<String> &a) {
        IPAddress host; String share, item;
        if (!parseUnc(a[1], host, share, item) || item.length() == 0) { Serial.println("Bad UNC path (use //host/share/dir)."); return; }
        SmbClient::Session *s = smbConnect(host, share, a, 2);
        if (!s) return;
        String err;
        Serial.println(s->makeDir(item, err) ? "Created." : "SMB: " + err);
        delete s;
    }

    void remoteRmdir(std::vector<String> &a) {
        IPAddress host; String share, item;
        if (!parseUnc(a[1], host, share, item) || item.length() == 0) { Serial.println("Bad UNC path (use //host/share/dir)."); return; }
        SmbClient::Session *s = smbConnect(host, share, a, 2);
        if (!s) return;
        String err;
        Serial.println(s->removeDir(item, err) ? "Removed." : "SMB: " + err);
        delete s;
    }

    void cmdLs(std::vector<String> &a) {
        if (a.size() > 1 && isUnc(a[1])) { remoteLs(a); return; }
        if (!sdFsReady()) return;
        String path = a.size() > 1 ? withSlash(a[1]) : "/";
        File dir = SD.open(path.c_str());
        if (!dir || !dir.isDirectory()) { Serial.println("Not a directory: " + path); return; }
        Serial.printf("%-32s %10s\n", "NAME", "SIZE");
        for (File f = dir.openNextFile(); f; f = dir.openNextFile()) {
            String name = f.name();
            if (f.isDirectory()) Serial.printf("%-32s %10s\n", (name + "/").c_str(), "<DIR>");
            else Serial.printf("%-32s %10u\n", name.c_str(), (unsigned)f.size());
        }
    }

    void cmdCat(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("cat"); return; }
        if (isUnc(a[1])) { remoteCat(a); return; }
        if (!sdFsReady()) return;
        String path = withSlash(a[1]);
        File f = SD.open(path.c_str(), FILE_READ);
        if (!f || f.isDirectory()) { Serial.println("No such file: " + path); return; }
        while (f.available()) Serial.write(f.read());
        Serial.println();
        f.close();
    }

    void cmdEcho(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("echo"); return; }
        int redirIdx = -1;
        bool append = false;
        for (size_t i = 1; i < a.size(); ++i) {
            if (a[i] == ">" || a[i] == ">>") { redirIdx = (int)i; append = (a[i] == ">>"); break; }
        }
        size_t textEnd = redirIdx >= 0 ? (size_t)redirIdx : a.size();
        String text;
        for (size_t i = 1; i < textEnd; ++i) { if (text.length()) text += ' '; text += a[i]; }

        if (redirIdx < 0) { Serial.println(text); return; }
        if ((size_t)redirIdx + 1 >= a.size()) { Serial.println("Missing path after '>'/'>>'."); return; }
        if (!sdFsReady()) return;

        String path = withSlash(a[redirIdx + 1]);
        File f = SD.open(path.c_str(), append ? FILE_APPEND : FILE_WRITE);
        if (!f) { Serial.println("Could not open " + path + " for writing."); return; }
        f.println(text);
        f.close();
        Serial.println((append ? "Appended to " : "Wrote ") + path);
    }

    void cmdRm(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("rm"); return; }
        if (isUnc(a[1])) { remoteRm(a); return; }
        if (!sdFsReady()) return;
        String path = withSlash(a[1]);
        Serial.println(SD.remove(path.c_str()) ? "Removed." : "Failed to remove (not found, or is a directory - use rmdir).");
    }

    void cmdMkdir(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("mkdir"); return; }
        if (isUnc(a[1])) { remoteMkdir(a); return; }
        if (!sdFsReady()) return;
        Serial.println(SD.mkdir(withSlash(a[1]).c_str()) ? "Created." : "Failed to create directory.");
    }

    void cmdRmdir(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("rmdir"); return; }
        if (isUnc(a[1])) { remoteRmdir(a); return; }
        if (!sdFsReady()) return;
        Serial.println(SD.rmdir(withSlash(a[1]).c_str()) ? "Removed." : "Failed to remove (not empty, or not found).");
    }

    void cmdMv(std::vector<String> &a) {
        if (a.size() < 3) { printUsage("mv"); return; }
        if (!sdFsReady()) return;
        Serial.println(SD.rename(withSlash(a[1]).c_str(), withSlash(a[2]).c_str()) ? "Renamed." : "Failed to rename.");
    }

    void cmdCp(std::vector<String> &a) {
        if (a.size() < 3) { printUsage("cp"); return; }
        if (!sdFsReady()) return;
        String src = withSlash(a[1]), dst = withSlash(a[2]);
        File in = SD.open(src.c_str(), FILE_READ);
        if (!in || in.isDirectory()) { Serial.println("No such file: " + src); return; }
        File out = SD.open(dst.c_str(), FILE_WRITE);
        if (!out) { Serial.println("Could not create " + dst); in.close(); return; }
        uint8_t buf[512];
        size_t total = 0;
        while (in.available()) {
            int n = in.read(buf, sizeof(buf));
            if (n <= 0) break;
            out.write(buf, n);
            total += n;
        }
        in.close(); out.close();
        Serial.printf("Copied %u bytes.\n", (unsigned)total);
    }

    void cmdGet(std::vector<String> &a) {
        if (a.size() < 3 || !isUnc(a[1])) { printUsage("get"); return; }
        if (!sdFsReady()) return;
        IPAddress host; String share, item;
        if (!parseUnc(a[1], host, share, item) || item.length() == 0) { Serial.println("Bad remote path (use //host/share/file)."); return; }
        String dst = withSlash(a[2]);
        SmbClient::Session *s = smbConnect(host, share, a, 3);
        if (!s) return;
        std::vector<uint8_t> data; String err;
        if (!s->readFile(item, data, 4 * 1024 * 1024, err)) { Serial.println("SMB: " + err); delete s; return; }
        delete s;
        File f = SD.open(dst.c_str(), FILE_WRITE);
        if (!f) { Serial.println("Could not open " + dst + " for writing."); return; }
        f.write(data.data(), data.size());
        f.close();
        Serial.printf("Downloaded %u bytes to %s\n", (unsigned)data.size(), dst.c_str());
    }

    void cmdPut(std::vector<String> &a) {
        if (a.size() < 3 || !isUnc(a[2])) { printUsage("put"); return; }
        if (!sdFsReady()) return;
        String src = withSlash(a[1]);
        IPAddress host; String share, item;
        if (!parseUnc(a[2], host, share, item) || item.length() == 0) { Serial.println("Bad remote path (use //host/share/file)."); return; }
        File f = SD.open(src.c_str(), FILE_READ);
        if (!f || f.isDirectory()) { Serial.println("No such local file: " + src); return; }
        size_t len = f.size();
        uint8_t *buf = (uint8_t *)malloc(len ? len : 1);
        if (!buf) { Serial.println("File too large to buffer."); f.close(); return; }
        f.read(buf, len); f.close();
        SmbClient::Session *s = smbConnect(host, share, a, 3);
        if (!s) { free(buf); return; }
        String err;
        Serial.println(s->writeFile(item, buf, len, err) ? ("Uploaded " + String((unsigned)len) + " bytes.") : ("SMB: " + err));
        delete s; free(buf);
    }

    void cmdStat(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("stat"); return; }
        if (!sdFsReady()) return;
        String path = withSlash(a[1]);
        File f = SD.open(path.c_str());
        if (!f) { Serial.println("No such file: " + path); return; }
        Serial.printf("  path   %s\n", path.c_str());
        Serial.printf("  type   %s\n", f.isDirectory() ? "directory" : "file");
        if (!f.isDirectory()) Serial.printf("  size   %u bytes\n", (unsigned)f.size());
        f.close();
    }

    void cmdDf(std::vector<String> &a) {
        if (!sdFsReady()) return;
        uint64_t total = SD.totalBytes(), used = SD.usedBytes();
        Serial.printf("  total   %llu MB\n", total / (1024ULL * 1024ULL));
        Serial.printf("  used    %llu MB\n", used / (1024ULL * 1024ULL));
        Serial.printf("  free    %llu MB\n", (total - used) / (1024ULL * 1024ULL));
    }

    void cmdSettings(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("settings"); return; }
        String sub = a[1]; sub.toLowerCase();
        if (sub == "show") {
            Serial.println(settingsJsonText());
        } else if (sub == "set") {
            if (a.size() < 4) { Serial.println("Usage: settings set <sd.cs|sd.sck|sd.miso|sd.mosi|hostname|mac> <value>"); return; }
            String key = a[2];
            if (key.startsWith("sd.")) {
                Serial.println(setSdPinSetting(key.substring(3), a[3].toInt())
                                   ? "Saved. Run 'reboot' for it to take effect." : "Unknown SD pin key.");
            } else if (key == "hostname") {
                setNetSetting("hostname", a[3]);
                Serial.println("Saved. Takes effect on the next 'wifi connect'.");
            } else if (key == "mac") {
                uint8_t m[6];
                if (!parseMac(a[3], m)) { Serial.println("Invalid MAC (use AA:BB:CC:DD:EE:FF, unicast)."); return; }
                setNetSetting("mac", a[3]);
                Serial.println("Saved. Takes effect on the next 'wifi connect'.");
            } else {
                Serial.println("Unknown setting key.");
            }
        } else if (sub == "reset") {
            resetSettings();
            Serial.println("Reset to defaults. Run 'reboot' for it to take effect.");
        } else {
            Serial.println("Unknown 'settings' subcommand. Try 'settings -h'.");
        }
    }

    // Pushes old content off-screen with blank lines instead of an ANSI
    // "clear screen" code, so it works on any serial terminal.
    void cmdMount(std::vector<String> &) {
        String err;
        if (UsbDrive::mount(err)) {
            JsonDocument d; deserializeJson(d, UsbDrive::status());
            Serial.printf("SD exported over USB (%.0f MB). It should appear as a drive on the host.\n",
                          d["sizeMB"].as<double>());
            Serial.println("Local file commands are paused until 'unmount'.");
        } else {
            Serial.println("Mount failed: " + err);
        }
    }

    void cmdUnmount(std::vector<String> &) {
        if (!UsbDrive::isMounted()) { Serial.println("Not mounted."); return; }
        Serial.println("Ejecting... (make sure the host has finished writing / safely ejected)");
        UsbDrive::unmount();
        Serial.println(sdReady() ? "Unmounted. SD is back under firmware control." :
                                   "Unmounted, but the SD card did not re-mount locally.");
    }

    void cmdDelay(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("delay"); return; }
        long ms = a[1].toInt();
        uint32_t end = millis() + (ms > 0 ? ms : 0);
        while ((long)(end - millis()) > 0) {
            if (checkInterrupt()) { Serial.println("^C"); return; }
            delay(20);
        }
    }

    void cmdRun(std::vector<String> &a) {
        if (a.size() < 2) { printUsage("run"); return; }
        if (!sdFsReady()) return;
        String path = withSlash(a[1]);
        if (!SD.exists(path.c_str())) { Serial.println("No such script: " + path); return; }
        Cli::runScript(path);
    }

    void cmdLoot(std::vector<String> &a) {
        if (!sdFsReady()) return;
        String sub = a.size() > 1 ? a[1] : "list"; sub.toLowerCase();
        if (sub == "list") {
            File dir = SD.open("/loot");
            if (!dir || !dir.isDirectory()) { Serial.println("No loot yet (/loot is empty)."); return; }
            Serial.printf("%-32s %10s\n", "NAME", "SIZE");
            uint32_t total = 0, count = 0;
            for (File f = dir.openNextFile(); f; f = dir.openNextFile()) {
                if (f.isDirectory()) continue;
                Serial.printf("%-32s %10u\n", f.name(), (unsigned)f.size());
                total += f.size(); count++;
            }
            Serial.printf("%u file(s), %u bytes total in /loot\n", (unsigned)count, (unsigned)total);
        } else if (sub == "clear") {
            File dir = SD.open("/loot");
            if (!dir || !dir.isDirectory()) { Serial.println("Nothing to clear."); return; }
            int n = 0;
            for (File f = dir.openNextFile(); f; f = dir.openNextFile()) {
                if (f.isDirectory()) continue;
                String p = "/loot/" + String(f.name());
                if (SD.remove(p.c_str())) n++;
            }
            Serial.printf("Cleared %d loot file(s).\n", n);
        } else {
            Serial.println("Usage: loot list | clear");
        }
    }

    void cmdDate(std::vector<String> &) {
        time_t now = time(nullptr);
        if (now < 1000000000) { Serial.println("Clock not set yet (connect to WiFi; NTP syncs a few seconds after)."); return; }
        struct tm t; gmtime_r(&now, &t);
        char buf[40]; strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &t);
        Serial.println(buf);
    }

    void cmdClear(std::vector<String> &) { for (int i = 0; i < 50; ++i) Serial.println(); }

    void cmdReboot(std::vector<String> &) { Serial.println("Rebooting..."); delay(200); ESP.restart(); }

    // ---------------------------------------------------------------
    // help + dispatch table
    // ---------------------------------------------------------------

    void cmdHelp(std::vector<String> &a);

    struct CmdInfo {
        const char *name;
        const char *usage;
        const char *desc;
        const char *category;
        void (*fn)(std::vector<String> &);
    };

    // Order here is also the order categories print in, in cmdHelp.
    const char *CATEGORY_ORDER[] = {
        "network", "recon", "active directory", "mitm & poisoning",
        "capture", "pivot", "files", "system",
    };

    CmdInfo COMMANDS[] = {
        {"help", "help [command]", "List all commands, or show one command's usage and options", "system", cmdHelp},
        {"wifi", "wifi scan | connect <ssid> [pass] | disconnect | status", "WiFi scanning and connection", "network", cmdWifi},
        {"download", "download <url> <path>", "HTTP(S) GET a file straight to the SD card", "network", cmdDownload},
        {"portscan", "portscan <target>[/prefix] [-p a-b] [-top] [-m 0|1|2] [-t ms]", "TCP port scan (connect/banner/version)", "recon", cmdPortscan},
        {"hostscan", "hostscan [ip[/prefix]]", "ICMP ping sweep (default: local /24)", "recon", cmdHostscan},
        {"arpscan", "arpscan [ip[/prefix]]", "ARP sweep (default: local /24; works even if ICMP is blocked)", "recon", cmdArpscan},
        {"nbtscan", "nbtscan [ip[/prefix]]", "NetBIOS node status sweep (default: local /24, no credentials)", "recon", cmdNbtscan},
        {"nslookup", "nslookup <name> [-type <A|AAAA|MX|TXT|NS|PTR|SOA|SRV|CAA|ANY>] [-server <ip>]", "DNS lookup of any record type", "recon", cmdNslookup},
        {"discover", "discover", "Find UPnP/SSDP + mDNS/Bonjour devices (multicast)", "recon", cmdDiscover},
        {"snmp", "snmp <target>[/prefix] [community]", "SNMP v1 sysDescr check (default community public)", "recon", cmdSnmp},
        {"dhcp", "dhcp", "Show this station's DHCP lease details", "recon", cmdDhcp},
        {"smbrecon", "smbrecon <target>[/prefix] [-u user -p pass | -H nthash] [-d domain] [--local-auth] [--users] [--pass-pol] [-t ms]", "SMB2 recon; anonymous banner, authed check/spray, SAMR users + password policy", "active directory", cmdSmbrecon},
        {"smbshares", "smbshares <target>[/prefix] [-u user -p pass | -H nthash] [-d domain] [--local-auth] [-t ms]", "List the server's SMB shares (SRVSVC)", "active directory", cmdSmbshares},
        {"ldaprecon", "ldaprecon <target>[/prefix] [-u user -p pass -d domain] [--users] [--pass-pol]", "LDAP recon: anonymous RootDSE, or authed user/password-policy enum", "active directory", cmdLdaprecon},
        {"kerbrute", "kerbrute <kdc> <realm> [wordlist]", "Kerberos AS-REQ username enumeration", "active directory", cmdKerbrute},
        {"asreproast", "asreproast <kdc> <realm> [wordlist]", "AS-REP roasting (no credentials needed)", "active directory", cmdAsreproast},
        {"kerberoast", "kerberoast <kdc> <realm> <user> <pass> [wordlist]", "Kerberoasting (needs valid creds; experimental)", "active directory", cmdKerberoast},
        {"arpspoof", "arpspoof on [victim gateway] | off | status", "ARP cache poisoning - whole subnet or one target", "mitm & poisoning", cmdArpspoof},
        {"responder", "responder on | off | status | clear", "LLMNR/NBT-NS poisoning + NTLM/Basic credential trap", "mitm & poisoning", cmdResponder},
        {"dnsspoof", "dnsspoof on [ip] | off | status", "Forge DNS A answers on the MITM relay (needs arpspoof)", "mitm & poisoning", cmdDnsspoof},
        {"pcap", "pcap start [name] [-w] | stop | status", "Packet capture to SD (Ethernet; -w = raw 802.11)", "capture", cmdPcap},
        {"wireguard", "wireguard up <file> | down | status", "WireGuard pivot tunnel from a wg-quick config file", "pivot", cmdWireguard},
        {"socks5", "socks5 on [port] | off | status", "SOCKS5 proxy to pivot into the LAN (over WireGuard)", "pivot", cmdSocks5},
        {"ls", "ls [path | //host/share/dir <creds>]", "List files on the SD card or an SMB share", "files", cmdLs},
        {"cat", "cat <path | //host/share/file <creds>>", "Print a file (SD or SMB share)", "files", cmdCat},
        {"echo", "echo <text> [> path | >> path]", "Print text, or write/append it to a file", "files", cmdEcho},
        {"rm", "rm <path | //host/share/file <creds>>", "Delete a file (SD or SMB share)", "files", cmdRm},
        {"mkdir", "mkdir <path | //host/share/dir <creds>>", "Create a directory (SD or SMB share)", "files", cmdMkdir},
        {"rmdir", "rmdir <path | //host/share/dir <creds>>", "Remove an empty directory (SD or SMB share)", "files", cmdRmdir},
        {"mv", "mv <src> <dst>", "Rename/move a file on the SD card", "files", cmdMv},
        {"cp", "cp <src> <dst>", "Copy a file on the SD card", "files", cmdCp},
        {"get", "get //host/share/file <sd-path> <creds>", "Download a file from an SMB share to the SD card", "files", cmdGet},
        {"put", "put <sd-path> //host/share/file <creds>", "Upload a file from the SD card to an SMB share", "files", cmdPut},
        {"stat", "stat <path>", "Show a file's type and size", "files", cmdStat},
        {"df", "df", "Show SD card space usage", "files", cmdDf},
        {"settings", "settings show | set <key> <value> | reset", "Edit SD pins + network identity (hostname/MAC)", "system", cmdSettings},
        {"run", "run <file>", "Run CLI commands from an SD script file", "system", cmdRun},
        {"delay", "delay <ms>", "Pause (for scripts/autorun); Ctrl+C skips", "system", cmdDelay},
        {"loot", "loot [list | clear]", "List or clear captured loot in /loot", "system", cmdLoot},
        {"date", "date", "Show the current UTC time (NTP-synced on connect)", "system", cmdDate},
        {"mount", "mount", "Export the SD card to the host as a USB drive", "system", cmdMount},
        {"unmount", "unmount", "Stop exporting the SD card and reclaim it", "system", cmdUnmount},
        {"clear", "clear", "Clear the terminal screen", "system", cmdClear},
        {"reboot", "reboot", "Restart the device", "system", cmdReboot},
    };
    const size_t NUM_COMMANDS = sizeof(COMMANDS) / sizeof(COMMANDS[0]);

    const CmdInfo *findCommand(String name) {
        name.toLowerCase();
        for (auto &c : COMMANDS) {
            if (name == c.name) return &c;
        }
        return nullptr;
    }

    // Prints multi-line text one line at a time with println, so every line
    // ends in CRLF regardless of how the terminal treats a bare LF.
    void printLines(const char *text) {
        while (*text) {
            const char *nl = strchr(text, '\n');
            size_t len = nl ? (size_t)(nl - text) : strlen(text);
            Serial.write((const uint8_t *)text, len);
            Serial.println();
            if (!nl) break;
            text = nl + 1;
        }
    }

    void printManual(const CmdInfo &c) {
        Serial.println();
        Serial.println("NAME");
        Serial.printf("    %s - %s\r\n\r\n", c.name, c.desc);
        Serial.println("USAGE");
        Serial.printf("    %s\r\n\r\n", c.usage);
        const char *page = manPage(c.name);
        if (page) printLines(page);
        Serial.println();
    }

    void printUsage(const char *name) {
        const CmdInfo *c = findCommand(name);
        if (!c) return;
        Serial.printf("Usage: %s\r\n", c->usage);
        Serial.printf("Try '%s -h' for the options.\r\n", c->name);
    }

    void cmdHelp(std::vector<String> &a) {
        if (a.size() > 1) {
            const CmdInfo *c = findCommand(a[1]);
            if (c) printManual(*c);
            else Serial.println("No such command: " + a[1]);
            return;
        }
        Serial.println("\nAvailable commands (use '<command> -h' for details):");
        for (auto category : CATEGORY_ORDER) {
            bool first = true;
            for (auto &c : COMMANDS) {
                if (strcmp(c.category, category) != 0) continue;
                if (first) { Serial.printf("\n%s:\n", category); first = false; }
                Serial.printf("  %-12s %s\n", c.name, c.desc);
            }
        }
        Serial.println();
    }

    // ---------------------------------------------------------------
    // line editor - supports Up/Down command history and Left/Right
    // cursor movement, by recognizing the ANSI escape sequences a
    // terminal sends for arrow keys (ESC [ A/B/C/D). Anything else
    // starting with ESC is swallowed rather than inserted literally.
    // ---------------------------------------------------------------

    String g_line;
    size_t g_cursor = 0;

    std::vector<String> g_history;
    int g_historyPos = -1;   // -1 = editing live, not browsing history
    String g_draft;          // what was being typed before Up was pressed
    const size_t MAX_HISTORY = 50;

    enum class Esc { NONE, GOT_ESC, GOT_BRACKET };
    Esc g_esc = Esc::NONE;

    const char *BANNER_ART =
        "#####   ####  ####     ###   ###    ####  #   #\r\n"
        "#      #      #   #     #   #   #  #      #  # \r\n"
        "###     ###   ####      #   #####  #      ###  \r\n"
        "#          #  #      #  #   #   #  #      #  # \r\n"
        "#####  ####   #       ##    #   #   ####  #   #\r\n";

    void printBanner() {
        Serial.println();
        Serial.print(BANNER_ART);
        Serial.println();
        Serial.println("offensive-security toolkit (serial CLI)");
        Serial.println("Type 'help' to list commands, '<command> -h' for details.");
        Serial.println("WARNING: use only on networks and systems you are authorized to test.");
        Serial.println();
    }

    void printPrompt() { Serial.print("root@espjack# "); }

    // Index in 'line' from which characters must be echoed as '*': the WiFi
    // password field in "wifi connect <ssid> <password>". Returns the line
    // length (i.e. nothing masked) for any other input. g_line keeps the
    // real characters; only what's shown is masked.
    size_t maskStart(const String &line) {
        const int PW_FIELD = 3;         // wifi(0) connect(1) ssid(2) password(3)
        int field = -1;
        bool inTok = false, inQ = false;
        size_t startOf[4] = {0, 0, 0, 0};
        String f0, f1;
        for (size_t i = 0; i < line.length(); ++i) {
            char c = line[i];
            if (c == '"') { inQ = !inQ; if (!inTok) { inTok = true; if (++field < 4) startOf[field] = i; } continue; }
            if (!inQ && (c == ' ' || c == '\t')) { inTok = false; continue; }
            if (!inTok) { inTok = true; if (++field < 4) startOf[field] = i; }
            if (field == 0) f0 += c; else if (field == 1) f1 += c;
        }
        f0.toLowerCase(); f1.toLowerCase();
        if (f0 == "wifi" && f1 == "connect" && field >= PW_FIELD) return startOf[PW_FIELD];
        return line.length();
    }

    // g_line with its masked region replaced by '*', for echoing/redraw.
    String maskedLine() {
        size_t ms = maskStart(g_line);
        if (ms >= g_line.length()) return g_line;
        String out = g_line.substring(0, ms);
        for (size_t i = ms; i < g_line.length(); ++i) out += '*';
        return out;
    }

    // Full line redraw: return to column 0, reprint prompt+line, erase any
    // leftover tail from a previously longer line, then park the cursor at
    // the right column. Used whenever the line content changes wholesale
    // (history recall) rather than by a single keystroke at the cursor.
    void redrawLine() {
        Serial.print("\r");
        printPrompt();
        Serial.print(maskedLine());
        // Portable "erase to end of line": print spaces to blank out any
        // leftover tail from a previously longer line, then backspace back
        // over them - plain backspace (unlike ANSI cursor codes) is
        // rendered correctly by every serial terminal, not just ANSI-aware
        // ones.
        const int pad = 40;
        for (int i = 0; i < pad; ++i) Serial.print(' ');
        for (int i = 0; i < pad; ++i) Serial.print('\b');
        size_t back = g_line.length() - g_cursor;
        for (size_t i = 0; i < back; ++i) Serial.print('\b');
    }

    void historyUp() {
        if (g_history.empty()) return;
        if (g_historyPos == -1) { g_draft = g_line; g_historyPos = (int)g_history.size() - 1; }
        else if (g_historyPos > 0) g_historyPos--;
        else return; // already at the oldest entry
        g_line = g_history[g_historyPos];
        g_cursor = g_line.length();
        redrawLine();
    }

    void historyDown() {
        if (g_historyPos == -1) return; // already editing the live line
        if (g_historyPos < (int)g_history.size() - 1) {
            g_historyPos++;
            g_line = g_history[g_historyPos];
        } else {
            g_historyPos = -1;
            g_line = g_draft;
        }
        g_cursor = g_line.length();
        redrawLine();
    }

    void execute(const String &line) {
        std::vector<String> tokens = tokenize(line);
        if (tokens.empty()) return;
        const CmdInfo *c = findCommand(tokens[0]);
        if (!c) { Serial.println(mErr() + " Unknown command: " + tokens[0] + " (try 'help')"); return; }
        if (tokens.size() > 1 && (tokens[1] == "-h" || tokens[1] == "--help")) { printManual(*c); return; }
        c->fn(tokens);
    }

    void resetLine() {
        g_line = "";
        g_cursor = 0;
        g_historyPos = -1;
    }

    // The S3's built-in USB serial gives no "terminal opened" signal, but the
    // core flags the link as connected once the host starts reading and drops
    // the flag on unplug or when a write times out. The banner is shown on
    // that rising edge, debounced because the core notes the flag can flap
    // briefly on a healthy link.
    bool g_bannerShown = false;
    uint32_t g_lastLinkCheck = 0;
    uint32_t g_linkDownSince = 0;
    const uint32_t LINK_DOWN_MS = 1500;

    void showBanner() {
        resetLine();
        g_esc = Esc::NONE;
        printBanner();
        printPrompt();
        g_bannerShown = true;
    }

    void checkTerminalLink() {
        uint32_t now = millis();
        if (now - g_lastLinkCheck < 250) return;
        g_lastLinkCheck = now;

        if (!Serial) {
            if (!g_linkDownSince) g_linkDownSince = now ? now : 1;
            return;
        }
        bool reconnected = g_linkDownSince && now - g_linkDownSince >= LINK_DOWN_MS;
        g_linkDownSince = 0;
        if (!g_bannerShown || reconnected) showBanner();
    }

    // Handles one fully-assembled key: a plain character, or an arrow
    // identified from an escape sequence (passed as 'A'/'B'/'C'/'D').
    void handleKey(char c) {
        if (c == 'A') { historyUp(); return; }           // Up
        if (c == 'B') { historyDown(); return; }          // Down
        if (c == 'C') {                                    // Right
            // No portable "move right without erasing" control code exists,
            // so re-print the character already shown there - same visual
            // result, cursor advances one column, nothing changes on screen.
            if (g_cursor < g_line.length()) {
                bool masked = (size_t)g_cursor >= maskStart(g_line);
                Serial.print(masked ? '*' : g_line[g_cursor]);
                g_cursor++;
            }
            return;
        }
        if (c == 'D') {                                    // Left
            if (g_cursor > 0) { g_cursor--; Serial.print('\b'); }
            return;
        }
    }
}

namespace Cli {

void begin() {
    if (Serial) showBanner();
}

bool runScript(const String &path) {
    File f = SD.open(path.c_str(), FILE_READ);
    if (!f) { Serial.println("Could not open script: " + path); return true; }
    Serial.println("[autorun] running " + path);
    bool ok = true;
    while (f.available()) {
        if (checkInterrupt()) { Serial.println("[autorun] ^C - stopped."); ok = false; break; }
        String line = f.readStringUntil('\n');
        line.trim();
        if (line.length() == 0 || line.startsWith("#")) continue;
        Serial.println("autorun> " + line);
        execute(line);
    }
    f.close();
    if (ok) Serial.println("[autorun] done.");
    return ok;
}

void runAutorun() {
    if (!sdReady() || !SD.exists("/autorun.txt")) return;
    Serial.println("\n/autorun.txt found - running in 3s (Ctrl+C to cancel)...");
    uint32_t end = millis() + 3000;
    while ((long)(end - millis()) > 0) {
        if (checkInterrupt()) { Serial.println("Autorun cancelled."); return; }
        delay(50);
    }
    runScript("/autorun.txt");
    Serial.println();
    printPrompt();
}

void update() {
    checkTerminalLink();
    // Fallback for hosts where the link flag never rises: anyone typing is
    // clearly connected.
    if (!g_bannerShown && Serial.available()) showBanner();

    while (Serial.available()) {
        char c = Serial.read();

        if (g_esc == Esc::GOT_ESC) {
            g_esc = (c == '[') ? Esc::GOT_BRACKET : Esc::NONE;
            continue;
        }
        if (g_esc == Esc::GOT_BRACKET) {
            g_esc = Esc::NONE;
            if (c == 'A' || c == 'B' || c == 'C' || c == 'D') handleKey(c);
            continue; // anything else (e.g. Home/End/Delete sequences) is ignored
        }
        if (c == 27) { g_esc = Esc::GOT_ESC; continue; }

        if (c == 3) { // Ctrl+C at an idle prompt: just clear the current line
            Serial.println("^C");
            resetLine();
            printPrompt();
            continue;
        }
        if (c == '\r') continue;
        if (c == '\n') {
            Serial.println();
            String line = g_line;
            resetLine();
            if (line.length() && (g_history.empty() || g_history.back() != line)) {
                g_history.push_back(line);
                if (g_history.size() > MAX_HISTORY) g_history.erase(g_history.begin());
            }
            execute(line);
            Serial.println();
            printPrompt();
            continue;
        }
        if (c == 8 || c == 127) { // backspace / DEL
            if (g_cursor > 0) {
                g_line.remove(g_cursor - 1, 1);
                g_cursor--;
                if (g_cursor == g_line.length()) {
                    Serial.print("\b \b"); // cheap path: was deleting at the end
                } else {
                    redrawLine();
                }
            }
            continue;
        }
        if (c >= 32 && c < 127) {
            if (g_cursor == g_line.length()) {
                g_line += c;      // cheap path: typing at the end
                g_cursor++;
                bool masked = (g_cursor - 1) >= maskStart(g_line);
                Serial.write(masked ? (uint8_t)'*' : (uint8_t)c);
            } else {
                g_line = g_line.substring(0, g_cursor) + c + g_line.substring(g_cursor);
                g_cursor++;
                redrawLine();
            }
        }
    }
}

} // namespace Cli
