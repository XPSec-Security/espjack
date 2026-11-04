#pragma once
#include <Arduino.h>
#include <IPAddress.h>

// Shared WiFi-station RX hook. Installed once (idempotent) and then left in
// place, staying transparent while idle. Two consumers use it:
//   - arpspoof: transparent L2 relay of poisoned victim<->gateway traffic
//     (so victims keep working instead of being black-holed).
//   - pcap: a frame sink that receives every DECRYPTED Ethernet frame the
//     station sees, so a capture shows real IP/DNS instead of encrypted
//     802.11. With arpspoof running, that includes all the victims' traffic.
namespace NetTap {
    struct Victim { uint32_t ip; uint8_t mac[6]; };

    // Installs the RX callback if not already installed. Returns true if the
    // hook is active (false only if the esp-netif handle couldn't be found).
    bool ensureHook();

    // ---- relay (arpspoof) ----
    void configureRelay(const IPAddress &ourIp, const uint8_t ourMac[6],
                        const IPAddress &gwIp, const uint8_t gwMac[6],
                        const IPAddress &mask, const Victim *victims, int n);
    void relayEnable(bool on);
    bool relayActive();
    uint32_t forwarded();

    // ---- capture (pcap) ----
    // Called for every received Ethernet frame while set. Runs in the WiFi
    // RX task, so it must be fast (copy and return). Pass nullptr to clear.
    typedef void (*FrameSink)(const uint8_t *eth, uint16_t len);
    void setSink(FrameSink sink);

    // ---- DNS spoofing (MITM) ----
    // While on, A-record DNS queries seen on the relay are answered locally
    // with 'spoofIp' (0 = this device's IP), redirecting the victim. Needs
    // the relay active (arpspoof) to see the victims' DNS. Non-A queries
    // pass through untouched.
    void setDnsSpoof(bool on, uint32_t spoofIp);
    bool dnsSpoofActive();
    uint32_t dnsSpoofed();
}
