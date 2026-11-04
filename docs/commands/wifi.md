# wifi

Category: network

Summary: WiFi scanning and connection

Usage:

```
wifi scan | connect <ssid> [pass] | disconnect | status
```

Manual:

```
DESCRIPTION
    Station-mode WiFi management. Every network command needs an active
    connection, so this is normally the first thing you run.

SUBCOMMANDS
    scan                   List nearby access points: SSID, signal (RSSI),
                           channel, encryption and BSSID.
    connect <ssid> [pass]  Join a network. Omit the password for open
                           networks; quote SSIDs with spaces ("My Net").
                           The password is masked as **** while typing.
                           Applies the hostname/MAC overrides from
                           'settings' first. Gives up after 20 s; Ctrl+C
                           aborts.
    disconnect             Drop the current connection and stop auto-
                           reconnect.
    status                 Show IP, gateway, mask, DNS, MAC, BSSID, RSSI,
                           channel and hostname.

EXAMPLES
    root@espjack# wifi scan
    Scanning...
    SSID                             RSSI   CH   ENC    BSSID
    HomeNet                          -48    6    WPA    60:83:E7:E8:F3:B0
    Guest                            -71    11   OPEN   62:83:E7:E8:F3:B1

    root@espjack# wifi connect HomeNet ***********
    Connecting to 'HomeNet' (Ctrl+C to abort).....
    Connected. IP 192.168.1.42  Gateway 192.168.1.1

    root@espjack# wifi disconnect
    Disconnected from 'HomeNet'.

    root@espjack# wifi status
      ssid                   HomeNet
      ip                     192.168.1.42
      gateway                192.168.1.1
      subnet                 255.255.255.0
      dns                    192.168.1.1
      mac                    24:58:7C:A1:B2:C3
      bssid                  60:83:E7:E8:F3:B0
      rssi                   -48
      channel                6
      hostname               esp32s3-A1B2C3
```
