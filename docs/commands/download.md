# download

Category: network

Summary: HTTP(S) GET a file straight to the SD card

Usage:

```
download <url> <path>
```

Manual:

```
DESCRIPTION
    Fetches a file over HTTP or HTTPS and saves it to the SD card - the
    usual way to get wordlists or a WireGuard config onto the device.
    HTTPS certificates are not verified. An existing file at <path> is
    overwritten. Ctrl+C aborts and keeps the partial file.

EXAMPLE
    (on your laptop: python -m http.server 8000)
    root@espjack# download http://192.168.1.50:8000/users.txt /wordlists/users.txt
    GET http://192.168.1.50:8000/users.txt
    1873 bytes / 1873
    Saved 1873 bytes to /wordlists/users.txt
```
