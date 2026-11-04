#pragma once
#include <Arduino.h>

// Exposes the microSD card to a host PC as a USB Mass Storage drive, so the
// operator can read/write SD files over the USB cable. Requires TinyUSB mode
// (ARDUINO_USB_MODE=0); the MSC interface is always present in the USB
// descriptor (an empty "card reader" slot) and this toggles the media and
// serves raw sectors while mounted.
//
// While mounted the firmware must NOT touch the FAT filesystem (the host
// owns it), so the file commands refuse until 'unmount'. unmount() re-reads
// the card so the firmware sees whatever the host changed.
namespace UsbDrive {
    void init();              // call once from setup(), after initSD()
    bool mount(String &err);  // present the SD to the host
    void unmount();           // hide it and re-mount the FAT locally
    bool isMounted();
    String status();          // JSON {mounted, sectors, sizeMB}
}
