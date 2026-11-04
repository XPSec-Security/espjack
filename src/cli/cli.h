#pragma once
#include <Arduino.h>

// A small Linux-style serial CLI: a banner, a "root@espjack# " prompt,
// line editing with backspace, per-command "-h" help, and Ctrl+C to cancel
// whatever is currently running. This is the device's only interface —
// there is no web server and no display; everything happens over the USB
// serial console at 115200 8N1.
namespace Cli {
    // Prints the banner and the first prompt. Call once from setup().
    void begin();

    // If /autorun.txt exists on the SD card, runs it as a payload after a
    // short Ctrl+C-cancellable countdown. Call once from setup(), after
    // begin(), so a dropped device can act unattended.
    void runAutorun();

    // Executes the commands in an SD file line by line (skipping blanks and
    // '#' comments). Returns false if interrupted with Ctrl+C.
    bool runScript(const String &path);

    // Call every loop() iteration. Reads available serial bytes, echoes
    // them back, handles line editing, and dispatches completed lines.
    void update();
}
