// Ripar Wallet firmware entry point (Arduino-ESP32 2.0.x). Everything happens in src/flows.cpp
// (ripar::app_setup / ripar::app_loop). No radio is ever started: nothing here or in any module includes the
// Wi-Fi or Bluetooth headers (docs/FIRMWARE.md "Radio check").
#include <Arduino.h>

#include "device.h"

// The loop task parses CBOR / JSON (recursive, bounded), builds review text and runs the ECDSA code: give it more
// than the 8 KB default stack.
SET_LOOP_TASK_STACK_SIZE(32 * 1024);

void setup() {
  Serial.begin(115200);    // USB CDC (development log only: status lines, never keys or request contents)
  Serial.setTxTimeoutMs(0);  // never block when no host is attached
  ripar::app_setup();
}

void loop() { ripar::app_loop(); }
