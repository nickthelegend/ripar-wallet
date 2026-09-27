// Ripar Wallet firmware entry point (Arduino-ESP32 2.0.x). Everything happens in src/flows.cpp
// (ripar::app_setup / ripar::app_loop). Bluetooth LE only runs when the user turns on the fallback courier in the device
// menu (env:ripar / ripar-ble, src/ble_link.cpp, docs/BLE_LINK.md). Wi-Fi (env:ripar only, a TEMPORARY TEST FEATURE,
// src/wifi_link.cpp, docs/WIFI_LINK.md) only runs with a network confirmed on the device AND WI-FI ON chosen in the
// menu - that choice is persisted, so it then also starts after boot (the device shows WIFI ON / NOT AIR-GAPPED).
// env:ripar-airgap links no radio code at all (docs/FIRMWARE.md "Security model", radio check).
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
