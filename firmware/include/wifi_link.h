// Wi-Fi courier - TEMPORARY TEST FEATURE (docs/WIFI_LINK.md). Ripar's pitch is the air-gapped signer; this link exists
// only so the device can be tested from a phone / PC on the same network. src/wifi_link.cpp is compiled only with
// RIPAR_WIFI=1 (env:ripar). env:ripar-ble and env:ripar-airgap contain none of it: remove the flag and it is gone.
//
// Radio policy (enforced by src/flows.cpp through this API):
//   - Wi-Fi never starts unless a network is stored (sent by the paired phone over the BLE PROV characteristic and
//     confirmed on the device with SIGN) AND the user turned it on (menu WI-FI ON; the choice is persisted in NVS so a
//     developer can keep it on across restarts);
//   - wifi_link_disable() stops the HTTP server and mDNS, drops the network and de-initialises the Wi-Fi driver; it
//     runs on WI-FI OFF, FORGET WI-FI and PANIC;
//   - wifi_link_radio_alive() is the truth for the WIFI ON badge: the Wi-Fi driver is initialised.
//
// Threading: everything here runs on the app loop (the HTTP server is polled from wifi_link_tick, non-blocking).
#pragma once
#include <cstdint>
#include <string>

#include "wifi_proto.h"

namespace ripar {

// ---- the stored network: NVS namespace "ripar-wifi" (separate from the wallet's "ripar" seed / context)
bool wifi_creds_load(wifip::Creds& c);       // false = none stored (c empty)
bool wifi_creds_ssid(std::string& ssid);     // the stored network's name only
bool wifi_creds_save(const wifip::Creds& c); // writes, reads back and compares
bool wifi_creds_forget();                    // erases the namespace: the network AND the WI-FI ON choice
bool wifi_auto_on();                         // WI-FI ON is persisted (started at boot when a network is stored)
bool wifi_set_auto_on(bool on);

// ---- radio (app loop only)
enum class WifiState : uint8_t { Off, Connecting, On };
const char* wifi_state_text(WifiState s);  // "off" | "connecting" | "on" (STATUS "wifi")

// Station mode with the stored network, the HTTP server on port 80 and (once connected) mDNS <host>.local.
// False + err = Wi-Fi stays off (the driver is de-initialised again).
bool wifi_link_enable(std::string& err);
void wifi_link_disable();
bool wifi_link_on();             // enabled by wifi_link_enable() and not turned off since
bool wifi_link_radio_alive();    // the Wi-Fi driver is initialised (badge), also if a teardown step failed
WifiState wifi_link_state();     // Off / Connecting (no IP yet, or reconnecting) / On (IP address)
std::string wifi_link_ip();      // "a.b.c.d" while On, else ""
std::string wifi_link_host();    // "ripar-xxxx" (mDNS ripar-xxxx.local), from the station MAC
std::string wifi_link_ssid();    // the network in use ("" while off)
std::string wifi_link_code();    // the per-boot 8-digit link code ("" before the first enable of this boot)
std::string wifi_link_detail();  // while not connected: "connecting" / "network not found" / ... ("" when On / off)

enum class WifiEvt : uint8_t { None, StateChange };
// Once per app-loop pass while on: connection state, mDNS, and at most one HTTP request step (non-blocking reads;
// the whole request must arrive within 5 s). `app` is the device side: STATUS, SCAN intake, the QR on screen.
WifiEvt wifi_link_tick(uint32_t nowMs, wifip::LinkApp& app);

}  // namespace ripar
