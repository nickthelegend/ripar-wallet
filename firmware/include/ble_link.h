// Bluetooth LE fallback courier (docs/BLE_LINK.md). Device-only; src/ble_link.cpp is compiled only when RIPAR_BLE=1
// (env:ripar). The radio-free build (env:ripar-airgap, RIPAR_BLE=0) contains none of this.
//
// Radio policy (enforced by src/flows.cpp through this API):
//   - the Bluetooth controller is never initialised at boot; ble_link_enable() is only called after the BLE LINK
//     review + pulse + SIGN on the device; Wi-Fi is never initialised by anything;
//   - ble_link_disable() tears everything down (advertising, link, Bluedroid, controller: disable + deinit);
//     it runs on BLE OFF, on PANIC, after 5 min without link traffic (ble_link_tick) and a power cycle always
//     leaves the radio off;
//   - ble_link_radio_alive() is the truth for the RADIO ON badge: the controller is anything but idle.
//
// Threading: Bluedroid calls back on its own task; everything here except those callbacks runs on the app loop.
#pragma once
#include <cstdint>
#include <string>

namespace ripar {

// ---- radio on / off (app loop only)
bool ble_link_enable(const std::string& name, std::string& err);  // name: blep::adv_name(); false + err = still off
void ble_link_disable();
bool ble_link_on();              // enabled by ble_link_enable() and not turned off since
bool ble_link_radio_alive();     // the controller is initialised (badge), also if a teardown step failed
std::string ble_link_name();     // advertised name while on

// ---- the one bonded phone
// Forgets the bond: at once while the radio is on (the phone is disconnected), otherwise before the next
// advertising starts (flag in NVS namespace "riparble").
void ble_link_forget_phone();
int ble_link_bonded_count();     // bonds known to the stack (-1 while the radio is off)

// ---- pairing (LE Secure Connections, numeric comparison)
// Pairing requests are refused unless the window is open (flows.cpp: only while Screen::BlePair is shown).
void ble_link_pairing_window(bool open);
bool ble_link_code(uint32_t& code);  // a 6-digit comparison value waits for the user's answer
void ble_link_answer(bool accept);   // accept: replaces any other bond with this phone once pairing completes

struct BleLinkView {
  bool connected = false;
  bool authenticated = false;  // LE Secure Connections + MITM (bonded phone): the only state with GATT access
  uint16_t mtu = 23;
};
BleLinkView ble_link_view();

// ---- data
// Next complete RX line (one UR part), only from an authenticated link.
bool ble_link_poll_line(std::string& line);

enum class BleEvt : uint8_t {
  None,
  AutoOff,     // 5 min without link traffic: the radio is now off
  CodeShown,   // a numeric comparison value is waiting (ble_link_code)
  Paired,      // a new phone was paired and bonded (the old bond, if any, is gone)
  PairFailed,  // a pairing on this window failed or was rejected
  LinkChange,  // connected / authenticated / disconnected
};
// Once per app-loop pass. status: the STATUS JSON (blep::status_json), notified when it changes; output: the UR text
// of the QR on screen (empty when none), sent on TX (text + '\n', MTU - 3 chunks) when it changes or when the phone
// subscribes. Returns the most important event of this pass.
BleEvt ble_link_tick(uint32_t nowMs, const std::string& status, const std::string& output);

}  // namespace ripar
