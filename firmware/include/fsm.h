// The signer's screen state machine (security review B1). Portable C++14 (host + device) so that every gate is
// host-tested (test/host/test_fsm.cpp).
//
// src/flows.cpp is the device driver around it. Once per loop pass it polls the BOOT key, the pulse sensor (only on
// Pulse / Armed) and the camera, feeds ONE FsmIn into Fsm::step(), runs the entry / exit side effects of any screen
// change (camera and pulse sensor on / off, key-queue drain, buffer wipes), performs the returned Act (parse, sign,
// draw) and reports back with go() / open_review() / review_drawn().
//
// What this state machine guarantees:
//   - Act::Sign is only returned on Screen::Armed, for a Key::Short polled in the SAME pass in which
//     pulse_update().passed was true (both are fields of the one FsmIn; no "passed" flag is remembered).
//   - Armed is only reachable from Pulse (pulse passed in that pass) and Pulse only from a Review whose every
//     display row has been reported as drawn (review_drawn), whose policy check passed (Review::ok) and whose job
//     needs the pulse. go() refuses Pulse, Armed and Review (use open_review) so the driver cannot skip a step.
//   - A refused review (ok == false) never leads to a signature. Its only exits are Home and, on a co-sign review,
//     Act::Deny (a deny can only restrict).
//   - Act::Confirm (RIPAR_WIFI test feature) is only returned for a fully seen WifiJoin / WifiOn review: a device
//     setting, never a signature; those jobs can never reach Pulse / Armed / Act::Sign.
//   - Deny: Long2s on a co-sign Review -> Act::Deny (the driver builds the deny itself with policy.h
//     deny_from_cosign and opens its review; that review signs with Act::SignNoPulse, no pulse).
//   - Panic: only from HomeHold, i.e. a hold that BEGAN on Home, passed the "RELEASE = PAIRING QR / keep holding =
//     PANIC" screen at 2 s and reached 5 s -> Act::Panic (no pulse, panic can only restrict). A Long2s on Home is
//     acted on only when the key is RELEASED before 5 s (-> the unsigned pairing QR), so a 5 s hold never also opens
//     that QR. A Hold5s on Home itself (its Long2s lost) does nothing.
//   - A key event belongs to the screen on which its press BEGAN (review conformance M1 / security m1): after any
//     screen change, events are ignored until a pass has seen the key up (FsmIn::keyDown == false), except on
//     HomeHold, which exists only for the hold that entered it. So a hold that cancels a screen (Scan, a review, the
//     QR, a menu) and reaches 5 s on Home never panics, a hold carried into a co-sign review never files a deny, and a
//     SIGN press that began on Pulse and is released after Armed appeared never signs. (The driver also drops such
//     presses in io.cpp, io_flush; this is the host-tested rule.)
//   - Every screen except Home and Fail returns to Home after `timeoutMs` without a key press (Act::Timeout).
//   - Fail (the self-test failed) is terminal: step() does nothing there and go() cannot leave it.
#pragma once
#include <cstdint>

namespace ripar {

// BOOT key events (src/io.cpp): Short = released after < 1 s; Long2s = fired while held, at 2 s; Hold5s = fired
// while held, at 5 s (a 5 s hold therefore yields Long2s, then Hold5s).
enum class Key { None, Short, Long2s, Hold5s };

enum class Screen : uint8_t {
  Fail,      // self-test failed: terminal, nothing is ever signed
  Home,      // Short = scan, Long2s -> HomeHold (released there = pairing QR, held on to 5 s = PANIC)
  HomeHold,  // BOOT held >= 2 s on Home: release = pairing QR, keep holding to 5 s = PANIC
  Scan,      // camera viewfinder, UR parts collected; Long2s = cancel
  Review,    // lines of the parsed request, paged by display row; Short = next page / continue
  Pulse,     // measuring the pulse (pulse_start() on entry from Review)
  Armed,     // pulse passed: Short signs
  Qr,        // the signed response QR; Short = done
  Message,   // refusal / information; Short = home
  PairQr,    // unsigned pairing QR (keys only); Short = home, Long2s = device actions menu
  Menu,      // device actions: Short = next item, Long2s = select
  BlePair,   // RIPAR_BLE builds only: Bluetooth pairing window; Short -> Act::BleConfirm, Long2s -> Act::BleReject
};

// What the review / signature is for.
// BleOn (RIPAR_BLE builds only): the confirmation that turns the radio on; it needs pulse + SIGN like a signature,
// but nothing is signed.
// WifiJoin / WifiOn (RIPAR_WIFI builds only, a TEMPORARY TEST FEATURE, docs/WIFI_LINK.md): store the Wi-Fi network a
// phone sent over BLE / turn Wi-Fi on. Device settings, not signatures: a fully seen review is confirmed with SIGN
// WITHOUT the pulse (Act::Confirm); hold 2 s rejects.
enum class Job : uint8_t { None, Pair, Cosign, Mandate, Deny, Privy, Revoke, Reopen, BleOn, WifiJoin, WifiOn };
bool job_needs_pulse(Job j);  // every job except Deny, WifiJoin and WifiOn (Panic never goes through a review)
bool job_is_setting(Job j);   // WifiJoin / WifiOn: confirmed with Act::Confirm, nothing is signed

// Device actions menu (Screen::Menu). The last item is always BACK. The radio-free build has MENU_ITEMS items; a
// RIPAR_BLE build constructs its Fsm with MENU_ITEMS_BLE (BLE LINK / BLE OFF and FORGET PHONE before BACK), a
// RIPAR_WIFI build with MENU_ITEMS_WIFI (then also WI-FI ON / WI-FI OFF and FORGET WI-FI before BACK).
enum MenuItem : int {
  MENU_REVOKE = 0,
  MENU_REOPEN = 1,
  MENU_BACK = 2,
  MENU_ITEMS = 3,
  MENU_BLE = 2,  // RIPAR_BLE menu: BLE LINK (radio off) / BLE OFF (radio on)
  MENU_FORGET = 3,
  MENU_BLE_BACK = 4,
  MENU_ITEMS_BLE = 5,
  MENU_WIFI = 4,  // RIPAR_WIFI menu (after the two BLE items): WI-FI ON (Wi-Fi off) / WI-FI OFF (Wi-Fi on)
  MENU_WIFI_FORGET = 5,
  MENU_WIFI_BACK = 6,
  MENU_ITEMS_WIFI = 7,
};

struct FsmIn {
  Key key = Key::None;       // the (at most one) key event polled in this pass (io_poll_key_state)
  bool keyDown = false;      // the debounced key state read together with `key` in this pass
  bool pulsePassed = false;  // pulse_update().passed polled in THIS pass (read on Pulse / Armed only)
  uint32_t nowMs = 0;        // millis() of this pass (wraps; only differences are used)
};

enum class Act : uint8_t {
  None,
  Redraw,       // same screen, new content (review paged, menu item moved)
  Ignored,      // a key press that does nothing here (e.g. Short while the pulse has not passed, or a press that began
                // on the previous screen): error beep
  PairQr,       // HomeHold: released before 5 s -> screen is now PairQr (unsigned keys-only QR)
  Panic,        // HomeHold: Hold5s -> sign Panic now; the driver then go(Qr) or go(Message)
  MenuSelect,   // Menu: Long2s on menu_index(); the driver opens that review or goes Home
  Sign,         // Armed: Short in the same pass as pulsePassed -> sign now; the driver then go(Qr) / go(Message)
  SignNoPulse,  // fully seen, allowed Deny review: Short -> sign the deny with zero evidence
  Deny,         // co-sign Review: Long2s -> the driver builds the device-side deny and opens its review
  Home,         // back to Home (cancel / done / refused review)
  Timeout,      // back to Home after timeoutMs without a key press
  BleConfirm,   // BlePair: Short (the driver confirms a shown pairing code, or goes Home)
  BleReject,    // BlePair: Long2s (the driver rejects a shown pairing code, or turns the radio off)
  Confirm,      // fully seen WifiJoin / WifiOn review: Short -> the driver applies it (no pulse, nothing signed)
};

// First display row to draw: `first` clamped so that a full screen of `visible` rows is shown whenever the review
// has that many (0 when everything fits). Used by ui.cpp ui_review().
int review_clamp_first(int first, int visible, int total);
// Row to draw after a "next page" press: the page moves by visible - 1 rows (one row of overlap, never fewer than
// one row), so every row is on screen at some point before the last one is.
int review_next_first(int firstShown, int rowsShown);

class Fsm {
 public:
  static const uint32_t DEFAULT_TIMEOUT_MS = 120000;
  // menuItems: MENU_ITEMS (radio-free build), MENU_ITEMS_BLE or MENU_ITEMS_WIFI; the last item is BACK
  explicit Fsm(uint32_t timeoutMs = DEFAULT_TIMEOUT_MS, int menuItems = MENU_ITEMS)
      : timeoutMs_(timeoutMs), menuItems_(menuItems < 2 ? 2 : menuItems) {}

  Screen screen() const { return screen_; }
  Job job() const { return job_; }
  bool review_ok() const { return ok_; }
  bool review_all_seen() const { return seenAll_; }
  int review_row() const { return row_; }  // first display row the driver should draw
  int menu_index() const { return menu_; }
  int menu_items() const { return menuItems_; }

  // One loop pass. May change screen() (the driver compares before / after and runs the entry / exit side effects).
  Act step(const FsmIn& in);

  // Driver-initiated screen change after it performed an action (parse result, signature, refusal). Refused (false,
  // nothing changes) for Pulse / Armed / Review (use open_review) and for anything while in Fail.
  bool go(Screen s, uint32_t nowMs);
  // Opens the review of a parsed request / device action: ok = the policy allows signing it (Review::ok).
  bool open_review(Job job, bool ok, uint32_t nowMs);
  // After each review draw: first row drawn (already clamped), rows drawn, total rows. Marks the review as fully
  // seen once every row from the first to the last has been drawn (contiguously; a jump ahead does not count).
  void review_drawn(int firstRow, int rowsShown, int totalRows);
  // Activity that is not a key press (e.g. a UR part scanned) postpones the timeout.
  void touch(uint32_t nowMs) { last_ = nowMs; }
  // Self-test failed: terminal.
  void fail() { screen_ = Screen::Fail; job_ = Job::None; ok_ = false; }

 private:
  void enter(Screen s, uint32_t nowMs);
  void clear_review();
  Act dispatch(Key k, const FsmIn& in, uint32_t now);  // step() after the stale-key filter and the timeout

  uint32_t timeoutMs_;
  int menuItems_;
  Screen screen_ = Screen::Home;
  uint32_t last_ = 0;  // last key press / screen change / touch
  Job job_ = Job::None;
  bool ok_ = false;
  bool seenAll_ = false;
  int row_ = 0;         // next first row to draw
  int shownFirst_ = 0;  // last reported draw
  int shownRows_ = 0;
  int seenUpTo_ = 0;    // rows [0, seenUpTo_) have all been drawn since open_review
  bool drawn_ = false;  // at least one draw reported since open_review
  int menu_ = 0;
  bool keyDown_ = false;      // FsmIn::keyDown of the latest pass
  bool upSinceEnter_ = true;  // the key was up when this screen was entered, or in a pass since
};

}  // namespace ripar
