// DEPS: ble_proto fsm
// Host tests for the portable part of the Bluetooth LE fallback link (include/ble_proto.h, docs/BLE_LINK.md) and
// the state-machine additions it needs (include/fsm.h: the 5-item RIPAR_BLE menu, Screen::BlePair, Job::BleOn):
//   - GATT UUIDs in Bluedroid (little-endian) byte order, advertised name
//   - RX line reassembly: any write boundaries, CR LF, empty lines, the 4096-byte limit, reset on link loss
//   - bounded line queue, TX chunking to MTU - 3
//   - STATUS JSON: shape, screen codes, scan progress only on SCAN, <= 180 bytes whatever the note
//   - the 5-minute radio idle timer (incl. millis() wrap)
//   - the SMP outcome rule: a new bond only with MITM + the user's confirmation on the device
//   - Fsm: radio-free menu unchanged (3 items), RIPAR_BLE menu (5 items, BACK last), BlePair keys / stale presses /
//     timeout, BleOn needs the full review + pulse + SIGN like a signature
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "ble_proto.h"
#include "check.h"
#include "fsm.h"

using namespace ripar;
using namespace ripar::blep;

namespace {

std::vector<std::string> feed(LineAssembler& a, const std::string& s) {
  std::vector<std::string> out;
  a.push(reinterpret_cast<const uint8_t*>(s.data()), s.size(), out);
  return out;
}

FsmIn in(Key k, uint32_t now, bool passed = false, bool down = false) {
  FsmIn i;
  i.key = k;
  i.nowMs = now;
  i.pulsePassed = passed;
  i.keyDown = down;
  return i;
}

void test_uuid_name() {
  CHECK_SECTION("uuids + name");
  uint8_t u[16];
  CHECK(uuid128_le(kServiceUuid, u));
  // 52495041-5200-4c49-4e4b-000000000001, least significant byte first
  CHECK_EQ_HEX(u, 16, "0100000000004b4e494c005241504952");
  CHECK(uuid128_le(kRxUuid, u));
  CHECK_EQ(int(u[0]), 2);
  CHECK(uuid128_le(kTxUuid, u));
  CHECK_EQ(int(u[0]), 3);
  CHECK(uuid128_le(kStatusUuid, u));
  CHECK_EQ(int(u[0]), 4);
  CHECK_EQ_HEX(u + 1, 15, "00000000004b4e494c005241504952");
  CHECK(uuid128_le("52495041-5200-4C49-4E4B-000000000001", u));  // upper case accepted
  CHECK(!uuid128_le("52495041-5200-4c49-4e4b-00000000001", u));  // short
  CHECK(!uuid128_le("52495041x5200-4c49-4e4b-000000000001", u));
  CHECK(!uuid128_le("52495041-5200-4c49-4e4b-00000000000g", u));
  CHECK(!uuid128_le(nullptr, u));
  CHECK_EQ(adv_name(0), std::string("RIPAR-0000"));
  CHECK_EQ(adv_name(0xab1f), std::string("RIPAR-AB1F"));
  CHECK_EQ(adv_name(0xffff).size(), size_t(10));
  CHECK_EQ(int(kLocalMtu), 247);
}

void test_lines() {
  CHECK_SECTION("rx line reassembly");
  LineAssembler a;
  std::vector<std::string> o = feed(a, "UR:RIPAR-COSIGN-REQ/1-3/LPAD");
  CHECK_EQ(o.size(), size_t(0));
  CHECK_EQ(a.pending(), size_t(28));
  o = feed(a, "AXLF\nUR:X/Y\r\nUR:");
  CHECK_EQ(o.size(), size_t(2));
  CHECK_EQ(o[0], std::string("UR:RIPAR-COSIGN-REQ/1-3/LPADAXLF"));
  CHECK_EQ(o[1], std::string("UR:X/Y"));  // CR LF
  o = feed(a, "A\n\n\r\n\n");
  CHECK_EQ(o.size(), size_t(1));  // empty lines skipped
  CHECK_EQ(o[0], std::string("UR:A"));

  // byte by byte gives the same lines
  const std::string stream = "UR:ONE\nUR:TWO/1-2/AB\nUR:TWO/2-2/CD\n";
  LineAssembler b;
  std::vector<std::string> all;
  for (char c : stream) b.push(reinterpret_cast<const uint8_t*>(&c), 1, all);
  CHECK_EQ(all.size(), size_t(3));
  CHECK_EQ(all[2], std::string("UR:TWO/2-2/CD"));

  // exactly 4096 bytes is kept, 4097 is dropped whole, and the stream recovers at the next '\n'
  LineAssembler c;
  std::string ok(kMaxLine, 'A');
  o = feed(c, ok + "\n");
  CHECK_EQ(o.size(), size_t(1));
  CHECK_EQ(o[0].size(), kMaxLine);
  CHECK_EQ(c.dropped(), 0u);
  std::string big(kMaxLine + 1, 'B');
  o = feed(c, big.substr(0, 1000));
  o = feed(c, big.substr(1000) + "TAIL-OF-THE-LONG-LINE\nUR:NEXT\n");
  CHECK_EQ(o.size(), size_t(1));
  CHECK_EQ(o[0], std::string("UR:NEXT"));
  CHECK_EQ(c.dropped(), 1u);
  CHECK_EQ(c.pending(), size_t(0));
  // a 4096-byte line + CR counts the CR: dropped
  o = feed(c, std::string(kMaxLine, 'C') + "\r\n");
  CHECK_EQ(o.size(), size_t(0));
  CHECK_EQ(c.dropped(), 2u);

  // reset (link lost) drops a partial line
  feed(c, "UR:PARTIAL");
  c.reset();
  o = feed(c, "UR:FRESH\n");
  CHECK_EQ(o.size(), size_t(1));
  CHECK_EQ(o[0], std::string("UR:FRESH"));
  // reset in the middle of an overlong line: the next line is accepted again
  feed(c, std::string(kMaxLine + 10, 'D'));
  c.reset();
  o = feed(c, "UR:AFTER\n");
  CHECK_EQ(o.size(), size_t(1));
}

void test_queue_chunks() {
  CHECK_SECTION("line queue + tx chunks");
  LineQueue q(3, 10);
  CHECK(q.push("AAAA"));
  CHECK(q.push("BBBB"));
  CHECK(!q.push("CCCC"));  // 12 bytes > 10
  CHECK(q.push("DD"));
  CHECK(!q.push("E"));     // 3 lines
  CHECK_EQ(q.dropped(), 2u);
  std::string s;
  CHECK(q.pop(s));
  CHECK_EQ(s, std::string("AAAA"));
  CHECK(q.push("EEEE"));  // room again
  CHECK(q.pop(s) && s == "BBBB");
  CHECK(q.pop(s) && s == "DD");
  CHECK(q.pop(s) && s == "EEEE");
  CHECK(!q.pop(s));
  q.push("X");
  q.clear();
  CHECK_EQ(q.size(), size_t(0));
  CHECK(q.push("0123456789"));

  const std::string ur = std::string("UR:RIPAR-COSIGN/") + std::string(600, 'Q') + "\n";
  std::vector<std::string> ch = chunk_for_mtu(ur, 247);
  CHECK_EQ(ch.size(), size_t(3));  // 617 bytes / 244
  CHECK_EQ(ch[0].size(), size_t(244));
  CHECK_EQ(ch[2].back(), '\n');
  std::string joined;
  for (const std::string& p : ch) joined += p;
  CHECK_EQ(joined, ur);
  ch = chunk_for_mtu(ur, 23);
  CHECK_EQ(ch[0].size(), size_t(20));
  CHECK_EQ(ch.size(), size_t((ur.size() + 19) / 20));
  CHECK_EQ(chunk_for_mtu(ur, 5)[0].size(), size_t(20));    // below the BLE minimum: 23
  CHECK_EQ(chunk_for_mtu(ur, 600)[0].size(), size_t(514));  // above the ATT maximum: 517
  CHECK_EQ(chunk_for_mtu("", 247).size(), size_t(0));
}

void test_status() {
  CHECK_SECTION("status json");
  StatusInfo s;
  s.screen = Screen::Home;
  s.paired = true;
  s.k1 = "0xAbCd...1234";
  s.fw = "0011223344556677";
  CHECK_EQ(status_json(s), std::string("{\"v\":1,\"screen\":\"HOME\",\"paired\":true,\"k1\":\"0xAbCd...1234\","
                                       "\"radio\":\"on\",\"fw\":\"0011223344556677\"}"));
  s.screen = Screen::Scan;
  s.got = 2;
  s.of = 5;
  s.paired = false;
  CHECK_EQ(status_json(s), std::string("{\"v\":1,\"screen\":\"SCAN\",\"paired\":false,\"k1\":\"0xAbCd...1234\","
                                       "\"scan\":{\"got\":2,\"of\":5},\"radio\":\"on\",\"fw\":\"0011223344556677\"}"));
  s.note = "ignored: \"not\" on SCAN\\";
  const std::string j = status_json(s);
  CHECK(j.find(",\"note\":\"ignored: \\\"not\\\" on SCAN\\\\\"}") != std::string::npos);
  s.note = std::string(500, 'n');
  CHECK(status_json(s).size() <= kMaxStatus);
  CHECK(status_json(s).find("\"note\":\"nnn") != std::string::npos);
  s.note = std::string(500, '"');  // escaping doubles every character
  CHECK(status_json(s).size() <= kMaxStatus);
  CHECK_EQ(status_json(s).back(), '}');
  s.note = "caf\xc3\xa9\x01";  // non-ASCII / control -> '?'
  CHECK(status_json(s).find("\"note\":\"caf???\"") != std::string::npos);
  s.k1 = std::string(100, 'k');
  s.fw = std::string(100, 'f');
  s.got = 4000000000u;
  s.of = 4000000000u;
  s.note = std::string(300, 'z');
  CHECK(status_json(s).size() <= kMaxStatus);

  CHECK_EQ(std::string(screen_code(Screen::Home)), std::string("HOME"));
  CHECK_EQ(std::string(screen_code(Screen::HomeHold)), std::string("HOME"));
  CHECK_EQ(std::string(screen_code(Screen::Scan)), std::string("SCAN"));
  CHECK_EQ(std::string(screen_code(Screen::Review)), std::string("REVIEW"));
  CHECK_EQ(std::string(screen_code(Screen::Pulse)), std::string("PULSE"));
  CHECK_EQ(std::string(screen_code(Screen::Armed)), std::string("ARMED"));
  CHECK_EQ(std::string(screen_code(Screen::Qr)), std::string("QR"));
  CHECK_EQ(std::string(screen_code(Screen::PairQr)), std::string("QR"));
  CHECK_EQ(std::string(screen_code(Screen::Message)), std::string("MESSAGE"));
  CHECK_EQ(std::string(screen_code(Screen::Fail)), std::string("MESSAGE"));
  CHECK_EQ(std::string(screen_code(Screen::Menu)), std::string("MENU"));
  CHECK_EQ(std::string(screen_code(Screen::BlePair)), std::string("BLE_PAIR"));
}

void test_idle() {
  CHECK_SECTION("radio idle timer");
  IdleTimer t;
  CHECK(!t.expired(0));
  CHECK(!t.running());
  t.start(1000);
  CHECK(!t.expired(1000 + kIdleOffMs - 1));
  CHECK_EQ(t.remaining_ms(1000 + kIdleOffMs - 1), 1u);
  CHECK(t.expired(1000 + kIdleOffMs));
  t.touch(200000);
  CHECK(!t.expired(1000 + kIdleOffMs));
  CHECK(t.expired(200000 + kIdleOffMs));
  // millis() wrap
  t.start(0xFFFFF000u);
  CHECK(!t.expired(0x00001000u));
  CHECK(t.expired(0xFFFFF000u + kIdleOffMs));
  t.stop();
  CHECK(!t.expired(0xFFFFF000u + kIdleOffMs + 5));
  t.touch(5);  // no effect while stopped
  CHECK(!t.running());
  IdleTimer shortT(100);
  shortT.start(0);
  CHECK(shortT.expired(100));
  CHECK_EQ(shortT.remaining_ms(40), 60u);
  CHECK_EQ(kIdleOffMs, 300000u);
}

void test_auth() {
  CHECK_SECTION("smp outcome");
  const uint8_t scMitmBond = kAuthSc | kAuthMitm | kAuthBond;
  CHECK_EQ(auth_outcome(false, scMitmBond, true, true), AuthOutcome::Refuse);
  CHECK_EQ(auth_outcome(false, scMitmBond, false, false), AuthOutcome::Refuse);
  // new pairing: only with the user's confirmation on the device and MITM
  CHECK_EQ(auth_outcome(true, scMitmBond, true, true), AuthOutcome::Authenticated);
  CHECK_EQ(auth_outcome(true, scMitmBond, true, false), AuthOutcome::RemoveBond);  // e.g. passkey typed on the phone
  CHECK_EQ(auth_outcome(true, kAuthSc | kAuthBond, true, true), AuthOutcome::RemoveBond);  // Just Works
  // re-encryption with the stored bond
  CHECK_EQ(auth_outcome(true, scMitmBond, false, false), AuthOutcome::Authenticated);
  CHECK_EQ(auth_outcome(true, kAuthMitm, false, false), AuthOutcome::Authenticated);
  CHECK_EQ(auth_outcome(true, kAuthBond, false, false), AuthOutcome::Refuse);
  CHECK_EQ(auth_outcome(true, 0, false, true), AuthOutcome::Refuse);
}

// drive a fully drawn, allowed review to a SIGN
void to_sign(Fsm& f, uint32_t& now, Job job) {
  CHECK(f.open_review(job, true, ++now));
  f.review_drawn(0, 5, 5);
  CHECK_EQ(f.step(in(Key::None, ++now)), Act::None);  // key seen up
  CHECK_EQ(f.step(in(Key::Short, ++now)), Act::None);
  CHECK_EQ(f.screen(), Screen::Pulse);
  CHECK_EQ(f.step(in(Key::None, ++now, true)), Act::Redraw);
  CHECK_EQ(f.screen(), Screen::Armed);
}

void test_fsm_menu() {
  CHECK_SECTION("fsm: radio-free menu unchanged");
  uint32_t now = 1;
  Fsm a;
  CHECK_EQ(a.menu_items(), int(MENU_ITEMS));
  a.go(Screen::Menu, ++now);
  CHECK_EQ(a.step(in(Key::Short, ++now)), Act::Redraw);
  CHECK_EQ(a.step(in(Key::Short, ++now)), Act::Redraw);
  CHECK_EQ(a.menu_index(), int(MENU_BACK));
  CHECK_EQ(a.step(in(Key::Long2s, ++now)), Act::Home);
  CHECK_EQ(a.screen(), Screen::Home);

  CHECK_SECTION("fsm: RIPAR_BLE menu");
  Fsm f(Fsm::DEFAULT_TIMEOUT_MS, MENU_ITEMS_BLE);
  CHECK_EQ(f.menu_items(), 5);
  f.go(Screen::Menu, ++now);
  CHECK_EQ(f.menu_index(), int(MENU_REVOKE));
  const int expect[] = {MENU_REOPEN, MENU_BLE, MENU_FORGET, MENU_BLE_BACK, MENU_REVOKE};
  for (int e : expect) {
    CHECK_EQ(f.step(in(Key::Short, ++now)), Act::Redraw);
    CHECK_EQ(f.menu_index(), e);
  }
  for (int i = 0; i < MENU_BLE; i++) f.step(in(Key::Short, ++now));
  CHECK_EQ(f.step(in(Key::Long2s, ++now)), Act::MenuSelect);  // BLE LINK / BLE OFF: the driver decides
  CHECK_EQ(f.menu_index(), int(MENU_BLE));
  f.step(in(Key::Short, ++now));
  CHECK_EQ(f.step(in(Key::Long2s, ++now)), Act::MenuSelect);  // FORGET PHONE
  CHECK_EQ(f.menu_index(), int(MENU_FORGET));
  f.step(in(Key::Short, ++now));
  CHECK_EQ(f.step(in(Key::Long2s, ++now)), Act::Home);  // BACK is the last item
  CHECK_EQ(f.screen(), Screen::Home);
  Fsm tiny(1000, 0);  // clamped: at least one item + BACK
  CHECK_EQ(tiny.menu_items(), 2);
}

void test_fsm_ble() {
  CHECK_SECTION("fsm: BleOn = review + pulse + SIGN");
  uint32_t now = 10;
  Fsm f(Fsm::DEFAULT_TIMEOUT_MS, MENU_ITEMS_BLE);
  CHECK(job_needs_pulse(Job::BleOn));
  // not fully seen: no pulse
  CHECK(f.open_review(Job::BleOn, true, ++now));
  f.review_drawn(0, 9, 12);
  f.step(in(Key::None, ++now));
  CHECK_EQ(f.step(in(Key::Short, ++now)), Act::Redraw);  // next page, not Pulse
  CHECK_EQ(f.screen(), Screen::Review);
  // a Short while measuring never enables; a lost pulse returns to Pulse
  to_sign(f, now, Job::BleOn);
  CHECK_EQ(f.step(in(Key::Short, ++now, false)), Act::Ignored);
  CHECK_EQ(f.screen(), Screen::Pulse);
  CHECK_EQ(f.step(in(Key::None, ++now, true)), Act::Redraw);
  CHECK_EQ(f.step(in(Key::Short, ++now, true)), Act::Sign);
  CHECK_EQ(f.job(), Job::BleOn);
  // cancel on the review
  CHECK(f.open_review(Job::BleOn, true, ++now));
  f.review_drawn(0, 5, 5);
  f.step(in(Key::None, ++now));
  CHECK_EQ(f.step(in(Key::Long2s, ++now)), Act::Home);  // not a co-sign: no deny
  CHECK_EQ(f.screen(), Screen::Home);

  CHECK_SECTION("fsm: BlePair");
  CHECK(f.go(Screen::BlePair, ++now));
  CHECK_EQ(f.step(in(Key::None, ++now)), Act::None);
  CHECK_EQ(f.step(in(Key::Short, ++now)), Act::BleConfirm);
  CHECK_EQ(f.screen(), Screen::BlePair);  // the driver decides where to go
  CHECK_EQ(f.step(in(Key::Long2s, ++now, false, true)), Act::BleReject);
  CHECK_EQ(f.step(in(Key::Hold5s, ++now, false, true)), Act::None);  // never a PANIC here
  CHECK_EQ(f.screen(), Screen::BlePair);
  // re-entering the screen (a pairing code appeared) makes a press that is still down stale: it confirms nothing
  f.step(in(Key::None, ++now, false, true));  // key down
  CHECK(f.go(Screen::BlePair, ++now));
  CHECK_EQ(f.step(in(Key::Short, ++now, false, false)), Act::Ignored);  // began before the code was shown
  CHECK_EQ(f.step(in(Key::Short, ++now, false, false)), Act::BleConfirm);  // a new press counts
  // timeout closes the window like every other screen
  const uint32_t t0 = ++now;
  CHECK(f.go(Screen::BlePair, t0));
  CHECK_EQ(f.step(in(Key::None, t0 + Fsm::DEFAULT_TIMEOUT_MS - 1)), Act::None);
  CHECK_EQ(f.step(in(Key::None, t0 + Fsm::DEFAULT_TIMEOUT_MS)), Act::Timeout);
  CHECK_EQ(f.screen(), Screen::Home);
  // Fail is terminal: no pairing window
  f.fail();
  CHECK(!f.go(Screen::BlePair, ++now));
  CHECK_EQ(f.screen(), Screen::Fail);
}

}  // namespace

int main() {
  test_uuid_name();
  test_lines();
  test_queue_chunks();
  test_status();
  test_idle();
  test_auth();
  test_fsm_menu();
  test_fsm_ble();
  return CHECK_SUMMARY();
}
