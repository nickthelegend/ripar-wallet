// DEPS: fsm
// Host tests for the signer's screen state machine (src/fsm.cpp, security review B1 + M2):
//   - review paging by display row: clamp / next-page helpers, and for every review size and screen height every row
//     is on screen before the review counts as fully seen (M2); SIGN cannot be armed before that
//   - the pulse + SIGN gate: Act::Sign only on Armed, for a Short in the same pass as pulsePassed; a Short pressed
//     while measuring, a lost pulse, a refused or unseen review never sign
//   - Deny (Long2s on a co-sign review, no pulse) and Panic (only a hold that began on Home and went through the
//     HomeHold warning; Long2s acted on at release)
//   - a key event belongs to the screen its press began on (review conformance M1 / security m1): a cancel-hold that
//     reaches 5 s on Home never panics, a hold carried into a co-sign review never denies, a SIGN press that began on
//     Pulse and is released after Armed appeared never signs
//   - 120 s timeouts back to Home (incl. millis() wrap), terminal Fail, go() cannot skip Review / Pulse / Armed
//   - a randomised run (driver model + random keys / pulse) checking the gate invariants on every pass
#include <cstdio>
#include <string>
#include <vector>

#include "check.h"
#include "fsm.h"

using namespace ripar;

namespace {

FsmIn in(Key k, uint32_t now, bool passed = false, bool down = false) {
  FsmIn i;
  i.key = k;
  i.nowMs = now;
  i.pulsePassed = passed;
  i.keyDown = down;
  return i;
}

// what ui_review does with a row request: clamp, then draw min(visible, total - first) rows
void draw(Fsm& f, int visible, int total, std::vector<int>* seen = nullptr) {
  const int first = review_clamp_first(f.review_row(), visible, total);
  const int shown = total - first < visible ? total - first : visible;
  if (seen)
    for (int r = first; r < first + shown; r++) (*seen)[size_t(r)]++;
  f.review_drawn(first, shown, total);
}

// opens a review and pages to its end (returns the number of Short presses used)
int read_all(Fsm& f, Job job, bool ok, uint32_t& now, int visible = 9, int total = 23) {
  f.open_review(job, ok, now);
  int presses = 0;
  draw(f, visible, total);
  while (!f.review_all_seen() && presses < 1000) {
    now += 10;
    if (f.step(in(Key::Short, now)) != Act::Redraw) break;
    presses++;
    draw(f, visible, total);
  }
  return presses;
}

uint32_t g_rng = 12345;
uint32_t rnd() {
  g_rng = g_rng * 1103515245u + 12345u;
  return (g_rng >> 8) & 0xFFFFFF;
}

}  // namespace

int main() {
  // ------------------------------------------------------------------------------------------------------------------
  CHECK_SECTION("review paging helpers (M2)");
  CHECK_EQ(review_clamp_first(0, 9, 5), 0);
  CHECK_EQ(review_clamp_first(3, 9, 5), 0);   // everything fits: always from the top
  CHECK_EQ(review_clamp_first(8, 9, 23), 8);
  CHECK_EQ(review_clamp_first(16, 9, 23), 14);  // last page is a full screen ending at the last row
  CHECK_EQ(review_clamp_first(-4, 9, 23), 0);
  CHECK_EQ(review_clamp_first(5, 0, 3), 2);     // visible < 1 treated as 1
  CHECK_EQ(review_clamp_first(0, 9, 0), 0);
  CHECK_EQ(review_next_first(0, 9), 8);         // one row of overlap
  CHECK_EQ(review_next_first(14, 9), 22);
  CHECK_EQ(review_next_first(3, 1), 4);         // never fewer than one row
  CHECK_EQ(review_next_first(3, 0), 4);

  // ------------------------------------------------------------------------------------------------------------------
  CHECK_SECTION("every row is drawn before the review counts as seen (all sizes)");
  {
    bool allOk = true, neverEarly = true, pressesOk = true;
    int cases = 0;
    for (int visible = 1; visible <= 12; visible++) {
      for (int total = 0; total <= 70; total++) {
        Fsm f;
        uint32_t now = 1000;
        f.open_review(Job::Cosign, true, now);
        std::vector<int> seen(size_t(total) + 1, 0);
        draw(f, visible, total, &seen);
        int presses = 0;
        while (!f.review_all_seen() && presses < 200) {
          now += 10;
          const Act a = f.step(in(Key::Short, now));
          if (a != Act::Redraw || f.screen() != Screen::Review) neverEarly = false;
          presses++;
          draw(f, visible, total, &seen);
        }
        for (int r = 0; r < total; r++)
          if (seen[size_t(r)] == 0) allOk = false;
        const int step = visible > 1 ? visible - 1 : 1;
        const int need = total <= visible ? 0 : (total - visible + step - 1) / step;
        if (presses != need) pressesOk = false;
        cases++;
      }
    }
    CHECK(allOk);
    CHECK(neverEarly);
    CHECK(pressesOk);
    CHECK_EQ(cases, 12 * 71);
  }
  {
    Fsm f;  // a draw that jumps ahead (not from the top) does not count
    f.open_review(Job::Cosign, true, 0);
    f.review_drawn(14, 9, 23);
    CHECK(!f.review_all_seen());
    f.review_drawn(0, 9, 23);
    CHECK(!f.review_all_seen());
    f.review_drawn(8, 9, 23);
    CHECK(!f.review_all_seen());
    f.review_drawn(14, 9, 23);
    CHECK(f.review_all_seen());
    CHECK_EQ(f.review_row(), 14);
  }
  {
    Fsm f;  // bad reports are ignored
    f.open_review(Job::Cosign, true, 0);
    f.review_drawn(-1, 9, 5);
    f.review_drawn(0, -3, 5);
    CHECK(!f.review_all_seen());
    CHECK_EQ(f.step(in(Key::Short, 5)), Act::Ignored);  // nothing drawn yet: a Short does nothing
    CHECK_EQ(f.screen(), Screen::Review);
  }
  {
    Fsm f;  // review_drawn outside Review is ignored
    f.go(Screen::Qr, 0);
    f.review_drawn(0, 9, 9);
    CHECK(!f.review_all_seen());
  }

  // ------------------------------------------------------------------------------------------------------------------
  CHECK_SECTION("co-sign happy path: Home -> Scan -> Review -> Pulse -> Armed -> Sign");
  {
    Fsm f;
    uint32_t now = 100;
    CHECK_EQ(f.screen(), Screen::Home);
    CHECK_EQ(f.step(in(Key::Short, now)), Act::None);
    CHECK_EQ(f.screen(), Screen::Scan);
    CHECK(f.open_review(Job::Cosign, true, now));
    CHECK_EQ(f.screen(), Screen::Review);
    CHECK_EQ(f.job(), Job::Cosign);
    draw(f, 9, 23);
    CHECK(!f.review_all_seen());
    now += 10;
    CHECK_EQ(f.step(in(Key::Short, now)), Act::Redraw);  // page 2
    CHECK_EQ(f.screen(), Screen::Review);
    draw(f, 9, 23);
    now += 10;
    CHECK_EQ(f.step(in(Key::Short, now)), Act::Redraw);  // page 3 (last)
    draw(f, 9, 23);
    CHECK(f.review_all_seen());
    now += 10;
    CHECK_EQ(f.step(in(Key::None, now, true)), Act::None);  // pulse "passed" on Review is not read
    CHECK_EQ(f.screen(), Screen::Review);
    CHECK_EQ(f.step(in(Key::Short, now)), Act::None);
    CHECK_EQ(f.screen(), Screen::Pulse);
    // measuring: presses are ignored, never sign
    CHECK_EQ(f.step(in(Key::Short, now + 1, false)), Act::Ignored);
    CHECK_EQ(f.screen(), Screen::Pulse);
    CHECK_EQ(f.step(in(Key::None, now + 2, false)), Act::None);
    // passed in the same pass as a Short: arms, but that press is ignored (it was made before SIGN was armed)
    CHECK_EQ(f.step(in(Key::Short, now + 3, true)), Act::Ignored);
    CHECK_EQ(f.screen(), Screen::Armed);
    // armed, pulse lost in the pass of the press: back to Pulse, no signature
    CHECK_EQ(f.step(in(Key::Short, now + 4, false)), Act::Ignored);
    CHECK_EQ(f.screen(), Screen::Pulse);
    CHECK_EQ(f.step(in(Key::None, now + 5, true)), Act::Redraw);
    CHECK_EQ(f.screen(), Screen::Armed);
    CHECK_EQ(f.step(in(Key::None, now + 6, true)), Act::None);  // no key: nothing
    CHECK_EQ(f.step(in(Key::Hold5s, now + 7, true)), Act::None);  // Hold5s is not SIGN
    CHECK_EQ(f.screen(), Screen::Armed);
    CHECK_EQ(f.step(in(Key::Short, now + 8, true)), Act::Sign);
    CHECK_EQ(f.screen(), Screen::Armed);  // the driver moves on after signing
    CHECK(f.go(Screen::Qr, now + 9));
    CHECK_EQ(f.job(), Job::None);  // the review is gone with the QR
    CHECK(!f.review_ok());
    CHECK_EQ(f.step(in(Key::Short, now + 10)), Act::Home);
    CHECK_EQ(f.screen(), Screen::Home);
  }
  {
    Fsm f;  // armed, lost pulse without a key: back to Pulse (redraw)
    uint32_t now = 0;
    read_all(f, Job::Mandate, true, now);
    f.step(in(Key::Short, ++now));
    CHECK_EQ(f.screen(), Screen::Pulse);
    f.step(in(Key::None, ++now, true));
    CHECK_EQ(f.screen(), Screen::Armed);
    CHECK_EQ(f.step(in(Key::None, ++now, false)), Act::Redraw);
    CHECK_EQ(f.screen(), Screen::Pulse);
    CHECK_EQ(f.step(in(Key::Long2s, ++now, true)), Act::Home);  // cancel while measuring
    CHECK_EQ(f.screen(), Screen::Home);
  }
  {
    Fsm f;  // cancel while armed
    uint32_t now = 0;
    read_all(f, Job::Privy, true, now);
    f.step(in(Key::Short, ++now));
    f.step(in(Key::None, ++now, true));
    CHECK_EQ(f.screen(), Screen::Armed);
    CHECK_EQ(f.step(in(Key::Long2s, ++now, true)), Act::Home);
    CHECK_EQ(f.screen(), Screen::Home);
    CHECK_EQ(f.job(), Job::None);
  }
  {
    Fsm f;  // every pulse job signs through the same gate
    const Job jobs[] = {Job::Pair, Job::Cosign, Job::Mandate, Job::Privy, Job::Revoke, Job::Reopen};
    bool ok = true;
    for (Job j : jobs) {
      uint32_t now = 0;
      f.go(Screen::Home, now);
      read_all(f, j, true, now, 9, 4);
      ok = ok && f.step(in(Key::Short, ++now)) == Act::None && f.screen() == Screen::Pulse;
      ok = ok && f.step(in(Key::Short, ++now, false)) == Act::Ignored;
      ok = ok && f.step(in(Key::None, ++now, true)) == Act::Redraw && f.screen() == Screen::Armed;
      ok = ok && f.step(in(Key::Short, ++now, true)) == Act::Sign;
      ok = ok && job_needs_pulse(j);
    }
    CHECK(ok);
    CHECK(!job_needs_pulse(Job::Deny));
    CHECK(!job_needs_pulse(Job::None));
  }

  // ------------------------------------------------------------------------------------------------------------------
  CHECK_SECTION("refused / unseen reviews never arm");
  {
    Fsm f;
    uint32_t now = 0;
    read_all(f, Job::Mandate, false, now);
    CHECK(f.review_all_seen());
    CHECK(!f.review_ok());
    CHECK_EQ(f.step(in(Key::None, ++now, true)), Act::None);
    CHECK_EQ(f.step(in(Key::Short, ++now, true)), Act::Home);  // refused: Short leaves
    CHECK_EQ(f.screen(), Screen::Home);
  }
  {
    Fsm f;  // refused co-sign: Long2s still files a deny (can only restrict)
    uint32_t now = 0;
    read_all(f, Job::Cosign, false, now);
    CHECK_EQ(f.step(in(Key::Long2s, ++now)), Act::Deny);
    CHECK_EQ(f.screen(), Screen::Review);
  }
  {
    Fsm f;  // Long2s before the end of a co-sign review is also a deny; on other reviews it cancels
    uint32_t now = 0;
    f.open_review(Job::Cosign, true, now);
    draw(f, 9, 40);
    CHECK_EQ(f.step(in(Key::Long2s, ++now)), Act::Deny);
    f.open_review(Job::Pair, true, now);
    draw(f, 9, 40);
    CHECK_EQ(f.step(in(Key::Long2s, ++now)), Act::Home);
    CHECK_EQ(f.screen(), Screen::Home);
  }
  {
    Fsm f;  // unseen rows: every Short pages, none reaches Pulse
    uint32_t now = 0;
    f.open_review(Job::Cosign, true, now);
    draw(f, 9, 200);
    bool ok = true;
    for (int i = 0; i < 20; i++) {
      ok = ok && f.step(in(Key::Short, ++now, true)) == Act::Redraw && f.screen() == Screen::Review;
      draw(f, 9, 200);
    }
    CHECK(ok);
    CHECK(!f.review_all_seen());
    CHECK_EQ(f.review_row(), 20 * 8);
  }
  {
    Fsm f;  // go() cannot skip the review / pulse steps
    CHECK(!f.go(Screen::Pulse, 0));
    CHECK(!f.go(Screen::Armed, 0));
    CHECK(!f.go(Screen::Review, 0));
    CHECK(!f.go(Screen::Fail, 0));
    CHECK_EQ(f.screen(), Screen::Home);
    CHECK(!f.open_review(Job::None, true, 0));
    CHECK_EQ(f.screen(), Screen::Home);
    CHECK(f.go(Screen::Message, 0));
    CHECK_EQ(f.step(in(Key::Long2s, 1)), Act::Home);
  }
  {
    Fsm f;  // a new review starts unseen, even after a fully seen one
    uint32_t now = 0;
    read_all(f, Job::Cosign, true, now);
    CHECK(f.review_all_seen());
    f.open_review(Job::Cosign, true, now);
    CHECK(!f.review_all_seen());
    CHECK_EQ(f.review_row(), 0);
    CHECK_EQ(f.step(in(Key::Short, ++now)), Act::Ignored);  // not drawn yet
  }

  // ------------------------------------------------------------------------------------------------------------------
  CHECK_SECTION("deny review: no pulse, Short signs once seen + allowed");
  {
    Fsm f;
    uint32_t now = 0;
    f.open_review(Job::Deny, true, now);
    draw(f, 9, 12);
    CHECK_EQ(f.step(in(Key::Short, ++now)), Act::Redraw);  // not all seen yet
    draw(f, 9, 12);
    CHECK(f.review_all_seen());
    CHECK_EQ(f.step(in(Key::Short, ++now)), Act::SignNoPulse);
    CHECK_EQ(f.screen(), Screen::Review);
    CHECK_EQ(f.step(in(Key::Long2s, ++now)), Act::Home);  // Long2s on a deny review cancels (no nested deny)
  }
  {
    Fsm f;
    uint32_t now = 0;
    read_all(f, Job::Deny, false, now, 9, 5);
    CHECK_EQ(f.step(in(Key::Short, ++now)), Act::Home);  // refused deny: no signature
    f.open_review(Job::Deny, true, now);
    draw(f, 9, 5);
    CHECK_EQ(f.step(in(Key::Hold5s, ++now)), Act::None);  // the tail of the 5 s hold that opened it
    CHECK_EQ(f.screen(), Screen::Review);
  }

  // ------------------------------------------------------------------------------------------------------------------
  CHECK_SECTION("home: pairing QR on release, PANIC at 5 s");
  {
    Fsm f;
    uint32_t now = 0;
    CHECK_EQ(f.step(in(Key::Long2s, ++now, false, true)), Act::Redraw);
    CHECK_EQ(f.screen(), Screen::HomeHold);
    CHECK_EQ(f.step(in(Key::None, ++now, false, true)), Act::None);  // still held
    CHECK_EQ(f.step(in(Key::Hold5s, ++now, false, true)), Act::Panic);
    CHECK_EQ(f.screen(), Screen::HomeHold);  // the driver signs and moves on
    CHECK(f.go(Screen::Qr, ++now));
    CHECK_EQ(f.step(in(Key::None, ++now, false, false)), Act::None);  // the release produces nothing
    CHECK_EQ(f.screen(), Screen::Qr);
  }
  {
    Fsm f;
    uint32_t now = 0;
    f.step(in(Key::Long2s, ++now, false, true));
    CHECK_EQ(f.step(in(Key::None, ++now, false, false)), Act::PairQr);  // released between 2 and 5 s
    CHECK_EQ(f.screen(), Screen::PairQr);
    CHECK_EQ(f.step(in(Key::Hold5s, ++now)), Act::None);  // no panic from the pairing QR
    CHECK_EQ(f.step(in(Key::Long2s, ++now)), Act::Redraw);
    CHECK_EQ(f.screen(), Screen::Menu);
    CHECK_EQ(f.menu_index(), int(MENU_REVOKE));
    CHECK_EQ(f.step(in(Key::Long2s, ++now)), Act::MenuSelect);
    CHECK_EQ(f.step(in(Key::Short, ++now)), Act::Redraw);
    CHECK_EQ(f.menu_index(), int(MENU_REOPEN));
    CHECK_EQ(f.step(in(Key::Long2s, ++now)), Act::MenuSelect);
    CHECK_EQ(f.step(in(Key::Short, ++now)), Act::Redraw);
    CHECK_EQ(f.menu_index(), int(MENU_BACK));
    CHECK_EQ(f.step(in(Key::Short, ++now)), Act::Redraw);
    CHECK_EQ(f.menu_index(), int(MENU_REVOKE));  // wraps
    f.step(in(Key::Short, ++now));
    f.step(in(Key::Short, ++now));
    CHECK_EQ(f.step(in(Key::Long2s, ++now)), Act::Home);  // BACK
    CHECK_EQ(f.screen(), Screen::Home);
    f.go(Screen::Menu, ++now);
    CHECK_EQ(f.menu_index(), int(MENU_REVOKE));  // menu starts at the top every time
  }
  {
    Fsm f;  // pairing QR: Short = home
    f.step(in(Key::Long2s, 1, false, true));
    f.step(in(Key::None, 2, false, false));
    CHECK_EQ(f.step(in(Key::Short, 3)), Act::Home);
    CHECK_EQ(f.screen(), Screen::Home);
  }
  {
    Fsm f;  // Hold5s straight on Home (its Long2s was lost): no PANIC without the HomeHold warning screen
    CHECK_EQ(f.step(in(Key::Hold5s, 1, false, true)), Act::None);
    CHECK_EQ(f.screen(), Screen::Home);
    // Hold5s anywhere else never panics
    const Screen others[] = {Screen::Scan, Screen::Qr, Screen::Message, Screen::PairQr, Screen::Menu};
    bool ok = true;
    for (Screen s : others) {
      f.go(s, 10);
      ok = ok && f.step(in(Key::Hold5s, 11, true, true)) != Act::Panic;
    }
    uint32_t now = 20;
    f.step(in(Key::None, now));  // released before the next request is scanned
    read_all(f, Job::Cosign, true, now);
    ok = ok && f.step(in(Key::Hold5s, ++now, true, true)) == Act::None;
    f.step(in(Key::Short, ++now));
    ok = ok && f.screen() == Screen::Pulse && f.step(in(Key::Hold5s, ++now, false, true)) == Act::None;
    f.step(in(Key::None, ++now, true));
    ok = ok && f.screen() == Screen::Armed && f.step(in(Key::Hold5s, ++now, true, true)) == Act::None;
    CHECK(ok);
  }
  {
    Fsm f;  // Home Short -> Scan; Long2s cancels the scan; Short while scanning does nothing
    CHECK_EQ(f.step(in(Key::Short, 1)), Act::None);
    CHECK_EQ(f.screen(), Screen::Scan);
    CHECK_EQ(f.step(in(Key::Short, 2)), Act::None);
    CHECK_EQ(f.screen(), Screen::Scan);
    CHECK_EQ(f.step(in(Key::Long2s, 3)), Act::Home);
    CHECK_EQ(f.screen(), Screen::Home);
  }

  // ------------------------------------------------------------------------------------------------------------------
  CHECK_SECTION("a key event belongs to the screen its press began on (review M1 / m1)");
  {
    // review probe: a hold that cancels a screen at 2 s and goes on to 5 s ended in Act::Panic on Home
    bool ok = true;
    const Screen from[] = {Screen::Scan, Screen::Qr, Screen::Message, Screen::PairQr};
    for (Screen s : from) {
      Fsm f;
      uint32_t now = 0;
      f.go(s, ++now);
      f.step(in(Key::None, ++now, false, false));
      const Act cancel = f.step(in(Key::Long2s, now += 2000, false, true));  // PairQr: -> Menu, others: -> Home
      ok = ok && (cancel == Act::Home || (s == Screen::PairQr && cancel == Act::Redraw));
      ok = ok && f.step(in(Key::None, ++now, false, true)) == Act::None;
      ok = ok && f.step(in(Key::Hold5s, now += 3000, false, true)) == Act::None;
      ok = ok && (f.screen() == Screen::Home || f.screen() == Screen::Menu);
      if (!ok) std::printf("     from screen %d: screen now %d\n", int(s), int(f.screen()));
    }
    CHECK(ok);
  }
  {
    // ... also from a review (cancel), from Pulse / Armed (cancel) and from Menu -> BACK
    bool ok = true;
    for (int which = 0; which < 4; which++) {
      Fsm f;
      uint32_t now = 0;
      read_all(f, Job::Mandate, true, now);
      if (which == 1 || which == 2) f.step(in(Key::Short, ++now));  // -> Pulse
      if (which == 2) f.step(in(Key::None, ++now, true));             // -> Armed
      if (which == 3) {
        f.go(Screen::Menu, ++now);
        f.step(in(Key::Short, ++now));
        f.step(in(Key::Short, ++now));  // BACK
      }
      const Act cancel = f.step(in(Key::Long2s, now += 2000, which == 2, true));
      ok = ok && cancel == Act::Home && f.screen() == Screen::Home;
      ok = ok && f.step(in(Key::Hold5s, now += 3000, false, true)) == Act::None && f.screen() == Screen::Home;
      ok = ok && f.step(in(Key::None, ++now, false, false)) == Act::None;  // released: nothing
      // a NEW hold on Home still goes through the warning to PANIC
      ok = ok && f.step(in(Key::Long2s, now += 2000, false, true)) == Act::Redraw && f.screen() == Screen::HomeHold;
      ok = ok && f.step(in(Key::Hold5s, now += 3000, false, true)) == Act::Panic;
      if (!ok) std::printf("     case %d failed\n", which);
    }
    CHECK(ok);
  }
  {
    Fsm f;  // review probe: a SIGN press that began while measuring and was released after arming signed
    uint32_t now = 0;
    read_all(f, Job::Cosign, true, now);
    f.step(in(Key::Short, ++now));
    CHECK_EQ(f.screen(), Screen::Pulse);
    f.step(in(Key::None, ++now, false, false));
    f.step(in(Key::None, ++now, false, true));  // the key goes down on Pulse
    CHECK_EQ(f.step(in(Key::None, ++now, true, true)), Act::Redraw);  // -> Armed while it is down
    CHECK_EQ(f.screen(), Screen::Armed);
    CHECK_EQ(f.step(in(Key::Short, now += 300, true, false)), Act::Ignored);  // released after arming: no signature
    CHECK_EQ(f.screen(), Screen::Armed);
    CHECK_EQ(f.step(in(Key::Short, now += 300, true, false)), Act::Sign);  // a fresh press signs
  }
  {
    Fsm f;  // the same while re-arming after the pulse was lost
    uint32_t now = 0;
    read_all(f, Job::Pair, true, now);
    f.step(in(Key::Short, ++now));
    f.step(in(Key::None, ++now, true));
    CHECK_EQ(f.screen(), Screen::Armed);
    f.step(in(Key::None, ++now, false, true));  // pulse lost while the key is down -> Pulse
    CHECK_EQ(f.screen(), Screen::Pulse);
    f.step(in(Key::None, ++now, true, true));  // -> Armed, key still down
    CHECK_EQ(f.screen(), Screen::Armed);
    CHECK_EQ(f.step(in(Key::Short, ++now, true, false)), Act::Ignored);
    CHECK_EQ(f.step(in(Key::Short, ++now, true, false)), Act::Sign);
  }
  {
    Fsm f;  // a press made while scanning, held into the co-sign review that the scan opened: no deny, no paging
    uint32_t now = 0;
    f.step(in(Key::Short, ++now));
    CHECK_EQ(f.screen(), Screen::Scan);
    f.step(in(Key::None, ++now, false, true));  // key down on Scan
    f.open_review(Job::Cosign, true, ++now);    // the request completed meanwhile
    draw(f, 9, 30);
    CHECK_EQ(f.step(in(Key::Long2s, now += 2000, false, true)), Act::None);  // the same hold: not a deny
    CHECK_EQ(f.screen(), Screen::Review);
    CHECK_EQ(f.step(in(Key::Hold5s, now += 3000, false, true)), Act::None);
    CHECK_EQ(f.step(in(Key::None, ++now, false, false)), Act::None);  // released
    CHECK_EQ(f.step(in(Key::Long2s, now += 2000, false, true)), Act::Deny);  // a new hold on the review denies
    Fsm g;  // a short press that straddles the change: Ignored on the review, no page turn
    now = 0;
    g.step(in(Key::Short, ++now));
    g.step(in(Key::None, ++now, false, true));
    g.open_review(Job::Cosign, true, ++now);
    draw(g, 9, 30);
    CHECK_EQ(g.step(in(Key::Short, ++now, false, false)), Act::Ignored);
    CHECK_EQ(g.review_row(), 0);
    CHECK_EQ(g.step(in(Key::Short, ++now, false, false)), Act::Redraw);  // the next press pages
  }
  {
    Fsm f;  // the deny review opened by a Long2s: the tail of that hold does nothing, a new press signs it
    uint32_t now = 0;
    read_all(f, Job::Cosign, true, now);
    CHECK_EQ(f.step(in(Key::Long2s, ++now, false, true)), Act::Deny);
    f.open_review(Job::Deny, true, now);
    draw(f, 9, 5);
    CHECK_EQ(f.step(in(Key::Hold5s, now += 3000, false, true)), Act::None);
    CHECK_EQ(f.step(in(Key::Short, ++now, false, false)), Act::Ignored);  // (cannot happen physically) still stale
    CHECK_EQ(f.step(in(Key::Short, ++now, false, false)), Act::SignNoPulse);
  }

  // ------------------------------------------------------------------------------------------------------------------
  CHECK_SECTION("timeouts (120 s, millis() wrap) + terminal Fail");
  {
    Fsm f;
    CHECK_EQ(Fsm::DEFAULT_TIMEOUT_MS, 120000u);
    const uint32_t t0 = 0xFFFFFFFFu - 50000u;  // wraps during the wait
    f.go(Screen::Scan, t0);
    CHECK_EQ(f.step(in(Key::None, t0 + 119999u)), Act::None);
    CHECK_EQ(f.screen(), Screen::Scan);
    CHECK_EQ(f.step(in(Key::None, t0 + 120000u)), Act::Timeout);
    CHECK_EQ(f.screen(), Screen::Home);
    CHECK_EQ(f.step(in(Key::None, t0 + 999999u)), Act::None);  // Home never times out
    CHECK_EQ(f.screen(), Screen::Home);
  }
  {
    Fsm f;  // a key press or touch() postpones the timeout
    uint32_t now = 1000;
    f.open_review(Job::Cosign, true, now);
    draw(f, 9, 40);
    CHECK_EQ(f.step(in(Key::Short, now + 100000)), Act::Redraw);
    draw(f, 9, 40);
    CHECK_EQ(f.step(in(Key::None, now + 219999)), Act::None);
    CHECK_EQ(f.screen(), Screen::Review);
    CHECK_EQ(f.step(in(Key::None, now + 220000)), Act::Timeout);
    CHECK_EQ(f.job(), Job::None);
    f.go(Screen::Scan, 0);
    f.touch(100000);
    CHECK_EQ(f.step(in(Key::None, 219999)), Act::None);
    CHECK_EQ(f.step(in(Key::None, 220000)), Act::Timeout);
  }
  {
    Fsm f(5000);  // Armed times out too (thumb on the sensor, nobody presses)
    uint32_t now = 0;
    read_all(f, Job::Cosign, true, now);
    f.step(in(Key::Short, ++now));
    f.step(in(Key::None, ++now, true));
    CHECK_EQ(f.screen(), Screen::Armed);
    CHECK_EQ(f.step(in(Key::None, now + 5000, true)), Act::Timeout);
    CHECK_EQ(f.screen(), Screen::Home);
  }
  {
    Fsm f;
    f.fail();
    CHECK_EQ(f.screen(), Screen::Fail);
    const Key keys[] = {Key::None, Key::Short, Key::Long2s, Key::Hold5s};
    bool ok = true;
    for (Key k : keys)
      for (int p = 0; p < 2; p++) ok = ok && f.step(in(k, 999999u * uint32_t(p + 1), p == 1, true)) == Act::None;
    CHECK(ok);
    CHECK(!f.go(Screen::Home, 1));
    CHECK(!f.open_review(Job::Cosign, true, 1));
    CHECK_EQ(f.screen(), Screen::Fail);
  }

  // ------------------------------------------------------------------------------------------------------------------
  CHECK_SECTION("randomised run: gate invariants on every pass");
  {
    Fsm f(3000);
    uint32_t now = 0;
    int total = 20, visible = 9;
    long signs = 0, noPulseSigns = 0, panics = 0, denies = 0, stales = 0, bad = 0;
    bool mUp = true;  // model of the key rule: the key was seen up since the last screen change
    for (int pass = 0; pass < 400000; pass++) {
      now += 1 + rnd() % 40;
      FsmIn i;
      const uint32_t r = rnd() % 100;
      i.key = r < 60 ? Key::None : r < 82 ? Key::Short : r < 94 ? Key::Long2s : Key::Hold5s;
      i.keyDown = (rnd() & 3) != 0;
      i.pulsePassed = (rnd() % 3) != 0;
      i.nowMs = now;
      const Screen before = f.screen();
      const Job job = f.job();
      const bool ok = f.review_ok(), seen = f.review_all_seen();
      const bool began = mUp || before == Screen::HomeHold;
      if (!i.keyDown) mUp = true;
      const Act a = f.step(i);
      const Screen after = f.screen();
      bool entered = after != before;
      if (i.key != Key::None && !began && before != Screen::Fail) {
        stales++;  // a press from an earlier screen: at most a beep / redraw / timeout, and only pulse-driven changes
        if (a != Act::None && a != Act::Ignored && a != Act::Redraw && a != Act::Timeout) bad++;
        if (after != before && a != Act::Timeout && !(before == Screen::Pulse && after == Screen::Armed) &&
            !(before == Screen::Armed && after == Screen::Pulse))
          bad++;
      }
      if (a == Act::Sign) {
        signs++;
        if (!(before == Screen::Armed && i.key == Key::Short && i.pulsePassed && ok && seen && job_needs_pulse(job)))
          bad++;
      }
      if (a == Act::SignNoPulse) {
        noPulseSigns++;
        if (!(before == Screen::Review && i.key == Key::Short && job == Job::Deny && ok && seen)) bad++;
      }
      if (a == Act::Panic) {
        panics++;
        if (!(before == Screen::HomeHold && i.key == Key::Hold5s)) bad++;
      }
      if (after == Screen::HomeHold && before != Screen::HomeHold &&
          !(before == Screen::Home && i.key == Key::Long2s && began))
        bad++;
      if (a == Act::Deny) {
        denies++;
        if (!(before == Screen::Review && job == Job::Cosign && i.key == Key::Long2s)) bad++;
      }
      if (after == Screen::Armed && before != Screen::Armed && !(before == Screen::Pulse && i.pulsePassed)) bad++;
      if (after == Screen::Pulse && before != Screen::Pulse && before != Screen::Armed &&
          !(before == Screen::Review && ok && seen && job_needs_pulse(job) && i.key == Key::Short))
        bad++;
      if ((after == Screen::Pulse || after == Screen::Armed) && !(f.review_ok() && f.review_all_seen())) bad++;
      // driver model
      switch (a) {
        case Act::Sign:
        case Act::SignNoPulse:
        case Act::Panic:
          entered = f.go((rnd() & 1) ? Screen::Qr : Screen::Message, now) || entered;
          break;
        case Act::Deny:
          entered = f.open_review(Job::Deny, (rnd() & 3) != 0, now) || entered;
          break;
        case Act::MenuSelect:
          entered = f.open_review((rnd() & 1) ? Job::Revoke : Job::Reopen, (rnd() & 1) != 0, now) || entered;
          break;
        default:
          break;
      }
      if (f.screen() == Screen::Scan && (rnd() % 8) == 0) {  // a request was scanned and parsed
        const Job jobs[] = {Job::Pair, Job::Cosign, Job::Mandate, Job::Deny, Job::Privy};
        total = 1 + int(rnd() % 40);
        visible = 1 + int(rnd() % 10);
        if ((rnd() % 5) == 0)
          entered = f.go(Screen::Message, now) || entered;  // parse refusal
        else
          entered = f.open_review(jobs[rnd() % 5], (rnd() % 3) != 0, now) || entered;
      }
      if (entered) mUp = !i.keyDown;
      if (f.screen() == Screen::Review && (rnd() % 4) != 0) draw(f, visible, total);
    }
    CHECK_EQ(bad, 0L);
    CHECK(signs > 100);
    CHECK(noPulseSigns > 20);
    CHECK(panics > 100);
    CHECK(denies > 100);
    CHECK(stales > 1000);
    std::printf("   random run: %ld signs, %ld deny signs, %ld panics, %ld denies, %ld stale key events\n", signs,
                noPulseSigns, panics, denies, stales);
  }

  return CHECK_SUMMARY();
}
