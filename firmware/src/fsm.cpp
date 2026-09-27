// Screen state machine of the signer (include/fsm.h). Portable C++14 (host + device), host-tested in
// test/host/test_fsm.cpp.
#include "fsm.h"

namespace ripar {

const uint32_t Fsm::DEFAULT_TIMEOUT_MS;

bool job_needs_pulse(Job j) { return j != Job::None && j != Job::Deny; }

int review_clamp_first(int first, int visible, int total) {
  if (visible < 1) visible = 1;
  int maxFirst = total - visible;
  if (maxFirst < 0) maxFirst = 0;
  if (first > maxFirst) first = maxFirst;
  if (first < 0) first = 0;
  return first;
}

int review_next_first(int firstShown, int rowsShown) {
  const int step = rowsShown > 1 ? rowsShown - 1 : 1;
  return firstShown + step;
}

void Fsm::clear_review() {
  job_ = Job::None;
  ok_ = false;
  seenAll_ = false;
  row_ = 0;
  shownFirst_ = 0;
  shownRows_ = 0;
  seenUpTo_ = 0;
  drawn_ = false;
}

void Fsm::enter(Screen s, uint32_t nowMs) {
  // the review (and with it the right to arm SIGN) only survives the Review -> Pulse <-> Armed path
  if (s != Screen::Review && s != Screen::Pulse && s != Screen::Armed) clear_review();
  if (s == Screen::Menu) menu_ = 0;
  screen_ = s;
  last_ = nowMs;
  upSinceEnter_ = !keyDown_;  // a key that is still down belongs to the previous screen
}

bool Fsm::go(Screen s, uint32_t nowMs) {
  if (screen_ == Screen::Fail) return false;
  if (s == Screen::Pulse || s == Screen::Armed || s == Screen::Review || s == Screen::Fail) return false;
  enter(s, nowMs);
  return true;
}

bool Fsm::open_review(Job job, bool ok, uint32_t nowMs) {
  if (screen_ == Screen::Fail || job == Job::None) return false;
  clear_review();
  job_ = job;
  ok_ = ok;
  enter(Screen::Review, nowMs);
  return true;
}

void Fsm::review_drawn(int firstRow, int rowsShown, int totalRows) {
  if (screen_ != Screen::Review) return;
  if (firstRow < 0 || rowsShown < 0 || totalRows < 0) return;
  drawn_ = true;
  shownFirst_ = firstRow;
  shownRows_ = rowsShown;
  row_ = firstRow;
  // rows [0, seenUpTo_) have all been on screen; a draw that starts beyond that (a jump) does not extend it
  if (firstRow <= seenUpTo_ && firstRow + rowsShown > seenUpTo_) seenUpTo_ = firstRow + rowsShown;
  if (seenUpTo_ >= totalRows) seenAll_ = true;
}

Act Fsm::step(const FsmIn& in) {
  if (screen_ == Screen::Fail) return Act::None;
  const uint32_t now = in.nowMs;
  // a press that began before this screen was entered does nothing here (HomeHold is entered BY a hold, whose
  // Hold5s must still reach it): the key must first be seen up in a pass since the screen change
  keyDown_ = in.keyDown;
  const bool pressBeganHere = upSinceEnter_ || screen_ == Screen::HomeHold;
  if (!in.keyDown) upSinceEnter_ = true;
  const bool stale = in.key != Key::None && !pressBeganHere;
  const Key k = stale ? Key::None : in.key;
  if (in.key != Key::None) last_ = now;
  if (screen_ != Screen::Home && uint32_t(now - last_) >= timeoutMs_) {
    enter(Screen::Home, now);
    return Act::Timeout;
  }
  const Act a = dispatch(k, in, now);
  return (stale && in.key == Key::Short && a == Act::None) ? Act::Ignored : a;  // error beep for a stale press
}

Act Fsm::dispatch(Key k, const FsmIn& in, uint32_t now) {
  switch (screen_) {
    case Screen::Home:
      if (k == Key::Short) {
        enter(Screen::Scan, now);
        return Act::None;
      }
      if (k == Key::Long2s) {  // decided on release (pairing QR) or at 5 s (PANIC)
        enter(Screen::HomeHold, now);
        return Act::Redraw;
      }
      return Act::None;  // Hold5s here (its Long2s was lost) never panics: PANIC only via the HomeHold warning

    case Screen::HomeHold:
      if (k == Key::Hold5s) return Act::Panic;
      if (!in.keyDown) {
        enter(Screen::PairQr, now);
        return Act::PairQr;
      }
      return Act::None;

    case Screen::Scan:
      if (k == Key::Long2s) {
        enter(Screen::Home, now);
        return Act::Home;
      }
      return Act::None;

    case Screen::Review:
      if (k == Key::Short) {
        if (!drawn_) return Act::Ignored;  // nothing on screen yet
        if (!seenAll_) {
          row_ = review_next_first(shownFirst_, shownRows_);
          return Act::Redraw;
        }
        if (!ok_) {
          enter(Screen::Home, now);
          return Act::Home;
        }
        if (job_needs_pulse(job_)) {
          enter(Screen::Pulse, now);
          return Act::None;
        }
        if (job_ == Job::Deny) return Act::SignNoPulse;
        return Act::Ignored;
      }
      if (k == Key::Long2s) {
        if (job_ == Job::Cosign) return Act::Deny;
        enter(Screen::Home, now);
        return Act::Home;
      }
      return Act::None;

    case Screen::Pulse:
      if (k == Key::Long2s) {
        enter(Screen::Home, now);
        return Act::Home;
      }
      if (in.pulsePassed && ok_ && seenAll_ && job_needs_pulse(job_)) {
        enter(Screen::Armed, now);  // a Short polled in this pass was pressed before SIGN was armed: ignored
        return k == Key::Short ? Act::Ignored : Act::Redraw;
      }
      return k == Key::Short ? Act::Ignored : Act::None;

    case Screen::Armed:
      if (k == Key::Long2s) {
        enter(Screen::Home, now);
        return Act::Home;
      }
      if (!in.pulsePassed) {  // thumb lifted / sensor stalled: back to measuring, never sign
        enter(Screen::Pulse, now);
        return k == Key::Short ? Act::Ignored : Act::Redraw;
      }
      if (k == Key::Short) {
        if (!(ok_ && seenAll_ && job_needs_pulse(job_))) {  // unreachable: Armed is only entered from such a review
          enter(Screen::Home, now);
          return Act::Home;
        }
        return Act::Sign;
      }
      return Act::None;

    case Screen::Qr:
    case Screen::Message:
      if (k == Key::Short || k == Key::Long2s) {
        enter(Screen::Home, now);
        return Act::Home;
      }
      return Act::None;

    case Screen::PairQr:
      if (k == Key::Short) {
        enter(Screen::Home, now);
        return Act::Home;
      }
      if (k == Key::Long2s) {
        enter(Screen::Menu, now);
        return Act::Redraw;
      }
      return Act::None;

    case Screen::Menu:
      if (k == Key::Short) {
        menu_ = (menu_ + 1) % menuItems_;
        return Act::Redraw;
      }
      if (k == Key::Long2s) {
        if (menu_ == menuItems_ - 1) {  // BACK
          enter(Screen::Home, now);
          return Act::Home;
        }
        return Act::MenuSelect;
      }
      return Act::None;

    case Screen::BlePair:  // the pairing window stays open until the driver leaves it (or the timeout)
      if (k == Key::Short) return Act::BleConfirm;
      if (k == Key::Long2s) return Act::BleReject;
      return Act::None;

    case Screen::Fail:
      break;
  }
  return Act::None;
}

}  // namespace ripar
