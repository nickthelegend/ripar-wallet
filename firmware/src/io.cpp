// BOOT key (GPIO0), LEDC buzzer and battery gauge.
//
// Key handling runs in a 5 ms esp_timer callback, not in io_poll_key(), so a press is not lost while the app
// thread is busy (drawing, signing). Events go into a small queue; io_poll_key() / io_poll_key_state() pop them.
// Events older than kEventMaxAgeMs are dropped at poll time, so a press made during a long stall can never approve a
// screen the user had not seen yet. The timer updates the debounced state and queues the event in ONE critical
// section, and io_poll_key_state() reads both in one, so the app never sees a release event together with a stale
// "still down" state (or the reverse).
// On every screen change the app calls io_flush(true) (before and after drawing the new screen): queued events are
// dropped AND a press that is still down is swallowed until it is released (no Short / Long2s / Hold5s from it), so a
// press can only act on a screen that was on display when it began (review conformance M1 / security m1). The one
// exception is Home -> HomeHold, entered BY a hold whose Hold5s must still arrive: io_flush(false) only clears the
// queue.
//
// Event timing (debounced, measured from the start of the press):
//   Short  : released after less than 1 s
//   Long2s : fired once while held, when the hold reaches 2 s
//   Hold5s : fired once while held, when the hold reaches 5 s  (a 5 s hold therefore yields Long2s, then Hold5s)
//   A release between 1 s and 2 s produces nothing; a release after Long2s/Hold5s produces nothing.
// GPIO0 is a strapping pin: a press that is already down at io_init() is ignored until the key is released.
//
// Buzzer: Arduino LEDC channel 4 (-> LEDC timer 2). The camera XCLK uses LEDC timer 0 / channel 0 and the LCD
// backlight uses channel 6 (-> timer 3), so none of them share a timer. Tones are sequenced by the same 5 ms
// timer, so buzz*() never blocks. The wiring doc lists an *active* 3.3 V buzzer; driving it with a 50 % PWM
// still sounds (as a modulated buzz), a passive piezo gives the real pitch.
#include <Arduino.h>

#include "board.h"
#include "device.h"
#include "esp_timer.h"

namespace ripar {
namespace {

constexpr uint32_t kTickUs = 5000;
constexpr uint32_t kDebounceMs = 30;
constexpr uint32_t kShortMaxMs = 1000;
constexpr uint32_t kLongMs = 2000;
constexpr uint32_t kHoldMs = 5000;
constexpr uint32_t kEventMaxAgeMs = 1000;
constexpr uint8_t kBuzzChannel = 4;
constexpr uint8_t kBuzzBits = 10;

portMUX_TYPE g_mux = portMUX_INITIALIZER_UNLOCKED;
esp_timer_handle_t g_timer = nullptr;

// ---- key state (timer context only, except g_stable which is read by io_key_down) ----
struct KeyEvent {
  Key key;
  uint32_t t;
};
constexpr int kQueueLen = 8;
KeyEvent g_queue[kQueueLen];
int g_qHead = 0, g_qCount = 0;  // guarded by g_mux

bool g_rawLast = false;
uint32_t g_rawSince = 0;
volatile bool g_stable = false;
bool g_armed = false;  // false while a press that began before io_init() is still down
uint32_t g_downSince = 0;
bool g_sentLong = false, g_sentHold = false;

// ---- buzzer sequence ----
struct Note {
  uint16_t hz;  // 0 = silence
  uint16_t ms;
};
constexpr int kMaxNotes = 6;
Note g_seq[kMaxNotes];
int g_seqLen = 0;          // guarded by g_mux
bool g_seqRestart = false;  // guarded by g_mux
// timer-context copy
Note g_play[kMaxNotes];
int g_playLen = 0, g_playIdx = 0;
bool g_playing = false;
uint32_t g_noteEnd = 0;

// caller holds g_mux
void push_locked(Key k, uint32_t now) {
  if (g_qCount < kQueueLen) {
    g_queue[(g_qHead + g_qCount) % kQueueLen] = KeyEvent{k, now};
    g_qCount++;
  }
}

void key_tick(uint32_t now) {
  const bool raw = digitalRead(PIN_BOOT) == LOW;  // active low, INPUT_PULLUP
  portENTER_CRITICAL(&g_mux);  // g_stable / g_armed / the queue change together (io_poll_key_state, io_flush)
  if (raw != g_rawLast) {
    g_rawLast = raw;
    g_rawSince = now;
  }
  if (raw != g_stable && (now - g_rawSince) >= kDebounceMs) {
    g_stable = raw;
    if (raw) {  // press
      g_downSince = g_rawSince;
      g_sentLong = g_sentHold = false;
    } else {  // release
      const uint32_t held = g_rawSince - g_downSince;
      if (g_armed && !g_sentLong && held < kShortMaxMs) push_locked(Key::Short, now);
      g_armed = true;
    }
  }
  if (g_stable && g_armed) {
    const uint32_t held = now - g_downSince;
    if (!g_sentLong && held >= kLongMs) {
      g_sentLong = true;
      push_locked(Key::Long2s, now);
    }
    if (!g_sentHold && held >= kHoldMs) {
      g_sentHold = true;
      push_locked(Key::Hold5s, now);
    }
  }
  portEXIT_CRITICAL(&g_mux);
}

// caller holds g_mux: the first event that is not older than kEventMaxAgeMs (stale ones are dropped)
Key pop_locked(uint32_t now) {
  while (g_qCount > 0) {
    const KeyEvent e = g_queue[g_qHead];
    g_qHead = (g_qHead + 1) % kQueueLen;
    g_qCount--;
    if (now - e.t <= kEventMaxAgeMs) return e.key;
  }
  return Key::None;
}

void start_note(const Note& n, uint32_t now) {
  if (n.hz) {
    ledcWriteTone(kBuzzChannel, n.hz);  // 50 % duty at n.hz
  } else {
    ledcWrite(kBuzzChannel, 0);
  }
  g_noteEnd = now + n.ms;
}

void buzz_tick(uint32_t now) {
  bool restart = false;
  portENTER_CRITICAL(&g_mux);
  if (g_seqRestart) {
    restart = true;
    g_seqRestart = false;
    g_playLen = g_seqLen;
    for (int i = 0; i < g_seqLen; i++) g_play[i] = g_seq[i];
  }
  portEXIT_CRITICAL(&g_mux);

  if (restart) {
    g_playIdx = 0;
    g_playing = g_playLen > 0;
    if (g_playing) {
      start_note(g_play[0], now);
    } else {
      ledcWrite(kBuzzChannel, 0);
    }
    return;
  }
  if (g_playing && int32_t(now - g_noteEnd) >= 0) {
    if (++g_playIdx < g_playLen) {
      start_note(g_play[g_playIdx], now);
    } else {
      g_playing = false;
      ledcWrite(kBuzzChannel, 0);
    }
  }
}

void on_tick(void*) {
  const uint32_t now = millis();
  key_tick(now);
  buzz_tick(now);
}

void play(const Note* notes, int n) {
  if (n > kMaxNotes) n = kMaxNotes;
  portENTER_CRITICAL(&g_mux);
  for (int i = 0; i < n; i++) g_seq[i] = notes[i];
  g_seqLen = n;
  g_seqRestart = true;
  portEXIT_CRITICAL(&g_mux);
}

}  // namespace

void io_init() {
  if (g_timer) return;
  pinMode(PIN_BOOT, INPUT_PULLUP);
  delay(2);
  const uint32_t now = millis();
  const bool down = digitalRead(PIN_BOOT) == LOW;
  g_rawLast = down;
  g_stable = down;
  g_rawSince = now;
  g_downSince = now;
  g_armed = !down;  // ignore a press that is already down (strapping pin / stuck key)

  ledcSetup(kBuzzChannel, 2000, kBuzzBits);
  ledcAttachPin(PIN_BUZZER, kBuzzChannel);
  ledcWrite(kBuzzChannel, 0);

  analogSetPinAttenuation(PIN_BAT_ADC, ADC_11db);

  esp_timer_create_args_t args = {};
  args.callback = &on_tick;
  args.arg = nullptr;
  args.dispatch_method = ESP_TIMER_TASK;
  args.name = "ripar_io";
  if (esp_timer_create(&args, &g_timer) == ESP_OK) {
    esp_timer_start_periodic(g_timer, kTickUs);
  } else {
    g_timer = nullptr;
  }
}

Key io_poll_key() {
  bool down = false;
  return io_poll_key_state(down);
}

Key io_poll_key_state(bool& down) {
  const uint32_t now = millis();
  portENTER_CRITICAL(&g_mux);
  const Key k = pop_locked(now);
  down = g_stable;
  portEXIT_CRITICAL(&g_mux);
  return k;
}

void io_flush(bool swallowHeld) {
  portENTER_CRITICAL(&g_mux);
  g_qHead = 0;
  g_qCount = 0;
  if (swallowHeld && g_stable) g_armed = false;  // the rest of this press produces no event; re-armed on release
  portEXIT_CRITICAL(&g_mux);
}

bool io_key_down() { return g_stable; }

void buzz(int freqHz, int ms) {
  if (ms <= 0) return;
  if (freqHz < 0) freqHz = 0;
  if (freqHz > 20000) freqHz = 20000;
  if (ms > 5000) ms = 5000;
  const Note n{uint16_t(freqHz), uint16_t(ms)};
  play(&n, 1);
}

void buzz_ok() {
  static const Note seq[] = {{1760, 60}, {0, 30}, {2349, 90}};
  play(seq, 3);
}

void buzz_err() {
  static const Note seq[] = {{440, 150}, {0, 60}, {330, 260}};
  play(seq, 3);
}

void buzz_beat() {
  static const Note seq[] = {{1200, 20}};
  play(seq, 1);
}

// VBAT -> 200k/100k divider -> GPIO5 (ADC1). VBAT = 3 x Vpin. Linear 3.3 V = 0 % .. 4.2 V = 100 %.
// Cached for 2 s. -1 when the reading is implausible (divider not connected).
int battery_percent() {
  static int cached = -1;
  static uint32_t lastMs = 0;
  static bool have = false;
  const uint32_t now = millis();
  if (have && now - lastMs < 2000) return cached;
  uint32_t sum = 0;
  constexpr int kN = 16;
  for (int i = 0; i < kN; i++) sum += analogReadMilliVolts(PIN_BAT_ADC);
  const uint32_t pinMv = sum / kN;
  const uint32_t batMv = pinMv * 3;
  int pct;
  if (pinMv < 300 || batMv > 4700) {
    pct = -1;
  } else if (batMv <= 3300) {
    pct = 0;
  } else if (batMv >= 4200) {
    pct = 100;
  } else {
    pct = int((batMv - 3300) * 100 / 900);
  }
  cached = pct;
  lastMs = now;
  have = true;
  return cached;
}

}  // namespace ripar
