// Camera QR scanner: esp32-camera (OV5640 / OV2640) + quirc, decoding on a FreeRTOS task pinned to core 0.
//
// Camera: grayscale QVGA 320x240 (OV5640 sends Y8), 2 frame buffers in PSRAM, CAMERA_GRAB_LATEST,
// XCLK 20 MHz from LEDC timer 0 / channel 0, SCCB on I2C port 1 (Wire / MAX30102 use port 0).
// Between scans the driver is de-initialised and the sensor is held in power-down (PWDN high).
//
// Orientation assumption (not verified on hardware): the OV5640 module sits on the back of the board, facing
// away from the LCD, and its 320x240 frame maps 1:1 onto the 320x240 landscape screen. RIPAR_CAM_VFLIP /
// RIPAR_CAM_HMIRROR set the sensor flips so the viewfinder reads upright and un-mirrored; flip them at build
// time if the preview is upside down or mirrored. QR decoding does not depend on this: rotation is irrelevant
// to quirc, and a mirrored code is retried with quirc_flip().
//
// Threading: the decode task owns the camera and quirc. It hands results to the app thread through a mutex:
//   - payload: single slot "latest decoded text"; an identical payload is re-delivered at most once per
//     kRepeatMs, so a static code does not flood the app but can be re-scanned after a cancel.
//   - viewfinder: triple buffer in PSRAM. The task writes a buffer that is neither the latest nor held by the
//     app; qrscan_frame() pins the latest one until qrscan_release_frame().
#include <Arduino.h>

#include <cstring>
#include <string>

#include "board.h"
#include "device.h"
#include "esp_camera.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "quirc.h"

#ifndef RIPAR_CAM_VFLIP
#define RIPAR_CAM_VFLIP 1
#endif
#ifndef RIPAR_CAM_HMIRROR
#define RIPAR_CAM_HMIRROR 0
#endif
#ifndef RIPAR_CAM_AE_LEVEL
#define RIPAR_CAM_AE_LEVEL (-2)  // darker than auto: phone screens are bright and wash out (plan suggests up to -4)
#endif

namespace ripar {
namespace {

constexpr int kW = 320, kH = 240;
constexpr size_t kFrameBytes = size_t(kW) * kH;
constexpr uint32_t kTaskStack = 40 * 1024;
constexpr UBaseType_t kTaskPrio = 3;
constexpr uint32_t kRepeatMs = 1000;

SemaphoreHandle_t g_mtx = nullptr;     // guards the handoff state below
SemaphoreHandle_t g_camMtx = nullptr;  // held by the task while it uses the camera; by start/stop to (de)init
TaskHandle_t g_task = nullptr;
volatile bool g_run = false;
bool g_camOn = false;  // driver initialised (guarded by g_camMtx)
int g_pid = 0;

struct quirc* g_q = nullptr;
struct quirc_code* g_code = nullptr;
struct quirc_data* g_data = nullptr;

// handoff (guarded by g_mtx)
uint8_t* g_view[3] = {nullptr, nullptr, nullptr};
int g_latest = -1, g_held = -1;
std::string g_payload;
bool g_havePayload = false;
std::string g_lastDelivered;
uint32_t g_lastDeliveredMs = 0;

camera_config_t cam_config() {
  camera_config_t c = {};
  c.pin_pwdn = PIN_CAM_PWDN;
  c.pin_reset = PIN_CAM_RESET;
  c.pin_xclk = PIN_CAM_XCLK;
  c.pin_sccb_sda = PIN_CAM_SIOD;
  c.pin_sccb_scl = PIN_CAM_SIOC;
  c.pin_d7 = PIN_CAM_D7;
  c.pin_d6 = PIN_CAM_D6;
  c.pin_d5 = PIN_CAM_D5;
  c.pin_d4 = PIN_CAM_D4;
  c.pin_d3 = PIN_CAM_D3;
  c.pin_d2 = PIN_CAM_D2;
  c.pin_d1 = PIN_CAM_D1;
  c.pin_d0 = PIN_CAM_D0;
  c.pin_vsync = PIN_CAM_VSYNC;
  c.pin_href = PIN_CAM_HREF;
  c.pin_pclk = PIN_CAM_PCLK;
  c.xclk_freq_hz = 20000000;
  c.ledc_timer = LEDC_TIMER_0;
  c.ledc_channel = LEDC_CHANNEL_0;
  c.pixel_format = PIXFORMAT_GRAYSCALE;
  c.frame_size = FRAMESIZE_QVGA;
  c.jpeg_quality = 12;
  c.fb_count = 2;
  c.fb_location = CAMERA_FB_IN_PSRAM;
  c.grab_mode = CAMERA_GRAB_LATEST;
  c.sccb_i2c_port = 1;
  return c;
}

void power_down_pin() {
  if (PIN_CAM_PWDN >= 0) {
    pinMode(PIN_CAM_PWDN, OUTPUT);
    digitalWrite(PIN_CAM_PWDN, HIGH);  // OV5640/OV2640 PWDN is active high
  }
}

void tune_sensor() {
  sensor_t* s = esp_camera_sensor_get();
  if (!s) return;
  if (s->set_vflip) s->set_vflip(s, RIPAR_CAM_VFLIP);
  if (s->set_hmirror) s->set_hmirror(s, RIPAR_CAM_HMIRROR);
  if (s->set_exposure_ctrl) s->set_exposure_ctrl(s, 1);
  if (s->set_gain_ctrl) s->set_gain_ctrl(s, 1);
  if (s->set_ae_level) s->set_ae_level(s, RIPAR_CAM_AE_LEVEL);
  if (s->set_contrast) s->set_contrast(s, 2);
  if (s->set_sharpness) s->set_sharpness(s, 2);
  if (s->set_brightness) s->set_brightness(s, 0);
}

// camera on/off; caller holds g_camMtx
bool cam_on() {
  if (g_camOn) return true;
  const camera_config_t cfg = cam_config();
  if (esp_camera_init(&cfg) != ESP_OK) {
    power_down_pin();
    return false;
  }
  tune_sensor();
  g_camOn = true;
  return true;
}

void cam_off() {
  if (g_camOn) {
    esp_camera_deinit();
    g_camOn = false;
  }
  power_down_pin();
}

void deliver(const uint8_t* p, int len) {
  if (len <= 0) return;
  const uint32_t now = millis();
  xSemaphoreTake(g_mtx, portMAX_DELAY);
  const bool same = g_lastDelivered.size() == size_t(len) && std::memcmp(g_lastDelivered.data(), p, size_t(len)) == 0;
  if (!same || now - g_lastDeliveredMs >= kRepeatMs) {
    g_payload.assign(reinterpret_cast<const char*>(p), size_t(len));
    g_havePayload = true;
    g_lastDelivered = g_payload;
    g_lastDeliveredMs = now;
  }
  xSemaphoreGive(g_mtx);
}

void decode_task(void*) {
  for (;;) {
    if (!g_run) {
      ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(500));
      continue;
    }
    bool gotFrame = false;
    xSemaphoreTake(g_camMtx, portMAX_DELAY);
    if (g_run && g_camOn) {
      camera_fb_t* fb = esp_camera_fb_get();
      if (fb) {
        if (fb->format == PIXFORMAT_GRAYSCALE && int(fb->width) == kW && int(fb->height) == kH &&
            fb->len >= kFrameBytes) {
          // viewfinder copy: pick a buffer that is neither the latest nor pinned by the app
          xSemaphoreTake(g_mtx, portMAX_DELAY);
          int w = 0;
          while (w == g_latest || w == g_held) w++;
          xSemaphoreGive(g_mtx);
          std::memcpy(g_view[w], fb->buf, kFrameBytes);
          xSemaphoreTake(g_mtx, portMAX_DELAY);
          g_latest = w;
          xSemaphoreGive(g_mtx);
          // quirc input (quirc binarises its buffer in place, hence the separate copy)
          uint8_t* img = quirc_begin(g_q, nullptr, nullptr);
          std::memcpy(img, fb->buf, kFrameBytes);
          gotFrame = true;
        }
        esp_camera_fb_return(fb);
      }
    }
    xSemaphoreGive(g_camMtx);

    if (!gotFrame) {
      vTaskDelay(pdMS_TO_TICKS(20));
      continue;
    }
    quirc_end(g_q);
    const int n = quirc_count(g_q);
    for (int i = 0; i < n; i++) {
      quirc_extract(g_q, i, g_code);
      quirc_decode_error_t err = quirc_decode(g_code, g_data);
      if (err != QUIRC_SUCCESS) {  // maybe a mirrored image
        quirc_flip(g_code);
        err = quirc_decode(g_code, g_data);
      }
      if (err == QUIRC_SUCCESS) deliver(g_data->payload, g_data->payload_len);
    }
    vTaskDelay(1);  // let IDLE0 run (task watchdog)
  }
}

bool alloc_once() {
  if (g_task) return true;
  g_mtx = xSemaphoreCreateMutex();
  g_camMtx = xSemaphoreCreateMutex();
  if (!g_mtx || !g_camMtx) return false;
  for (auto& v : g_view) {
    v = static_cast<uint8_t*>(heap_caps_malloc(kFrameBytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    if (!v) return false;
    std::memset(v, 0, kFrameBytes);
  }
  g_code = static_cast<struct quirc_code*>(heap_caps_malloc(sizeof(struct quirc_code), MALLOC_CAP_SPIRAM));
  g_data = static_cast<struct quirc_data*>(heap_caps_malloc(sizeof(struct quirc_data), MALLOC_CAP_SPIRAM));
  if (!g_code || !g_data) return false;
  g_q = quirc_new();  // large allocations land in PSRAM (CONFIG_SPIRAM_USE_MALLOC, > 4 KB)
  if (!g_q || quirc_resize(g_q, kW, kH) < 0) return false;
  if (xTaskCreatePinnedToCore(decode_task, "ripar_qr", kTaskStack, nullptr, kTaskPrio, &g_task, 0) != pdPASS) {
    g_task = nullptr;
    return false;
  }
  return true;
}

}  // namespace

bool qrscan_init() {
  if (!psramFound()) return false;
  if (!alloc_once()) return false;
  xSemaphoreTake(g_camMtx, portMAX_DELAY);
  bool ok = cam_on();
  if (ok) {
    sensor_t* s = esp_camera_sensor_get();
    g_pid = s ? int(s->id.PID) : 0;
    ok = g_pid != 0;
  }
  cam_off();  // probe only; qrscan_start powers it up again
  xSemaphoreGive(g_camMtx);
  return ok;
}

void qrscan_start() {
  if (!g_task) return;
  xSemaphoreTake(g_mtx, portMAX_DELAY);
  g_havePayload = false;
  g_payload.clear();
  g_lastDelivered.clear();
  g_latest = -1;
  xSemaphoreGive(g_mtx);
  xSemaphoreTake(g_camMtx, portMAX_DELAY);
  const bool ok = cam_on();
  if (ok) {
    sensor_t* s = esp_camera_sensor_get();
    if (s) g_pid = int(s->id.PID);
  }
  g_run = ok;
  xSemaphoreGive(g_camMtx);
  if (ok) xTaskNotifyGive(g_task);
}

void qrscan_stop() {
  if (!g_task) return;
  g_run = false;
  xSemaphoreTake(g_camMtx, portMAX_DELAY);  // waits for an in-flight frame grab to finish
  cam_off();
  xSemaphoreGive(g_camMtx);
  xSemaphoreTake(g_mtx, portMAX_DELAY);
  g_latest = -1;
  g_havePayload = false;
  xSemaphoreGive(g_mtx);
}

bool qrscan_poll(std::string& payload) {
  if (!g_mtx) return false;
  bool have = false;
  xSemaphoreTake(g_mtx, portMAX_DELAY);
  if (g_havePayload) {
    payload.swap(g_payload);
    g_payload.clear();
    g_havePayload = false;
    have = true;
  }
  xSemaphoreGive(g_mtx);
  return have;
}

const uint8_t* qrscan_frame(int& w, int& h) {
  if (!g_mtx) return nullptr;
  const uint8_t* p = nullptr;
  xSemaphoreTake(g_mtx, portMAX_DELAY);
  if (g_latest >= 0) {
    g_held = g_latest;
    p = g_view[g_held];
  }
  xSemaphoreGive(g_mtx);
  if (p) {
    w = kW;
    h = kH;
  }
  return p;
}

void qrscan_release_frame() {
  if (!g_mtx) return;
  xSemaphoreTake(g_mtx, portMAX_DELAY);
  g_held = -1;
  xSemaphoreGive(g_mtx);
}

int camera_pid() { return g_pid; }

}  // namespace ripar
