// Bluetooth LE fallback courier (include/ble_link.h, docs/BLE_LINK.md). Compiled only with RIPAR_BLE=1 (env:ripar);
// env:ripar-airgap excludes this file and links no radio code at all.
//
// Stack: the Bluedroid host + BLE controller bundled with Arduino-ESP32 2.0.17 (ESP-IDF 4.4), used through its
// ESP-IDF API (esp_gap_ble_api.h / esp_gatts_api.h, the layer the framework's BLE C++ library wraps). The C++
// wrapper is not used: it keeps static singletons that cannot be torn down and started again (the radio is switched
// off and on at run time here), and its numeric-comparison callback blocks the Bluetooth task until it returns,
// while the answer here comes from a key press in the app loop.
//
// Life cycle: nothing Bluetooth runs until ble_link_enable() (after the BLE LINK review + pulse + SIGN). Enable =
// controller init + enable (BLE only), Bluedroid init + enable, one GATT service from an attribute table, legacy
// advertising (flags + the 128-bit service UUID; the name in the scan response). Disable = stop advertising, drop
// the link, Bluedroid disable + deinit, controller disable + deinit. The controller memory is NOT released
// (esp_bt_controller_mem_release), because a released controller can never be started again until reboot (see
// btInUse() below). Wi-Fi is never touched.
//
// Security: LE Secure Connections only, MITM, bonding (ESP_LE_AUTH_REQ_SC_MITM_BOND with "only accept the specified
// authentication"), IO capability DisplayYesNo -> numeric comparison: the 6-digit value is shown on the device and
// the user confirms it with SIGN. Pairing requests are refused unless the pairing window (Screen::BlePair) is open.
// Every characteristic value and descriptor needs an encrypted MITM link at the ATT layer, and the app additionally
// answers every read / write itself and refuses it unless this link completed an authenticated (MITM) SMP procedure.
// One connection at a time; one bond (a confirmed new pairing removes every other bond).
#include "device.h"

#if RIPAR_BLE

#include <Arduino.h>
#include <Preferences.h>

#include <cstring>
#include <deque>
#include <string>
#include <vector>

#include "ble_link.h"
#include "ble_proto.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_gatt_common_api.h"
#include "esp_gatts_api.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

// Arduino-ESP32 frees the Bluetooth controller memory at boot when btInUse() returns false (initArduino()). On the
// ESP32-S3 the framework's weak default (esp32-hal-bt.c) is already true; it is defined here explicitly so that the
// memory is never released behind this file's back. It only keeps the memory reserved: it does NOT start anything.
extern "C" bool btInUse(void) { return true; }

namespace ripar {
namespace {

using namespace blep;

constexpr uint16_t kAppId = 0x52;
constexpr uint32_t kSetupTimeoutMs = 4000;
constexpr uint32_t kUnauthDropMs = 30000;  // a link that has not authenticated after 30 s is dropped
constexpr size_t kMaxPrep = kMaxLine + 64;  // prepared (long) write buffer
constexpr int kTxPerPass = 4;               // notifications queued per app-loop pass (paced; stops when congested)
constexpr const char* kNvsNs = "riparble";
constexpr const char* kNvsForget = "forget";

// ---- attribute table
enum Idx { IDX_SVC, IDX_RX_CHAR, IDX_RX_VAL, IDX_TX_CHAR, IDX_TX_VAL, IDX_TX_CCC, IDX_ST_CHAR, IDX_ST_VAL, IDX_ST_CCC,
           IDX_NB };
uint8_t g_uuidSvc[16], g_uuidRx[16], g_uuidTx[16], g_uuidSt[16];
const uint16_t kUuidPrimary = ESP_GATT_UUID_PRI_SERVICE;
const uint16_t kUuidCharDecl = ESP_GATT_UUID_CHAR_DECLARE;
const uint16_t kUuidCcc = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;
const uint8_t kPropWrite = ESP_GATT_CHAR_PROP_BIT_WRITE | ESP_GATT_CHAR_PROP_BIT_WRITE_NR;
const uint8_t kPropNotify = ESP_GATT_CHAR_PROP_BIT_NOTIFY;
const uint8_t kPropReadNotify = ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_NOTIFY;
uint8_t g_initRx[1], g_initTx[1], g_initSt[1], g_initTxCcc[2], g_initStCcc[2];
constexpr esp_gatt_perm_t kPermMitm = ESP_GATT_PERM_READ_ENC_MITM | ESP_GATT_PERM_WRITE_ENC_MITM;

esp_gatts_attr_db_t g_db[IDX_NB];

void build_db() {
  auto decl = [](esp_gatts_attr_db_t& e, uint8_t autoRsp, uint16_t uuidLen, const void* uuid, esp_gatt_perm_t perm,
                 uint16_t maxLen, uint16_t len, const void* value) {
    e.attr_control.auto_rsp = autoRsp;
    e.att_desc.uuid_length = uuidLen;
    e.att_desc.uuid_p = const_cast<uint8_t*>(static_cast<const uint8_t*>(uuid));
    e.att_desc.perm = perm;
    e.att_desc.max_length = maxLen;
    e.att_desc.length = len;
    e.att_desc.value = const_cast<uint8_t*>(static_cast<const uint8_t*>(value));
  };
  // declarations are readable without a link key (service discovery); every value / descriptor is not
  decl(g_db[IDX_SVC], ESP_GATT_AUTO_RSP, ESP_UUID_LEN_16, &kUuidPrimary, ESP_GATT_PERM_READ, 16, 16, g_uuidSvc);
  decl(g_db[IDX_RX_CHAR], ESP_GATT_AUTO_RSP, ESP_UUID_LEN_16, &kUuidCharDecl, ESP_GATT_PERM_READ, 1, 1, &kPropWrite);
  decl(g_db[IDX_RX_VAL], ESP_GATT_RSP_BY_APP, ESP_UUID_LEN_128, g_uuidRx, ESP_GATT_PERM_WRITE_ENC_MITM, 512, 0,
       g_initRx);
  decl(g_db[IDX_TX_CHAR], ESP_GATT_AUTO_RSP, ESP_UUID_LEN_16, &kUuidCharDecl, ESP_GATT_PERM_READ, 1, 1, &kPropNotify);
  decl(g_db[IDX_TX_VAL], ESP_GATT_RSP_BY_APP, ESP_UUID_LEN_128, g_uuidTx, ESP_GATT_PERM_READ_ENC_MITM, 512, 0,
       g_initTx);
  decl(g_db[IDX_TX_CCC], ESP_GATT_RSP_BY_APP, ESP_UUID_LEN_16, &kUuidCcc, kPermMitm, 2, 2, g_initTxCcc);
  decl(g_db[IDX_ST_CHAR], ESP_GATT_AUTO_RSP, ESP_UUID_LEN_16, &kUuidCharDecl, ESP_GATT_PERM_READ, 1, 1,
       &kPropReadNotify);
  decl(g_db[IDX_ST_VAL], ESP_GATT_RSP_BY_APP, ESP_UUID_LEN_128, g_uuidSt, ESP_GATT_PERM_READ_ENC_MITM, 256, 0,
       g_initSt);
  decl(g_db[IDX_ST_CCC], ESP_GATT_RSP_BY_APP, ESP_UUID_LEN_16, &kUuidCcc, kPermMitm, 2, 2, g_initStCcc);
}

// ---- advertising
uint8_t g_adv[31], g_scanRsp[31];
uint32_t g_advLen = 0, g_scanRspLen = 0;
esp_ble_adv_params_t g_advParams;

void build_adv(const std::string& name) {
  g_advLen = 0;
  g_adv[g_advLen++] = 2;  // flags: LE general discoverable, BR/EDR not supported
  g_adv[g_advLen++] = ESP_BLE_AD_TYPE_FLAG;
  g_adv[g_advLen++] = ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT;
  g_adv[g_advLen++] = 17;  // complete list of 128-bit service UUIDs
  g_adv[g_advLen++] = ESP_BLE_AD_TYPE_128SRV_CMPL;
  std::memcpy(g_adv + g_advLen, g_uuidSvc, 16);
  g_advLen += 16;
  const size_t n = name.size() > 29 ? 29 : name.size();
  g_scanRspLen = 0;
  g_scanRsp[g_scanRspLen++] = uint8_t(n + 1);
  g_scanRsp[g_scanRspLen++] = ESP_BLE_AD_TYPE_NAME_CMPL;
  std::memcpy(g_scanRsp + g_scanRspLen, name.data(), n);
  g_scanRspLen += uint32_t(n);
  std::memset(&g_advParams, 0, sizeof g_advParams);
  g_advParams.adv_int_min = 0x60;  // 60 ms
  g_advParams.adv_int_max = 0xA0;  // 100 ms
  g_advParams.adv_type = ADV_TYPE_IND;
  g_advParams.own_addr_type = BLE_ADDR_TYPE_PUBLIC;
  g_advParams.channel_map = ADV_CHNL_ALL;
  g_advParams.adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY;
}

// ---- state shared with the Bluetooth task (g_mtx)
SemaphoreHandle_t g_mtx = nullptr;
struct Lock {
  Lock() { xSemaphoreTake(g_mtx, portMAX_DELAY); }
  ~Lock() { xSemaphoreGive(g_mtx); }
  Lock(const Lock&) = delete;
  Lock& operator=(const Lock&) = delete;
};

struct LinkState {
  bool connected = false;
  uint16_t connId = 0;
  esp_bd_addr_t bda = {0};     // connection address
  esp_bd_addr_t secBda = {0};  // address of the pending numeric comparison
  esp_bd_addr_t newBond = {0}; // address of a bond just made with the user's confirmation
  uint16_t mtu = 23;
  uint32_t connectedAt = 0;
  bool authenticated = false;  // SMP completed with MITM on this link (blep::auth_outcome)
  bool pairing = false;        // an SMP pairing ran on this link
  bool userConfirmed = false;  // the user pressed SIGN on the code of this link
  bool codePending = false;
  uint32_t code = 0;
  bool txNotify = false, stNotify = false;
  bool congested = false;
  bool dropSent = false;       // unauthenticated drop already requested
};

LinkState g_link;
bool g_window = false;
// events for the app loop (cleared by ble_link_tick)
bool g_evTraffic = false, g_evCode = false, g_evPaired = false, g_evPairFailed = false, g_evLink = false;
bool g_evRestartAdv = false, g_evResendTx = false, g_evResendSt = false;
LineAssembler g_asm;
LineQueue g_lines;
std::string g_prep;       // prepared-write buffer (RX)
std::string g_statusVal;  // STATUS value served on reads

// setup progress (written by the Bluetooth task, polled by ble_link_enable)
volatile bool g_session = false;  // callbacks registered, Bluedroid running
volatile bool g_setupFail = false, g_advData = false, g_scanData = false, g_svcStarted = false;
volatile bool g_advRequested = false, g_advStarted = false;
esp_gatt_if_t g_gattsIf = ESP_GATT_IF_NONE;
uint16_t g_handles[IDX_NB];

// ---- app-loop-only state
bool g_on = false;
std::string g_name;
IdleTimer g_idle(kIdleOffMs);
std::string g_lastStatus, g_lastOutput;
bool g_statusDirty = false, g_outputDirty = false;
std::deque<std::string> g_txq;

esp_gatt_rsp_t g_rsp;  // Bluetooth task only (callbacks are serialised there); too big for its stack

void wipe_str(std::string& s) {
  if (!s.empty()) {
    volatile char* p = &s[0];
    for (size_t i = 0; i < s.size(); i++) p[i] = 0;
  }
  s.clear();
}
void wipe_txq() {
  for (std::string& s : g_txq) wipe_str(s);
  g_txq.clear();
}

bool same_addr(const esp_bd_addr_t a, const esp_bd_addr_t b) { return std::memcmp(a, b, sizeof(esp_bd_addr_t)) == 0; }

// ================================================================================================ Bluetooth task
void maybe_start_adv() {  // Bluetooth task
  if (g_session && g_advData && g_scanData && g_svcStarted && !g_advRequested) {
    g_advRequested = true;
    if (esp_ble_gap_start_advertising(&g_advParams) != ESP_OK) g_setupFail = true;
  }
}

void queue_lines(std::vector<std::string>& out) {  // with g_mtx held
  for (std::string& l : out) g_lines.push(std::move(l));
}

void gap_cb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t* p) {
  switch (event) {
    case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
      if (p->adv_data_raw_cmpl.status != ESP_BT_STATUS_SUCCESS) g_setupFail = true;
      g_advData = true;
      maybe_start_adv();
      break;
    case ESP_GAP_BLE_SCAN_RSP_DATA_RAW_SET_COMPLETE_EVT:
      if (p->scan_rsp_data_raw_cmpl.status != ESP_BT_STATUS_SUCCESS) g_setupFail = true;
      g_scanData = true;
      maybe_start_adv();
      break;
    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
      if (p->adv_start_cmpl.status == ESP_BT_STATUS_SUCCESS)
        g_advStarted = true;
      else if (!g_advStarted)
        g_setupFail = true;
      break;

    case ESP_GAP_BLE_SEC_REQ_EVT: {  // the phone asks to pair: only while the pairing window is open
      bool accept;
      {
        Lock l;
        accept = g_window && g_link.connected;
        if (accept) {
          g_link.pairing = true;
          g_evTraffic = true;
        }
      }
      esp_ble_gap_security_rsp(p->ble_security.ble_req.bd_addr, accept);
      break;
    }
    case ESP_GAP_BLE_NC_REQ_EVT: {  // numeric comparison: shown on the device, answered with SIGN (app loop)
      bool reject = false;
      {
        Lock l;
        if (g_window && g_link.connected && !g_link.codePending) {
          g_link.pairing = true;
          g_link.codePending = true;
          g_link.userConfirmed = false;
          g_link.code = p->ble_security.key_notif.passkey % 1000000u;
          std::memcpy(g_link.secBda, p->ble_security.key_notif.bd_addr, sizeof(esp_bd_addr_t));
          g_evCode = true;
          g_evTraffic = true;
        } else {
          reject = true;
        }
      }
      if (reject) esp_ble_confirm_reply(p->ble_security.key_notif.bd_addr, false);
      break;
    }
    case ESP_GAP_BLE_PASSKEY_NOTIF_EVT: {
      // passkey entry (the phone would type our number): the device could not confirm it -> abort the pairing
      esp_bd_addr_t bda;
      {
        Lock l;
        g_link.pairing = true;
        std::memcpy(bda, g_link.bda, sizeof bda);
      }
      esp_ble_gap_disconnect(bda);
      break;
    }
    case ESP_GAP_BLE_PASSKEY_REQ_EVT:  // we would have to type a number: no keyboard
      esp_ble_passkey_reply(p->ble_security.ble_req.bd_addr, false, 0);
      break;
    case ESP_GAP_BLE_AUTH_CMPL_EVT: {
      const esp_ble_auth_cmpl_t& a = p->ble_security.auth_cmpl;
      AuthOutcome o;
      esp_bd_addr_t linkBda;
      {
        Lock l;
        o = auth_outcome(a.success, uint8_t(a.auth_mode), g_link.pairing, g_link.userConfirmed);
        std::memcpy(linkBda, g_link.bda, sizeof linkBda);
        const bool wasPairing = g_link.pairing;
        g_link.codePending = false;
        if (g_link.connected && o == AuthOutcome::Authenticated) {
          g_link.authenticated = true;
          g_evTraffic = true;
          if (wasPairing) {
            std::memcpy(g_link.newBond, a.bd_addr, sizeof(esp_bd_addr_t));
            g_evPaired = true;
          }
        } else {
          g_link.authenticated = false;
          if (wasPairing) g_evPairFailed = true;
        }
        g_link.pairing = false;
        g_link.userConfirmed = false;
        g_evLink = true;
      }
      if (o == AuthOutcome::RemoveBond) esp_ble_remove_bond_device(const_cast<uint8_t*>(a.bd_addr));
      if (o != AuthOutcome::Authenticated) esp_ble_gap_disconnect(linkBda);
      break;
    }
    default:
      break;
  }
}

void respond(esp_gatt_if_t ifc, uint16_t connId, uint32_t transId, esp_gatt_status_t st, esp_gatt_rsp_t* rsp) {
  esp_ble_gatts_send_response(ifc, connId, transId, st, rsp);
}

void on_read(esp_gatt_if_t ifc, esp_ble_gatts_cb_param_t* p) {
  const auto& r = p->read;
  if (!r.need_rsp) return;
  std::memset(&g_rsp, 0, sizeof g_rsp);
  g_rsp.attr_value.handle = r.handle;
  g_rsp.attr_value.offset = r.offset;
  g_rsp.attr_value.auth_req = ESP_GATT_AUTH_REQ_NONE;
  esp_gatt_status_t st = ESP_GATT_OK;
  {
    Lock l;
    if (!g_link.connected || !g_link.authenticated || r.conn_id != g_link.connId) {
      st = ESP_GATT_INSUF_AUTHENTICATION;
    } else if (r.handle == g_handles[IDX_ST_VAL]) {
      g_evTraffic = true;
      if (r.offset > g_statusVal.size()) {
        st = ESP_GATT_INVALID_OFFSET;
      } else {
        size_t n = g_statusVal.size() - r.offset;
        const size_t cap = size_t(g_link.mtu) - 1;
        if (n > cap) n = cap;
        if (n > ESP_GATT_MAX_ATTR_LEN) n = ESP_GATT_MAX_ATTR_LEN;
        std::memcpy(g_rsp.attr_value.value, g_statusVal.data() + r.offset, n);
        g_rsp.attr_value.len = uint16_t(n);
      }
    } else if (r.handle == g_handles[IDX_TX_CCC] || r.handle == g_handles[IDX_ST_CCC]) {
      g_evTraffic = true;
      const bool on = r.handle == g_handles[IDX_TX_CCC] ? g_link.txNotify : g_link.stNotify;
      g_rsp.attr_value.value[0] = on ? 1 : 0;
      g_rsp.attr_value.len = r.offset == 0 ? 2 : 0;
    } else if (r.handle == g_handles[IDX_TX_VAL]) {
      g_rsp.attr_value.len = 0;  // notify-only: nothing to read
    } else {
      st = ESP_GATT_READ_NOT_PERMIT;
    }
  }
  respond(ifc, r.conn_id, r.trans_id, st, &g_rsp);
}

void on_write(esp_gatt_if_t ifc, esp_ble_gatts_cb_param_t* p) {
  const auto& w = p->write;
  esp_gatt_status_t st = ESP_GATT_OK;
  {
    Lock l;
    if (!g_link.connected || !g_link.authenticated || w.conn_id != g_link.connId) {
      st = ESP_GATT_INSUF_AUTHENTICATION;
    } else if (w.handle == g_handles[IDX_RX_VAL]) {
      g_evTraffic = true;
      if (w.is_prep) {
        if (w.offset != g_prep.size())
          st = ESP_GATT_INVALID_OFFSET;
        else if (g_prep.size() + w.len > kMaxPrep)
          st = ESP_GATT_PREPARE_Q_FULL;
        else
          g_prep.append(reinterpret_cast<const char*>(w.value), w.len);
      } else {
        std::vector<std::string> out;
        g_asm.push(w.value, w.len, out);
        queue_lines(out);
      }
    } else if (w.handle == g_handles[IDX_TX_CCC] || w.handle == g_handles[IDX_ST_CCC]) {
      g_evTraffic = true;
      if (w.is_prep || w.len != 2 || w.offset != 0) {
        st = ESP_GATT_INVALID_ATTR_LEN;
      } else {
        const bool on = (w.value[0] & 1) != 0;
        if (w.handle == g_handles[IDX_TX_CCC]) {
          if (on && !g_link.txNotify) g_evResendTx = true;
          g_link.txNotify = on;
        } else {
          if (on && !g_link.stNotify) g_evResendSt = true;
          g_link.stNotify = on;
        }
      }
    } else {
      st = ESP_GATT_WRITE_NOT_PERMIT;
    }
  }
  if (!w.need_rsp) return;
  if (w.is_prep && st == ESP_GATT_OK) {  // a prepare-write response echoes the fragment
    std::memset(&g_rsp, 0, sizeof g_rsp);
    g_rsp.attr_value.handle = w.handle;
    g_rsp.attr_value.offset = w.offset;
    g_rsp.attr_value.len = w.len > ESP_GATT_MAX_ATTR_LEN ? ESP_GATT_MAX_ATTR_LEN : w.len;
    g_rsp.attr_value.auth_req = ESP_GATT_AUTH_REQ_NONE;
    std::memcpy(g_rsp.attr_value.value, w.value, g_rsp.attr_value.len);
    respond(ifc, w.conn_id, w.trans_id, st, &g_rsp);
  } else {
    respond(ifc, w.conn_id, w.trans_id, st, nullptr);
  }
}

void on_exec_write(esp_gatt_if_t ifc, esp_ble_gatts_cb_param_t* p) {
  const auto& x = p->exec_write;
  esp_gatt_status_t st = ESP_GATT_OK;
  {
    Lock l;
    if (!g_link.connected || !g_link.authenticated || x.conn_id != g_link.connId) {
      st = ESP_GATT_INSUF_AUTHENTICATION;
    } else if (x.exec_write_flag == ESP_GATT_PREP_WRITE_EXEC && !g_prep.empty()) {
      std::vector<std::string> out;
      g_asm.push(reinterpret_cast<const uint8_t*>(g_prep.data()), g_prep.size(), out);
      queue_lines(out);
      g_evTraffic = true;
    }
    g_prep.clear();
  }
  respond(ifc, x.conn_id, x.trans_id, st, nullptr);
}

void gatts_cb(esp_gatts_cb_event_t event, esp_gatt_if_t ifc, esp_ble_gatts_cb_param_t* p) {
  switch (event) {
    case ESP_GATTS_REG_EVT:
      if (p->reg.status != ESP_GATT_OK || p->reg.app_id != kAppId) {
        g_setupFail = true;
        break;
      }
      g_gattsIf = ifc;
      if (esp_ble_gap_set_device_name(g_name.c_str()) != ESP_OK ||
          esp_ble_gap_config_adv_data_raw(g_adv, g_advLen) != ESP_OK ||
          esp_ble_gap_config_scan_rsp_data_raw(g_scanRsp, g_scanRspLen) != ESP_OK ||
          esp_ble_gatts_create_attr_tab(g_db, ifc, IDX_NB, 0) != ESP_OK)
        g_setupFail = true;
      break;
    case ESP_GATTS_CREAT_ATTR_TAB_EVT:
      if (p->add_attr_tab.status != ESP_GATT_OK || p->add_attr_tab.num_handle != IDX_NB) {
        g_setupFail = true;
        break;
      }
      std::memcpy(g_handles, p->add_attr_tab.handles, sizeof g_handles);
      if (esp_ble_gatts_start_service(g_handles[IDX_SVC]) != ESP_OK) g_setupFail = true;
      break;
    case ESP_GATTS_START_EVT:
      if (p->start.status != ESP_GATT_OK) {
        g_setupFail = true;
        break;
      }
      g_svcStarted = true;
      maybe_start_adv();
      break;
    case ESP_GATTS_CONNECT_EVT: {
      bool second = false;
      {
        Lock l;
        if (g_link.connected) {
          second = true;  // one phone at a time
        } else {
          g_link = LinkState();
          g_link.connected = true;
          g_link.connId = p->connect.conn_id;
          std::memcpy(g_link.bda, p->connect.remote_bda, sizeof(esp_bd_addr_t));
          g_link.connectedAt = millis();
          g_asm.reset();
          g_prep.clear();
          g_evLink = true;
        }
      }
      if (second) {
        esp_ble_gap_disconnect(p->connect.remote_bda);
      } else {
        // ask for the bonded, MITM-protected link at once: a bonded phone re-encrypts, a new one must pair
        // (refused unless the pairing window is open)
        esp_ble_set_encryption(p->connect.remote_bda, ESP_BLE_SEC_ENCRYPT_MITM);
      }
      break;
    }
    case ESP_GATTS_DISCONNECT_EVT: {
      Lock l;
      if (g_link.connected && p->disconnect.conn_id == g_link.connId) {
        if (g_link.pairing || g_link.codePending) g_evPairFailed = true;
        g_link = LinkState();
        g_asm.reset();
        g_prep.clear();
        g_evLink = true;
        g_evRestartAdv = true;
      }
      break;
    }
    case ESP_GATTS_MTU_EVT: {
      Lock l;
      if (g_link.connected && p->mtu.conn_id == g_link.connId) g_link.mtu = p->mtu.mtu;
      break;
    }
    case ESP_GATTS_CONGEST_EVT: {
      Lock l;
      if (g_link.connected && p->congest.conn_id == g_link.connId) g_link.congested = p->congest.congested;
      break;
    }
    case ESP_GATTS_READ_EVT:
      on_read(ifc, p);
      break;
    case ESP_GATTS_WRITE_EVT:
      on_write(ifc, p);
      break;
    case ESP_GATTS_EXEC_WRITE_EVT:
      on_exec_write(ifc, p);
      break;
    default:
      break;
  }
}

// ================================================================================================ app loop
void log_line(const char* what, esp_err_t rc) {
  if (Serial) Serial.printf("ripar: ble %s: %s\n", what, esp_err_to_name(rc));
}

// removes every bond except the given addresses (nullptr = none kept)
void remove_bonds_except(const uint8_t* keepA, const uint8_t* keepB) {
  int n = esp_ble_get_bond_device_num();
  if (n <= 0) return;
  std::vector<esp_ble_bond_dev_t> list(static_cast<size_t>(n));
  if (esp_ble_get_bond_device_list(&n, list.data()) != ESP_OK) return;
  for (int i = 0; i < n; i++) {
    uint8_t* a = list[size_t(i)].bd_addr;
    if (keepA && same_addr(a, keepA)) continue;
    if (keepB && same_addr(a, keepB)) continue;
    esp_ble_remove_bond_device(a);
  }
  std::memset(list.data(), 0, list.size() * sizeof(esp_ble_bond_dev_t));  // key material
}

bool forget_flag(bool set, bool clear) {
  Preferences prefs;
  if (!prefs.begin(kNvsNs, !(set || clear))) return false;
  bool v = prefs.getUChar(kNvsForget, 0) != 0;
  if (set) prefs.putUChar(kNvsForget, 1);
  if (clear && v) prefs.remove(kNvsForget);
  prefs.end();
  return v;
}

// Everything off. Safe to call in any partial state (also from a failed enable).
void teardown() {
  g_on = false;
  if (g_session) {
    bool connected;
    esp_bd_addr_t bda;
    {
      Lock l;
      g_window = false;
      connected = g_link.connected;
      std::memcpy(bda, g_link.bda, sizeof bda);
    }
    if (g_advRequested) esp_ble_gap_stop_advertising();
    if (connected) esp_ble_gap_disconnect(bda);
    delay(60);  // let the stop / disconnect reach the controller
  }
  esp_err_t rc;
  if (esp_bluedroid_get_status() == ESP_BLUEDROID_STATUS_ENABLED && (rc = esp_bluedroid_disable()) != ESP_OK)
    log_line("bluedroid disable", rc);
  if (esp_bluedroid_get_status() == ESP_BLUEDROID_STATUS_INITIALIZED && (rc = esp_bluedroid_deinit()) != ESP_OK)
    log_line("bluedroid deinit", rc);
  g_session = false;
  if (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_ENABLED) {
    if ((rc = esp_bt_controller_disable()) != ESP_OK) log_line("controller disable", rc);
    for (int i = 0; i < 100 && esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_ENABLED; i++) delay(2);
  }
  if (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_INITED) {
    if ((rc = esp_bt_controller_deinit()) != ESP_OK) log_line("controller deinit", rc);
    for (int i = 0; i < 100 && esp_bt_controller_get_status() != ESP_BT_CONTROLLER_STATUS_IDLE; i++) delay(2);
  }
  {
    Lock l;
    g_link = LinkState();
    g_window = false;
    g_evTraffic = g_evCode = g_evPaired = g_evPairFailed = g_evLink = false;
    g_evRestartAdv = g_evResendTx = g_evResendSt = false;
    g_asm.reset();
    g_lines.clear();
    wipe_str(g_prep);
    g_statusVal.clear();
  }
  g_gattsIf = ESP_GATT_IF_NONE;
  g_advRequested = g_advStarted = g_advData = g_scanData = g_svcStarted = g_setupFail = false;
  wipe_txq();
  wipe_str(g_lastOutput);
  g_lastStatus.clear();
  g_statusDirty = g_outputDirty = false;
  g_idle.stop();
  if (Serial)
    Serial.printf("ripar: ble off (controller %s)\n",
                  esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_IDLE ? "idle" : "NOT IDLE");
}

bool fail(std::string& err, const char* what, esp_err_t rc) {
  err = std::string(what) + ": " + esp_err_to_name(rc);
  log_line(what, rc);
  teardown();
  return false;
}

}  // namespace

// ================================================================================================ API
bool ble_link_enable(const std::string& name, std::string& err) {
  if (g_on) return true;
  if (!g_mtx) g_mtx = xSemaphoreCreateMutex();
  if (!g_mtx) {
    err = "no memory for the link mutex";
    return false;
  }
  if (!uuid128_le(kServiceUuid, g_uuidSvc) || !uuid128_le(kRxUuid, g_uuidRx) || !uuid128_le(kTxUuid, g_uuidTx) ||
      !uuid128_le(kStatusUuid, g_uuidSt)) {
    err = "bad UUID table";
    return false;
  }
  teardown();  // clean slate (no-op when everything is already off)
  g_name = name;
  build_db();
  build_adv(name);

  esp_err_t rc;
  esp_bt_controller_config_t cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  if ((rc = esp_bt_controller_init(&cfg)) != ESP_OK) return fail(err, "controller init", rc);
  if ((rc = esp_bt_controller_enable(ESP_BT_MODE_BLE)) != ESP_OK) return fail(err, "controller enable", rc);
  if ((rc = esp_bluedroid_init()) != ESP_OK) return fail(err, "bluedroid init", rc);
  if ((rc = esp_bluedroid_enable()) != ESP_OK) return fail(err, "bluedroid enable", rc);
  g_session = true;
  if ((rc = esp_ble_gap_register_callback(gap_cb)) != ESP_OK) return fail(err, "gap callback", rc);
  if ((rc = esp_ble_gatts_register_callback(gatts_cb)) != ESP_OK) return fail(err, "gatts callback", rc);

  esp_ble_auth_req_t auth = ESP_LE_AUTH_REQ_SC_MITM_BOND;
  esp_ble_io_cap_t io = ESP_IO_CAP_IO;  // DisplayYesNo -> numeric comparison with a phone
  uint8_t keySize = 16, initKey = ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK,
          rspKey = ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK;
  uint8_t onlySpecified = ESP_BLE_ONLY_ACCEPT_SPECIFIED_AUTH_ENABLE, oob = ESP_BLE_OOB_DISABLE;
  if ((rc = esp_ble_gap_set_security_param(ESP_BLE_SM_AUTHEN_REQ_MODE, &auth, sizeof auth)) != ESP_OK ||
      (rc = esp_ble_gap_set_security_param(ESP_BLE_SM_IOCAP_MODE, &io, sizeof io)) != ESP_OK ||
      (rc = esp_ble_gap_set_security_param(ESP_BLE_SM_MAX_KEY_SIZE, &keySize, 1)) != ESP_OK ||
      (rc = esp_ble_gap_set_security_param(ESP_BLE_SM_MIN_KEY_SIZE, &keySize, 1)) != ESP_OK ||
      (rc = esp_ble_gap_set_security_param(ESP_BLE_SM_SET_INIT_KEY, &initKey, 1)) != ESP_OK ||
      (rc = esp_ble_gap_set_security_param(ESP_BLE_SM_SET_RSP_KEY, &rspKey, 1)) != ESP_OK ||
      (rc = esp_ble_gap_set_security_param(ESP_BLE_SM_ONLY_ACCEPT_SPECIFIED_SEC_AUTH, &onlySpecified, 1)) !=
          ESP_OK ||
      (rc = esp_ble_gap_set_security_param(ESP_BLE_SM_OOB_SUPPORT, &oob, 1)) != ESP_OK)
    return fail(err, "security parameters", rc);
  if ((rc = esp_ble_gatt_set_local_mtu(kLocalMtu)) != ESP_OK) return fail(err, "local MTU", rc);

  // FORGET PHONE chosen while the radio was off: drop the bonds before anyone can connect
  if (forget_flag(false, false)) {
    remove_bonds_except(nullptr, nullptr);
    forget_flag(false, true);
  }

  if ((rc = esp_ble_gatts_app_register(kAppId)) != ESP_OK) return fail(err, "gatt app", rc);
  const uint32_t t0 = millis();
  while (!g_advStarted && !g_setupFail && millis() - t0 < kSetupTimeoutMs) delay(10);
  if (!g_advStarted) return fail(err, g_setupFail ? "GATT / advertising setup" : "setup timeout", ESP_FAIL);

  g_on = true;
  g_idle.start(millis());
  if (Serial) Serial.printf("ripar: ble ON as %s (bonds %d)\n", g_name.c_str(), esp_ble_get_bond_device_num());
  return true;
}

void ble_link_disable() {
  if (!g_mtx) return;  // never enabled
  teardown();
}

bool ble_link_on() { return g_on; }

bool ble_link_radio_alive() { return esp_bt_controller_get_status() != ESP_BT_CONTROLLER_STATUS_IDLE; }

std::string ble_link_name() { return g_on ? g_name : std::string(); }

void ble_link_forget_phone() {
  if (!g_on) {
    forget_flag(true, false);
    return;
  }
  bool connected;
  esp_bd_addr_t bda;
  {
    Lock l;
    connected = g_link.connected;
    std::memcpy(bda, g_link.bda, sizeof bda);
  }
  remove_bonds_except(nullptr, nullptr);
  if (connected) esp_ble_gap_disconnect(bda);
}

int ble_link_bonded_count() { return g_on ? esp_ble_get_bond_device_num() : -1; }

void ble_link_pairing_window(bool open) {
  if (!g_mtx) return;
  bool reject = false;
  esp_bd_addr_t bda;
  {
    Lock l;
    g_window = open && g_on;
    if (!g_window && g_link.codePending) {
      g_link.codePending = false;
      reject = true;
      std::memcpy(bda, g_link.secBda, sizeof bda);
    }
  }
  if (reject) esp_ble_confirm_reply(bda, false);
}

bool ble_link_code(uint32_t& code) {
  if (!g_on) return false;
  Lock l;
  if (!g_link.codePending) return false;
  code = g_link.code;
  return true;
}

void ble_link_answer(bool accept) {
  if (!g_on) return;
  esp_bd_addr_t bda;
  {
    Lock l;
    if (!g_link.codePending || !g_window) return;
    g_link.codePending = false;
    g_link.userConfirmed = accept;
    std::memcpy(bda, g_link.secBda, sizeof bda);
  }
  esp_ble_confirm_reply(bda, accept);
}

BleLinkView ble_link_view() {
  BleLinkView v;
  if (!g_on) return v;
  Lock l;
  v.connected = g_link.connected;
  v.authenticated = g_link.authenticated;
  v.mtu = g_link.mtu;
  return v;
}

bool ble_link_poll_line(std::string& line) {
  if (!g_on) return false;
  Lock l;
  return g_lines.pop(line);
}

BleEvt ble_link_tick(uint32_t now, const std::string& status, const std::string& output) {
  if (!g_on) return BleEvt::None;
  bool traffic, code, paired, pairFailed, link, restartAdv, resendTx, resendSt;
  LinkState s;
  {
    Lock l;
    traffic = g_evTraffic;
    code = g_evCode;
    paired = g_evPaired;
    pairFailed = g_evPairFailed;
    link = g_evLink;
    restartAdv = g_evRestartAdv;
    resendTx = g_evResendTx;
    resendSt = g_evResendSt;
    g_evTraffic = g_evCode = g_evPaired = g_evPairFailed = g_evLink = false;
    g_evRestartAdv = g_evResendTx = g_evResendSt = false;
    if (status != g_statusVal) g_statusVal = status;  // what reads return from now on
    s = g_link;
    if (g_link.connected && !g_link.authenticated && !g_link.codePending && !g_link.dropSent &&
        uint32_t(now - g_link.connectedAt) >= kUnauthDropMs)
      g_link.dropSent = true;
  }
  if (traffic) g_idle.touch(now);
  if (paired) remove_bonds_except(s.newBond, s.bda);  // one phone: the new bond replaces the old one
  if (restartAdv && esp_ble_gap_start_advertising(&g_advParams) != ESP_OK && Serial)
    Serial.println("ripar: ble advertising restart failed");
  if (s.connected && !s.authenticated && !s.codePending && !s.dropSent && uint32_t(now - s.connectedAt) >= kUnauthDropMs)
    esp_ble_gap_disconnect(s.bda);

  // STATUS: notified when it changes (and when the phone subscribes)
  if (status != g_lastStatus) {
    g_lastStatus = status;
    g_statusDirty = true;
  }
  if (resendSt) g_statusDirty = true;
  // TX: the QR on screen, sent once per QR (and again when the phone subscribes)
  if (output != g_lastOutput) {
    wipe_str(g_lastOutput);
    g_lastOutput = output;
    wipe_txq();
    g_outputDirty = !g_lastOutput.empty();
  }
  if (resendTx && !g_lastOutput.empty()) {
    wipe_txq();
    g_outputDirty = true;
  }
  const bool ready = s.connected && s.authenticated && g_gattsIf != ESP_GATT_IF_NONE;
  if (!ready) {
    wipe_txq();
  } else {
    if (g_statusDirty && s.stNotify) {
      const size_t n = g_lastStatus.size() > size_t(s.mtu) - 3 ? size_t(s.mtu) - 3 : g_lastStatus.size();
      std::string v = g_lastStatus.substr(0, n);
      if (esp_ble_gatts_send_indicate(g_gattsIf, s.connId, g_handles[IDX_ST_VAL], uint16_t(v.size()),
                                      reinterpret_cast<uint8_t*>(&v[0]), false) == ESP_OK)
        g_statusDirty = false;
    }
    if (g_outputDirty && s.txNotify) {
      wipe_txq();
      for (std::string& c : chunk_for_mtu(g_lastOutput + "\n", s.mtu)) g_txq.push_back(std::move(c));
      g_outputDirty = false;
    }
    if (!s.txNotify) wipe_txq();
    for (int i = 0; i < kTxPerPass && !g_txq.empty() && !s.congested; i++) {
      std::string& c = g_txq.front();
      if (esp_ble_gatts_send_indicate(g_gattsIf, s.connId, g_handles[IDX_TX_VAL], uint16_t(c.size()),
                                      reinterpret_cast<uint8_t*>(&c[0]), false) != ESP_OK)
        break;
      wipe_str(c);
      g_txq.pop_front();
    }
  }

  if (g_idle.expired(now)) {
    if (Serial) Serial.println("ripar: ble idle for 5 min: radio off");
    teardown();
    return BleEvt::AutoOff;
  }
  if (code) return BleEvt::CodeShown;
  if (paired) return BleEvt::Paired;
  if (pairFailed) return BleEvt::PairFailed;
  if (link) return BleEvt::LinkChange;
  return BleEvt::None;
}

}  // namespace ripar

#endif  // RIPAR_BLE
