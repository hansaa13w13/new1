#ifndef EVIL_TWIN_H
#define EVIL_TWIN_H

#include <Arduino.h>
#include "WiFiClient.h"

// ─── Yapılandırma ──────────────────────────────────────────────────────────────
#define ET_MAX_PASSWORDS       15
#define ET_AP_IP_STR           "192.168.1.1"
#define ET_DEAUTH_INTERVAL_MS  300UL      // Deauth burst aralığı (ms)
#define ET_VERIFY_TIMEOUT_MS   10000UL    // Şifre doğrulama zaman aşımı (ms)
#define ET_RETRACK_INTERVAL_MS 25000UL    // Hedef yeniden tarama aralığı (ms)

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
extern bool       evil_twin_dual_band;   // İkinci band aktif mi?
extern uint8_t    evil_twin_bssid2[6];   // 5GHz/karşı band BSSID
extern int        evil_twin_channel2;    // 5GHz/karşı band kanal
extern String     evil_twin_ssid2;       // Karşı band SSID (farklıysa)
// ─────────────────────────────────────────────────────────────────────────────
extern ETPassword et_passwords[ET_MAX_PASSWORDS];
extern int        et_password_count;
extern bool       et_last_verify_ok;
extern String     et_last_verify_pass;

// ─── Fonksiyon bildirimleri ───────────────────────────────────────────────────
// scan_idx: RTL8720dn-Deauther.ino içindeki scan_results dizisinin indeksi
void start_evil_twin(int scan_idx);
void stop_evil_twin();
void evil_twin_loop();

// Web isteği yönlendirme:
// Captive portal isteği ise işler ve true döner; admin isteği ise false döner.
bool evil_twin_portal_handle(WiFiClient &client,
                             const String &request,
                             const String &path);

#endif
