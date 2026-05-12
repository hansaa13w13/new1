// ─── BW16 RTL8720DN — Wi-Fi Güvenlik Aracı ───────────────────────────────────
// Arduino IDE: Ai-Thinker BW16 (RTL8720DN) kartını seçin
// Seri monitör: 115200 baud
//
// ADIM 5 — Deauth: WiFi istemcilerini bağlantıdan düşür
// ─────────────────────────────────────────────────────────────────────────────

#include <Arduino.h>
#include <WiFi.h>
#include "definitions.h"
#include "platform_compat.h"
#include "web_interface.h"
#include "deauth.h"

#define AP_SSID "BW16-Test"
#define AP_PASS "12345678"
#define AP_CH   1

void setup() {
  Serial.begin(115200);
  delay(800);

  DBGLN(F("\n========================================"));
  DBGLN(F("  BW16 RTL8720DN — Güvenlik Aracı"));
  DBGLN(F("  ADIM 5: Deauth"));
  DBGLN(F("========================================"));

  led_init();
  DBGLN(F("[1/3] LED hazır"));

  DBG(F("[2/3] AP -> ")); DBGLN(F(AP_SSID));
  wifi_ap_start(AP_SSID, AP_PASS, AP_CH);
  DBG(F("      IP : ")); DBGLN(WiFi.localIP());

  web_begin();
  DBGLN(F("[3/3] HTTP sunucu hazır"));

  DBGLN(F("========================================"));
  DBG(F("  http://")); DBGLN(WiFi.localIP());
  DBGLN(F("========================================\n"));

  led_blink(5, 100);
}

void loop() {
  WiFi.disablePowerSave();
  deauth_loop();    // aktifse deauth paketleri gönder
  web_handle();     // HTTP isteklerini işle
  delay(5);
}
