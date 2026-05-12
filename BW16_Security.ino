// ─── BW16 RTL8720DN — Wi-Fi Guvenlik Araci ───────────────────────────────────
// Arduino IDE: Ai-Thinker BW16 (RTL8720DN) kartini secin
// Seri monitor: 115200 baud
//
// KURULUM (bir kez yapilir):
//   1. patch_lib.bat dosyasini yonetici olarak calistirin.
//   2. Ardindan bu projeyi derleyip yukleyin.
// ─────────────────────────────────────────────────────────────────────────────

#include <Arduino.h>
#include <WiFi.h>
#include "definitions.h"
#include "platform_compat.h"
#include "web_interface.h"
#include "deauth.h"

#define AP_SSID "BW16-Guvenlik"
#define AP_PASS "12345678"
#define AP_CH   1

void setup() {
  Serial.begin(115200);
  delay(800);

  DBGLN(F("\n========================================"));
  DBGLN(F("  BW16 RTL8720DN - Guvenlik Araci"));
  DBGLN(F("========================================"));

  led_init();

  // AP'yi baslat
  DBG(F("[1/3] AP baslatiliyor -> ")); DBGLN(F(AP_SSID));
  wifi_ap_start(AP_SSID, AP_PASS, AP_CH);
  DBG(F("      IP: ")); DBGLN(WiFi.localIP());

  // AP basladiktan sonra tarama yap
  DBGLN(F("[2/3] Aglar taraniyor..."));
  scan_networks();
  DBG(F("      Bulunan ag: ")); DBGLN(net_count);

  // Web sunucuyu baslat
  web_begin();
  DBGLN(F("[3/3] HTTP sunucu hazir"));

  DBGLN(F("========================================"));
  DBG(F("  http://")); DBGLN(WiFi.localIP());
  DBGLN(F("========================================\n"));

  led_blink(5, 100);
}

void loop() {
  WiFi.disablePowerSave();
  deauth_loop();
  web_handle();
  delay(5);
}
