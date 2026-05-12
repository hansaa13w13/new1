#ifndef PLATFORM_COMPAT_H
#define PLATFORM_COMPAT_H

// ── RTL8720DN / AmebaD WiFi sarmalayıcıları ──────────────────────────────────
#include <WiFi.h>
#include <WiFiUdp.h>
#include <IPAddress.h>

// AP'yi 192.168.4.1 IP'siyle başlat
// AmebaD'de varsayılan AP IP'si 192.168.43.1 olabilir; config() ile zorla.
inline void wifi_ap_start(const char* ssid, const char* pass, int ch = 1) {
  char ch_str[4];
  snprintf(ch_str, sizeof(ch_str), "%d", ch);

  // apbegin() öncesi IP ata
  WiFi.config(IPAddress(192,168,4,1),
              IPAddress(192,168,4,1),
              IPAddress(255,255,255,0));

  if (!pass || pass[0] == '\0') {
    WiFi.apbegin((char*)ssid, ch_str);
  } else {
    WiFi.apbegin((char*)ssid, (char*)pass, ch_str);
  }

  // apbegin() bazı SDK sürümlerinde IP'yi sıfırlar, tekrar ata
  delay(100);
  WiFi.config(IPAddress(192,168,4,1),
              IPAddress(192,168,4,1),
              IPAddress(255,255,255,0));
}

#endif
