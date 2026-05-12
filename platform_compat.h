#ifndef PLATFORM_COMPAT_H
#define PLATFORM_COMPAT_H

#include <WiFi.h>
#include <WiFiUdp.h>
#include <IPAddress.h>

// AP'yi 192.168.4.1 IP'siyle baslatir.
inline void wifi_ap_start(const char* ssid, const char* pass, int ch = 1) {
  char ch_str[4];
  snprintf(ch_str, sizeof(ch_str), "%d", ch);

  WiFi.config(IPAddress(192,168,4,1),
              IPAddress(192,168,4,1),
              IPAddress(255,255,255,0));

  if (!pass || pass[0] == '\0') {
    WiFi.apbegin((char*)ssid, ch_str);
  } else {
    WiFi.apbegin((char*)ssid, (char*)pass, ch_str);
  }

  delay(500);

  // apbegin() bazi SDK surumlerinde IP'yi sifirlar, tekrar ata
  WiFi.config(IPAddress(192,168,4,1),
              IPAddress(192,168,4,1),
              IPAddress(255,255,255,0));
}

#endif
