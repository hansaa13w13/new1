#ifndef DEAUTH_H
#define DEAUTH_H

#include <Arduino.h>

#define MAX_NETWORKS 20

struct NetInfo {
  char    ssid[33];
  uint8_t bssid[6];
  int     channel;
  int32_t rssi;
  uint8_t enc;
};

// Tarama sonuclari (web_interface.cpp ile paylasilan)
extern NetInfo net_list[MAX_NETWORKS];
extern int     net_count;

// Deauth durumu
extern bool deauth_active;
extern char deauth_ssid[33];

// API
void scan_networks();
void deauth_start(int net_idx);
void deauth_stop();
void deauth_loop();

#endif
