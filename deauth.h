#ifndef DEAUTH_H
#define DEAUTH_H

#include <Arduino.h>

// ── Durum ─────────────────────────────────────────────────────────────────────
extern bool    deauth_active;
extern char    deauth_ssid[64];
extern int     deauth_channel;

// ── API ───────────────────────────────────────────────────────────────────────
void deauth_start(int net_idx);   // tarama listesindeki ağı hedef al
void deauth_stop();
void deauth_loop();               // her loop'ta çağrılır

#endif
