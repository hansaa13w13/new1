#ifndef DEFINITIONS_H
#define DEFINITIONS_H

// ── Kart ──────────────────────────────────────────────────────────────────────
#define BOARD_BW16          // Ai-Thinker BW16 (RTL8720DN)

// ── LED ───────────────────────────────────────────────────────────────────────
#define LED_PIN  10         // BW16 dahili LED pini (aktif-LOW)

inline void led_init()  { pinMode(LED_PIN, OUTPUT); digitalWrite(LED_PIN, HIGH); }
inline void led_on()    { digitalWrite(LED_PIN, LOW);  }
inline void led_off()   { digitalWrite(LED_PIN, HIGH); }

inline void led_blink(int n, int ms) {
  for (int i = 0; i < n; i++) {
    led_on();  delay(ms);
    led_off(); delay(ms);
  }
}

// ── Seri debug ────────────────────────────────────────────────────────────────
#define DBG(...)   Serial.print(__VA_ARGS__)
#define DBGLN(...) Serial.println(__VA_ARGS__)

#endif
