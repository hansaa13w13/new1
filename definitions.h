#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#define BOARD_BW16

#define LED_PIN  10

inline void led_init()  { pinMode(LED_PIN, OUTPUT); digitalWrite(LED_PIN, HIGH); }
inline void led_on()    { digitalWrite(LED_PIN, LOW);  }
inline void led_off()   { digitalWrite(LED_PIN, HIGH); }

inline void led_blink(int n, int ms) {
  for (int i = 0; i < n; i++) {
    led_on();  delay(ms);
    led_off(); delay(ms);
  }
}

#define DBG(...)   Serial.print(__VA_ARGS__)
#define DBGLN(...) Serial.println(__VA_ARGS__)

#endif
