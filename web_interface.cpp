#include <WiFi.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
#include "web_interface.h"
#include "deauth.h"
#include "definitions.h"

static WiFiServer _srv(80);

// ── Tarama sonuçları ──────────────────────────────────────────────────────────
static int  _net_count    = 0;
static bool _scan_needed  = true;
static unsigned long _scan_time = 0;

// ── Tek satır oku ─────────────────────────────────────────────────────────────
static String read_line(WiFiClient& c, unsigned long ms) {
  String s;
  unsigned long t = millis() + ms;
  while (millis() < t) {
    if (!c.available()) { delay(1); continue; }
    char ch = c.read();
    if (ch == '\n') break;
    if (ch != '\r') s += ch;
  }
  return s;
}

// ── URI parse ────────────────────────────────────────────────────────────────
static String read_uri(WiFiClient& c) {
  String req = read_line(c, 500);
  DBG(F("[WEB] ")); DBGLN(req);
  while (true) {              // headerları tüket
    String h = read_line(c, 200);
    if (h.length() == 0) break;
  }
  int s1 = req.indexOf(' ');
  int s2 = req.lastIndexOf(' ');
  if (s1 < 0 || s1 == s2) return "/";
  String uri = req.substring(s1 + 1, s2);
  if (uri.startsWith(F("http://")) || uri.startsWith(F("https://"))) {
    int sl = uri.indexOf('/', 8);
    uri = (sl >= 0) ? uri.substring(sl) : "/";
  }
  int q = uri.indexOf('?');
  if (q >= 0) uri = uri.substring(0, q);
  if (uri.length() == 0) uri = "/";
  return uri;
}

// ── HTTP yardımcıları ─────────────────────────────────────────────────────────
static void send_header(WiFiClient& c, int code, const char* ct) {
  const char* r = (code==200)?"OK":(code==204)?"No Content":"Found";
  c.print(F("HTTP/1.1 ")); c.print(code); c.print(' '); c.println(r);
  c.println(F("Connection: close"));
  c.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
  c.println(F("Pragma: no-cache"));
  if (ct && *ct) { c.print(F("Content-Type: ")); c.println(ct); }
  c.println();
}

static void send_redirect(WiFiClient& c, const char* loc) {
  c.print(F("HTTP/1.1 302 Found\r\nConnection: close\r\n"
            "Cache-Control: no-cache,no-store\r\nContent-Length: 0\r\nLocation: "));
  c.print(loc);
  c.print(F("\r\n\r\n"));
}

// ── CSS ───────────────────────────────────────────────────────────────────────
static const char CSS[] =
  "*{box-sizing:border-box;margin:0;padding:0}"
  "body{font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:18px}"
  "h1{color:#58a6ff;font-size:1.6em;margin-bottom:4px}"
  ".sub{color:#8b949e;font-size:.82em;margin-bottom:14px}"
  ".alert{padding:10px 14px;border-radius:7px;margin-bottom:14px;font-weight:600}"
  ".alert-red{background:#3d1a1a;border:1px solid #f85149;color:#f85149}"
  ".card{background:#161b22;border:1px solid #30363d;border-radius:10px;"
        "padding:16px;margin-bottom:14px}"
  "h2{color:#f0f6fc;font-size:1em;margin-bottom:10px}"
  "table{width:100%;border-collapse:collapse;font-size:.85em}"
  "th{background:#21262d;color:#8b949e;padding:7px 9px;text-align:left;"
     "font-size:.75em;text-transform:uppercase}"
  "td{padding:7px 9px;border-top:1px solid #21262d;vertical-align:middle}"
  "tr:hover td{background:#1c2128}"
  ".tag{padding:2px 6px;border-radius:4px;font-size:.72em;font-weight:700}"
  ".open{background:#0d2818;color:#3fb950}"
  ".wpa{background:#0d1f3c;color:#58a6ff}"
  ".wep{background:#2d1f0e;color:#f0883e}"
  ".btn{display:inline-block;padding:5px 12px;border:none;border-radius:5px;"
       "font-size:.8em;font-weight:700;cursor:pointer;text-decoration:none;"
       "color:#fff;background:#b62324}"
  ".btn-blue{background:#1f6feb}"
  ".btn-gray{background:#21262d;color:#c9d1d9;border:1px solid #30363d}"
  ".ts{color:#8b949e;font-size:.76em;margin-top:5px}";

// ── Şifreleme etiketi ─────────────────────────────────────────────────────────
static const char* enc_tag(int enc) {
  if (enc == 7) return "<span class='tag open'>OPEN</span>";
  if (enc == 5) return "<span class='tag wep'>WEP</span>";
  return "<span class='tag wpa'>WPA2</span>";
}

// ── Tarama ───────────────────────────────────────────────────────────────────
static void do_scan() {
  DBGLN(F("[SCAN] Basliyor..."));
  delay(200);
  int n = WiFi.scanNetworks();
  DBG(F("[SCAN] Sonuc: ")); DBGLN(n);
  _net_count   = (n > 0) ? n : 0;
  _scan_time   = millis();
  _scan_needed = false;
}

// ── Deauth argümanını parse et ("/deauth?n=3" → 3) ───────────────────────────
static int parse_net_arg(WiFiClient& c_unused, const String& full_req) {
  // full_req: "GET /deauth?n=2 HTTP/1.1"
  int qi = full_req.indexOf('?');
  if (qi < 0) return -1;
  int ni = full_req.indexOf(F("n="), qi);
  if (ni < 0) return -1;
  return full_req.substring(ni + 2).toInt();
}

// ── read_uri_full: URI + tam istek satırını birlikte döndür ──────────────────
static String _last_req;   // son istek satırı (argüman parse için)

static String read_uri_full(WiFiClient& c) {
  _last_req = read_line(c, 500);
  DBG(F("[WEB] ")); DBGLN(_last_req);
  while (true) {
    String h = read_line(c, 200);
    if (h.length() == 0) break;
  }
  int s1 = _last_req.indexOf(' ');
  int s2 = _last_req.lastIndexOf(' ');
  if (s1 < 0 || s1 == s2) return "/";
  String uri = _last_req.substring(s1 + 1, s2);
  if (uri.startsWith(F("http://")) || uri.startsWith(F("https://"))) {
    int sl = uri.indexOf('/', 8);
    uri = (sl >= 0) ? uri.substring(sl) : "/";
  }
  // Sorgu parametrelerini URI'dan ayır ama koru
  int q = uri.indexOf('?');
  String path = (q >= 0) ? uri.substring(0, q) : uri;
  if (path.length() == 0) path = "/";
  return path;
}

// ── Ana sayfa ─────────────────────────────────────────────────────────────────
static void handle_root(WiFiClient& c) {
  send_header(c, 200, "text/html; charset=utf-8");

  c.print(F("<!DOCTYPE html><html lang='tr'><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>BW16 Guvenlik</title><style>"));
  c.print(CSS);
  c.print(F("</style></head><body>"
    "<h1>BW16 Guvenlik Araci</h1>"
    "<p class='sub'>RTL8720DN</p>"));

  // ── Deauth durum bandı ──
  if (deauth_active) {
    char buf[120];
    snprintf(buf, sizeof(buf),
      "<div class='alert alert-red'>"
      "&#9889; DEAUTH aktif &mdash; Hedef: <b>%s</b> &nbsp;"
      "<a href='/stop' class='btn btn-gray'>Durdur</a></div>",
      deauth_ssid);
    c.print(buf);
  }

  // ── Ağ listesi kartı ──
  c.print(F("<div class='card'><h2>Ag Listesi"));
  char buf2[64];
  snprintf(buf2, sizeof(buf2), " &mdash; %d ag</h2>", _net_count);
  c.print(buf2);

  snprintf(buf2, sizeof(buf2),
    "<p class='ts'>Son tarama: %lu sn once</p>",
    (millis() - _scan_time) / 1000UL);
  c.print(buf2);

  if (_net_count == 0) {
    c.print(F("<p style='color:#8b949e;margin-top:10px'>Ag bulunamadi.</p>"));
  } else {
    c.print(F("<table><tr>"
      "<th>#</th><th>SSID</th><th>RSSI</th><th>Guvenlik</th><th>Islem</th>"
      "</tr>"));
    for (int i = 0; i < _net_count; i++) {
      char row[280];
      snprintf(row, sizeof(row),
        "<tr><td>%d</td><td>%s</td><td>%ld dBm</td><td>%s</td>"
        "<td><a href='/deauth?n=%d' class='btn'>Deauth</a></td></tr>",
        i + 1,
        WiFi.SSID((uint8_t)i),
        (long)WiFi.RSSI((uint8_t)i),
        enc_tag((int)WiFi.encryptionType((uint8_t)i)),
        i);
      c.print(row);
    }
    c.print(F("</table>"));
  }

  c.print(F("</div>"
    "<a href='/scan' class='btn btn-blue' "
    "style='display:inline-block;margin-top:4px'>Yeniden Tara</a>"
    "</body></html>"));
}

// ── Başlat ────────────────────────────────────────────────────────────────────
void web_begin() {
  _srv.begin();
  DBGLN(F("[WEB] Baslatildi port 80"));
}

// ── Loop ──────────────────────────────────────────────────────────────────────
void web_handle() {
  if (_scan_needed) do_scan();

  WiFiClient client = _srv.available();
  if (!client) return;

  unsigned long t = millis() + 400;
  while (!client.available() && millis() < t) delay(1);
  if (!client.available()) { client.stop(); return; }

  String path = read_uri_full(client);

  if (path == F("/scan")) {
    do_scan();
    handle_root(client);
  }
  else if (path == F("/deauth")) {
    // n parametresini _last_req'den çıkar
    int qi = _last_req.indexOf('?');
    int ni = (qi >= 0) ? _last_req.indexOf(F("n="), qi) : -1;
    int idx = (ni >= 0) ? _last_req.substring(ni + 2).toInt() : -1;
    if (idx >= 0 && idx < _net_count) {
      deauth_start(idx);
    }
    handle_root(client);
  }
  else if (path == F("/stop")) {
    deauth_stop();
    handle_root(client);
  }
  else if (path == F("/generate_204") || path == F("/gen_204") || path == F("/204")) {
    send_header(client, 204, nullptr);
  }
  else if (path == F("/")) {
    handle_root(client);
  }
  else {
    send_redirect(client, "http://192.168.4.1/");
  }

  client.flush();
  delay(5);
  client.stop();
}
