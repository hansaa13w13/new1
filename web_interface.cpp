#include <WiFi.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
#include "web_interface.h"
#include "deauth.h"
#include "definitions.h"

static WiFiServer _srv(80);
static unsigned long _scan_time = 0;

// ── Tek satir oku ─────────────────────────────────────────────────────────────
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

// ── Istek satirini oku, tum headerlari tüket ────────────────────────────────
static String _last_req;

static String read_uri(WiFiClient& c) {
  _last_req = read_line(c, 500);
  DBG(F("[WEB] ")); DBGLN(_last_req);
  while (true) {
    String h = read_line(c, 200);
    if (h.length() == 0) break;
  }
  int s1 = _last_req.indexOf(' ');
  int s2 = _last_req.lastIndexOf(' ');
  if (s1 < 0 || s1 == s2) return F("/");
  String uri = _last_req.substring(s1 + 1, s2);
  if (uri.startsWith(F("http://")) || uri.startsWith(F("https://"))) {
    int sl = uri.indexOf('/', 8);
    uri = (sl >= 0) ? uri.substring(sl) : F("/");
  }
  int q = uri.indexOf('?');
  return (q >= 0) ? uri.substring(0, q) : uri;
}

// ── HTTP yardimcilari ────────────────────────────────────────────────────────
static void send_header(WiFiClient& c, int code, const char* ct) {
  const char* r = (code == 200) ? "OK" : (code == 204) ? "No Content" : "Found";
  c.print(F("HTTP/1.1 ")); c.print(code); c.print(' '); c.println(r);
  c.println(F("Connection: close"));
  c.println(F("Cache-Control: no-cache, no-store, must-revalidate"));
  if (ct && *ct) { c.print(F("Content-Type: ")); c.println(ct); }
  c.println();
}

static void send_redirect(WiFiClient& c, const char* loc) {
  c.print(F("HTTP/1.1 302 Found\r\nConnection: close\r\n"
            "Cache-Control: no-cache,no-store\r\nContent-Length: 0\r\nLocation: "));
  c.print(loc);
  c.print(F("\r\n\r\n"));
}

// ── CSS ──────────────────────────────────────────────────────────────────────
static const char CSS[] PROGMEM =
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

static const char* enc_label(uint8_t enc) {
  if (enc == 7) return "<span class='tag open'>OPEN</span>";
  if (enc == 5) return "<span class='tag wep'>WEP</span>";
  return "<span class='tag wpa'>WPA2</span>";
}

// ── BSSID'yi XX:XX:... formatinda string'e cevir ────────────────────────────
static void bssid_str(const uint8_t* b, char* out) {
  snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
           b[0], b[1], b[2], b[3], b[4], b[5]);
}

// ── Ana sayfa ────────────────────────────────────────────────────────────────
static void handle_root(WiFiClient& c) {
  send_header(c, 200, "text/html; charset=utf-8");

  c.print(F("<!DOCTYPE html><html lang='tr'><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>BW16 Guvenlik</title><style>"));
  c.print(CSS);
  c.print(F("</style></head><body>"
    "<h1>BW16 Guvenlik Araci</h1>"
    "<p class='sub'>Ai-Thinker BW16 &mdash; RTL8720DN</p>"));

  // Deauth durum bandi
  if (deauth_active) {
    char buf[140];
    snprintf(buf, sizeof(buf),
      "<div class='alert alert-red'>"
      "&#9889; DEAUTH aktif &mdash; Hedef: <b>%s</b> &nbsp;"
      "<a href='/stop' class='btn btn-gray'>Durdur</a></div>",
      deauth_ssid);
    c.print(buf);
  }

  // Ag listesi karti
  c.print(F("<div class='card'><h2>Ag Listesi"));
  {
    char buf[64];
    snprintf(buf, sizeof(buf), " &mdash; %d ag bulundu</h2>", net_count);
    c.print(buf);
    snprintf(buf, sizeof(buf),
      "<p class='ts'>Son tarama: %lu sn once</p>",
      (millis() - _scan_time) / 1000UL);
    c.print(buf);
  }

  if (net_count == 0) {
    c.print(F("<p style='color:#8b949e;margin-top:10px'>"
              "Ag bulunamadi. Yeniden tara butonuna basin.</p>"));
  } else {
    c.print(F("<table><tr>"
      "<th>#</th><th>SSID</th><th>BSSID</th>"
      "<th>Ch</th><th>RSSI</th><th>Guvenlik</th><th>Islem</th>"
      "</tr>"));
    for (int i = 0; i < net_count; i++) {
      char bssid[18];
      bssid_str(net_list[i].bssid, bssid);
      char row[320];
      snprintf(row, sizeof(row),
        "<tr><td>%d</td><td>%s</td><td style='font-size:.75em'>%s</td>"
        "<td>%d</td><td>%ld</td><td>%s</td>"
        "<td><a href='/deauth?n=%d' class='btn'>Deauth</a></td></tr>",
        i + 1,
        net_list[i].ssid,
        bssid,
        net_list[i].channel,
        (long)net_list[i].rssi,
        enc_label(net_list[i].enc),
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

// ── "Taraniyor..." bekleme sayfasi (otomatik yenileme) ───────────────────────
static void handle_scanning(WiFiClient& c) {
  send_header(c, 200, "text/html; charset=utf-8");
  c.print(F("<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta http-equiv='refresh' content='5;url=/'>"
    "<title>Taraniyor...</title><style>"
    "body{font-family:sans-serif;background:#0d1117;color:#c9d1d9;"
    "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
    ".box{text-align:center}"
    "h2{color:#58a6ff;margin-bottom:12px}p{color:#8b949e}"
    "</style></head><body>"
    "<div class='box'><h2>&#128246; Aglar Taraniyor...</h2>"
    "<p>Lutfen bekleyin, 5 saniye sonra ana sayfaya yonlendirileceksiniz.</p>"
    "</div></body></html>"));
}

// ── Baslat ───────────────────────────────────────────────────────────────────
void web_begin() {
  _srv.begin();
  _scan_time = millis();
  DBGLN(F("[WEB] Baslatildi port 80"));
}

// ── Dongu ────────────────────────────────────────────────────────────────────
static bool _scan_pending = false;

void web_handle() {
  // Bekleyen tarama varsa simdi yap (cevap gonderildikten sonra)
  if (_scan_pending) {
    _scan_pending = false;
    scan_networks();
    _scan_time = millis();
  }

  WiFiClient client = _srv.available();
  if (!client) return;

  unsigned long t = millis() + 400;
  while (!client.available() && millis() < t) delay(1);
  if (!client.available()) { client.stop(); return; }

  String path = read_uri(client);

  if (path == F("/scan")) {
    handle_scanning(client);
    _scan_pending = true;   // bir sonraki loop'ta tara
  }
  else if (path == F("/deauth")) {
    int qi = _last_req.indexOf('?');
    int ni = (qi >= 0) ? _last_req.indexOf(F("n="), qi) : -1;
    int idx = (ni >= 0) ? _last_req.substring(ni + 2).toInt() : -1;
    if (idx >= 0 && idx < net_count) {
      deauth_start(idx);
    }
    handle_root(client);
  }
  else if (path == F("/stop")) {
    deauth_stop();
    handle_root(client);
  }
  else if (path == F("/favicon.ico") ||
           path == F("/generate_204") ||
           path == F("/gen_204")      ||
           path == F("/204")) {
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
