/*
 * TANOD ESP32 test node (Section 3.6, Table 6)
 *
 * NORMAL mode : publishes a small sensor reading to the simulated server
 *               about once per second (baseline traffic).
 * HACKED mode : reproduces the network behavior of a compromised device for
 *               Tests T6 to T8. No real exploit, no real malware.
 *
 * SAFETY: hacked mode is for the isolated test network only, on the
 * researchers' own devices. Do not flash a node with real Wi-Fi credentials
 * of any other network.
 *
 * Serial commands (115200 baud, newline-terminated), sent from the attacker
 * laptop during formal trials:
 *   HACK SCAN      T6: scan the other test devices
 *   HACK UPLOAD    T7: upload a dummy file to the simulated server
 *   HACK BEACON    T8: contact an unknown test server once per second
 *   NORMAL         end the trial, back to normal mode
 *   STATUS         print the current mode
 * The test button (BUTTON_PIN) cycles NORMAL -> SCAN -> UPLOAD -> BEACON for demos.
 *
 * Every mode change prints a line like
 *   TANOD_MODE,<millis>,<epoch_s>,HACK_SCAN
 * so the attacker laptop can log the trial start time. Epoch time comes from
 * the gateway (NTP), which all devices use as their time source.
 */
#include <WiFi.h>
#include <HTTPClient.h>
#include <time.h>

// ---- test network config (fill in, never commit real secrets) ----------
const char* WIFI_SSID = "TANOD-TEST";
const char* WIFI_PASS = "change-me";
const char* NTP_SERVER = "192.168.50.1";           // the gateway
const char* SERVER_HOST = "10.10.0.5";             // simulated internet server
const uint16_t SERVER_PORT = 8000;
const char* UNKNOWN_HOST = "10.10.0.99";           // unknown test server for T8
const uint16_t UNKNOWN_PORT = 4444;
const char* UPLOAD_URL = "http://10.10.0.66:8080/upload";  // T7 sink on the server laptop
// Other test devices to scan in T6 (set to the other nodes and the camera)
const char* SCAN_TARGETS[] = {"192.168.50.11", "192.168.50.12", "192.168.50.13", "192.168.50.20"};
const uint16_t SCAN_PORT_FIRST = 20, SCAN_PORT_LAST = 120;

const int BUTTON_PIN = 0;   // BOOT button on most dev boards
const int LED_PIN = 2;

enum Mode { NORMAL, HACK_SCAN, HACK_UPLOAD, HACK_BEACON };
Mode mode = NORMAL;
const char* MODE_NAMES[] = {"NORMAL", "HACK_SCAN", "HACK_UPLOAD", "HACK_BEACON"};

unsigned long lastReport = 0, lastBeacon = 0;
size_t scanIndex = 0;
uint16_t scanPort = SCAN_PORT_FIRST;
bool uploadDone = false;

void setMode(Mode m) {
  mode = m;
  scanIndex = 0;
  scanPort = SCAN_PORT_FIRST;
  uploadDone = false;
  time_t now;
  time(&now);
  Serial.printf("TANOD_MODE,%lu,%ld,%s\n", millis(), (long)now, MODE_NAMES[m]);
  digitalWrite(LED_PIN, m == NORMAL ? LOW : HIGH);
}

void handleSerial() {
  if (!Serial.available()) return;
  String cmd = Serial.readStringUntil('\n');
  cmd.trim();
  cmd.toUpperCase();
  if (cmd == "HACK SCAN") setMode(HACK_SCAN);
  else if (cmd == "HACK UPLOAD") setMode(HACK_UPLOAD);
  else if (cmd == "HACK BEACON") setMode(HACK_BEACON);
  else if (cmd == "NORMAL") setMode(NORMAL);
  else if (cmd == "STATUS") Serial.printf("TANOD_STATUS,%s\n", MODE_NAMES[mode]);
  else if (cmd.length()) Serial.printf("TANOD_ERR,unknown command: %s\n", cmd.c_str());
}

void handleButton() {
  static bool last = HIGH;
  static unsigned long lastChange = 0;
  bool now = digitalRead(BUTTON_PIN);
  if (now != last && millis() - lastChange > 50) {
    lastChange = millis();
    if (now == LOW) setMode((Mode)((mode + 1) % 4));
    last = now;
  }
}

// ---- normal behavior --------------------------------------------------
void normalReport() {
  if (millis() - lastReport < 1000) return;
  lastReport = millis();
  // TODO(groupmates/Narz): replace with the real sensor reading and the
  // protocol used in baseline collection (MQTT or HTTP). Keep it identical
  // between baseline and attack tests.
  WiFiClient c;
  if (c.connect(SERVER_HOST, SERVER_PORT, 500)) {
    c.printf("GET /report?temp=%d HTTP/1.0\r\nHost: %s\r\n\r\n", 25 + (int)random(0, 5), SERVER_HOST);
    c.stop();
  }
}

// ---- hacked mode behaviors (Table 6) ------------------------------------
void stepScan() {  // T6: try one port per loop on the other test devices
  const size_t n = sizeof(SCAN_TARGETS) / sizeof(SCAN_TARGETS[0]);
  if (scanIndex >= n) return;  // finished, stay quiet until NORMAL
  String self = WiFi.localIP().toString();
  if (self == SCAN_TARGETS[scanIndex]) { scanIndex++; return; }
  WiFiClient c;
  c.connect(SCAN_TARGETS[scanIndex], scanPort, 50);  // short timeout, closed ports fail fast
  c.stop();
  if (++scanPort > SCAN_PORT_LAST) { scanPort = SCAN_PORT_FIRST; scanIndex++; }
}

void stepUpload() {  // T7: send a dummy file (filler bytes, no real data)
  if (uploadDone) return;
  HTTPClient http;
  http.begin(UPLOAD_URL);
  http.addHeader("Content-Type", "application/octet-stream");
  static uint8_t buf[64 * 1024];
  memset(buf, 'A', sizeof(buf));
  int code = http.POST(buf, sizeof(buf));
  http.end();
  Serial.printf("TANOD_UPLOAD,%lu,%d\n", millis(), code);
  uploadDone = true;
}

void stepBeacon() {  // T8: contact the unknown test server once per second
  if (millis() - lastBeacon < 1000) return;
  lastBeacon = millis();
  WiFiClient c;
  if (c.connect(UNKNOWN_HOST, UNKNOWN_PORT, 500)) {
    c.print("PING\n");
    c.stop();
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  pinMode(LED_PIN, OUTPUT);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) delay(200);
  configTime(8 * 3600, 0, NTP_SERVER);  // Philippine time, synced to the gateway
  Serial.printf("TANOD_READY,%s\n", WiFi.localIP().toString().c_str());
  setMode(NORMAL);
}

void loop() {
  handleSerial();
  handleButton();
  normalReport();  // normal traffic continues in hacked mode too
  switch (mode) {
    case HACK_SCAN: stepScan(); break;
    case HACK_UPLOAD: stepUpload(); break;
    case HACK_BEACON: stepBeacon(); break;
    default: break;
  }
  delay(5);
}
