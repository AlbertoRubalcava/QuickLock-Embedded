#include <WiFi.h>
#include <WebServer.h>
#include <Wire.h>
#include <Adafruit_PN532.h>

Adafruit_PN532 nfc(-1, -1);

// ---------------- WIFI SETTINGS -----------------
const char* ssid = "Wifi Name";
const char* password = "Password";

// ESP32 web server running on port 80
WebServer server(80);

// ---------------- NFC SETTINGS ------------------
const int blueLedPin = 2;
String authorizedUID = "4C:05:3F:06";

String lastNFCUID = "";
bool nfcAuthorized = false; // Reflects current LED state

// ---------------- HTTP HANDLERS ------------------
void handleUnlock() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"status\":\"unlocked\"}");
  digitalWrite(blueLedPin, HIGH);
  nfcAuthorized = true;
}

void handleLock() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"status\":\"locked\"}");
  digitalWrite(blueLedPin, LOW);
  nfcAuthorized = false;
}

void handleCORS() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.sendHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  server.sendHeader("Access-Control-Allow-Headers", "Content-Type");
  server.send(204);
}

// ---------------- SETUP ------------------
void setup() {
  Serial.begin(115200);
  pinMode(blueLedPin, OUTPUT);
  digitalWrite(blueLedPin, LOW);

  // ---------------- WIFI CONNECT ----------------
  Serial.print("Connecting to WiFi ");
  Serial.println(ssid);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConnected!");
  Serial.print("ESP32 IP Address: ");
  Serial.println(WiFi.localIP());

  // ---------------- HTTP SERVER ----------------
  server.on("/unlock", HTTP_OPTIONS, handleCORS);
  server.on("/lock", HTTP_OPTIONS, handleCORS);

  server.on("/unlock", HTTP_POST, handleUnlock);
  server.on("/lock", HTTP_POST, handleLock);

  server.on("/nfc-status", HTTP_GET, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(200, "application/json",
      String("{\"uid\":\"") + lastNFCUID + "\",\"authorized\":" + (nfcAuthorized ? "true" : "false") + "}"
    );
  });

  server.onNotFound([]() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(404, "text/plain", "Not found");
  });

  server.begin();
  Serial.println("HTTP server started");

  // ---------------- NFC SETUP --------------------
  nfc.begin();
  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata) {
    Serial.println("Didn't find PN532");
    while (1);
  }
  nfc.SAMConfig();
  Serial.println("Waiting for NFC card...");
}

// ---------------- LOOP ------------------
void loop() {
  server.handleClient();  // handle API calls

  uint8_t uid[7];
  uint8_t uidLength;

  if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 20)) {
    String uidString = "";
    for (uint8_t i = 0; i < uidLength; i++) {
      if (uid[i] < 0x10) uidString += "0";
      uidString += String(uid[i], HEX);
      if (i < uidLength - 1) uidString += ":";
    }
    uidString.toUpperCase();
    lastNFCUID = uidString;

    if (uidString == authorizedUID) {
      Serial.println("Authorized via NFC");
      // Toggle LED depending on current state
      nfcAuthorized = !nfcAuthorized;
      digitalWrite(blueLedPin, nfcAuthorized ? HIGH : LOW);
    } else {
      Serial.println("Unauthorized NFC card");
    }

    delay(500);
  }
}
