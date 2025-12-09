#include <WiFi.h>
#include <HTTPClient.h>
#include <Wire.h>
#include <Adafruit_PN532.h>

Adafruit_PN532 nfc(-1, -1);
const int blueLedPin = 2;

const char* ssid = "name";
const char* password = "password";

const char* DJANGO_BASE_URL = "http://192.168.X.X:8000"; 
const char* CARD_REQUEST_PATH = "/embedded/card_request/";
const char* STATUS_REQUEST_PATH  = "/embedded/request_status/";

String lockId = "1";  
bool currentLockStatus = false;   

String lastNFCUID = "";

const unsigned long STATUS_POLL_INTERVAL_MS = 1000; 
unsigned long lastStatusPoll = 0;

void TaskPollLockStatus(void *pvParameters);

void applyLockStatus(bool lockStatus) {
  currentLockStatus = lockStatus;
  digitalWrite(blueLedPin, lockStatus ? HIGH : LOW);
}

bool parseLockStatus(const String& payload, bool& outStatus) {
  int idx = payload.indexOf("lock_status");
  if (idx == -1) {
    Serial.println("lock_status key not found in payload");
    return false;
  }

  int colonIdx = payload.indexOf(":", idx);
  if (colonIdx == -1) return false;

  String afterColon = payload.substring(colonIdx + 1);
  afterColon.trim();

  if (afterColon.startsWith("true")) {
    outStatus = true;
    return true;
  } else if (afterColon.startsWith("false")) {
    outStatus = false;
    return true;
  }

  Serial.print("Unexpected lock_status value in payload: ");
  Serial.println(afterColon);
  return false;
}

void sendCardUIDToDjango(const String& uid) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected, cannot send card UID");
    return;
  }

  HTTPClient http;
  String url = String(DJANGO_BASE_URL) + CARD_REQUEST_PATH;

  http.begin(url);
  http.addHeader("Content-Type", "application/json");

  String body = String("{\"lock_id\":") + lockId + ",\"uid\":\"" + uid + "\"}";
  Serial.print("Request body: ");
  Serial.println(body);

  int httpCode = http.POST(body);
  if (httpCode > 0) {
    String payload = http.getString();
    Serial.print("card_request response (");
    Serial.print(httpCode);
    Serial.print("): ");
    Serial.println(payload); 

    bool lockStatus;
    if (parseLockStatus(payload, lockStatus)) {
      applyLockStatus(lockStatus);
    }
  } else {
    Serial.print("card_request POST failed, error: ");
    Serial.println(http.errorToString(httpCode));
  }

  http.end();
}

void pollLockStatusFromDjango() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected, cannot poll lock status");
    return;
  }

  HTTPClient http;
  String url = String(DJANGO_BASE_URL) + STATUS_REQUEST_PATH;

  http.begin(url);
  http.addHeader("Content-Type", "application/json");

  String body = String("{\"lock_id\":\"") + lockId + "\"}";

  int httpCode = http.POST(body);
  if (httpCode > 0) {
    String payload = http.getString();

    bool lockStatus;
    if (parseLockStatus(payload, lockStatus)) {
      applyLockStatus(lockStatus);
    }
  } else {
    Serial.print("request_status POST failed, error: ");
    Serial.println(http.errorToString(httpCode));
  }

  http.end();
}

void TaskPollLockStatus(void *pvParameters) {
  (void) pvParameters; 

  for (;;) {
    unsigned long now = millis();
    if (now - lastStatusPoll >= STATUS_POLL_INTERVAL_MS) {
      lastStatusPoll = now;
      pollLockStatusFromDjango();
    }

    vTaskDelay(10 / portTICK_PERIOD_MS);
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(blueLedPin, OUTPUT);
  digitalWrite(blueLedPin, LOW); 

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

  nfc.begin();
  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata) {
    Serial.println("Didn't find PN532");
    while (1) {
      delay(1000);
    }
  }
  nfc.SAMConfig();
  Serial.println("Waiting for NFC card...");

  xTaskCreatePinnedToCore(
    TaskPollLockStatus,   
    "PollLockStatus",     
    4096,                
    NULL,                 
    1,                    
    NULL,                 
    0                     
  );
}

void loop() {
  uint8_t uid[7];
  uint8_t uidLength;

  if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 200)) {
    String uidString = "";
    for (uint8_t i = 0; i < uidLength; i++) {
      if (uid[i] < 0x10) uidString += "0";
      uidString += String(uid[i], HEX);
      if (i < uidLength - 1) uidString += ":";
    }
    uidString.toUpperCase();
    lastNFCUID = uidString;

    Serial.print("NFC card read, UID: ");
    Serial.println(uidString);

    sendCardUIDToDjango(uidString);

    delay(500); 
  }
}
