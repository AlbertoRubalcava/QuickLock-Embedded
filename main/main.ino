#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "secrets.h"
#define NFC_INTERFACE_HSU

#include <PN532_HSU.h>
#include <PN532_HSU.cpp>
#include <PN532.h>

PN532_HSU pn532hsu(Serial1);
PN532 nfc(pn532hsu);

const int SERVO_LOCK_US   = 2000;
const int SERVO_UNLOCK_US = 1500;

const int SERVO_PIN  = 18;
const int SERVO_FREQ = 50;
const int SERVO_RES  = 16;

static inline uint32_t usToDuty(int us) {
  const uint32_t period_us = 1000000UL / SERVO_FREQ; // 20000
  const uint32_t maxDuty   = (1UL << SERVO_RES) - 1; // 65535
  us = constrain(us, 0, (int)period_us);
  return (uint32_t)((uint64_t)us * maxDuty / period_us);
}

static inline void servoWriteMicros(int us) {
  ledcWrite(SERVO_PIN, usToDuty(us)); 
}

const int blueLedPin = 2;

const char* ssid = WIFI_SSID;
const char* password = WIFI_PASSWORD;

const char* CARD_REQUEST_PATH = "/access/Locks/";
const char* STATUS_REQUEST_PATH  = "/access/Locks/";

String lockId = "1";  
bool currentLockStatus = false;   

String lastNFCUID = "";

const unsigned long STATUS_POLL_INTERVAL_MS = 1000; 
unsigned long lastStatusPoll = 0;

uint8_t desfireKey[16] = {
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00
};

void TaskPollLockStatus(void *pvParameters);

void lockDoor() {
  servoWriteMicros(SERVO_LOCK_US);
}

void unlockDoor() {
  servoWriteMicros(SERVO_UNLOCK_US);
}


void applyLockStatus(bool lockStatus) {
  if (lockStatus == currentLockStatus) return;

  currentLockStatus = lockStatus;

  digitalWrite(blueLedPin, lockStatus ? HIGH : LOW);

  if (lockStatus) {
    lockDoor();     // LOCK
    Serial.println("Servo: LOCK");
  } else {
    unlockDoor();   // UNLOCK
    Serial.println("Servo: UNLOCK");
  }

  delay(500);
}

bool parseLockStatus(const String& payload, bool& outStatus) {
  StaticJsonDocument<256> doc;
  DeserializationError error = deserializeJson(doc, payload);

  if (error) {
    Serial.println("JSON parse failed");
    return false;
  }

  if (!doc.containsKey("status")) {
    Serial.println("No 'status' field in response");
    return false;
  }

  outStatus = doc["status"];
  return true;
}

void sendCardUIDToDjango(const String& uid) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected, cannot send card UID");
    return;
  }

  HTTPClient http;

  String url = String(DJANGO_BASE_URL) +
               CARD_REQUEST_PATH +
               lockId +
               "/card_unlock/";

  http.begin(url);
  http.addHeader("Content-Type", "application/json");

  String body = String("{\"uid\":\"") + uid + "\"}";

  Serial.print("POST ");
  Serial.println(url);
  Serial.print("Body: ");
  Serial.println(body);

  int httpCode = http.POST(body);

  if (httpCode > 0) {
    String payload = http.getString();

    Serial.print("card_unlock response (");
    Serial.print(httpCode);
    Serial.print("): ");
    Serial.println(payload);

    pollLockStatusFromDjango();

  } else {
    Serial.print("card_unlock POST failed: ");
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

  String url = String(DJANGO_BASE_URL) +
               STATUS_REQUEST_PATH +
               lockId +
               "/status/";

  http.begin(url);

  int httpCode = http.GET(); 

  if (httpCode > 0) {

    String payload = http.getString();

    Serial.print("Status GET (");
    Serial.print(httpCode);
    Serial.print("): ");
    Serial.println(payload);

    bool lockStatus;
    if (parseLockStatus(payload, lockStatus)) {
      applyLockStatus(lockStatus);
    }

  } else {
    Serial.print("Status GET failed: ");
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

  ledcAttach(SERVO_PIN, SERVO_FREQ, SERVO_RES);
  servoWriteMicros(SERVO_LOCK_US);
  delay(600);

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

  pollLockStatusFromDjango();

  Serial1.begin(115200, SERIAL_8N1, 17, 16);   // RX=17 TX=16 (match your wiring)
  delay(200);

  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata) {
    Serial.println("Didn't find PN532");
    while (1);
  }

  Serial.print("Found chip PN5");
  Serial.println((versiondata >> 24) & 0xFF, HEX);

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

  if (nfc.readPassiveTargetID(
        PN532_MIFARE_ISO14443A,
        uid,
        &uidLength,
        2000)) {

    String uidString = "";

    for (uint8_t i = 0; i < uidLength; i++) {
      if (uid[i] < 0x10) uidString += "0";
      uidString += String(uid[i], HEX);
      if (i < uidLength - 1) uidString += ":";
    }

    uidString.toUpperCase();

    Serial.print("UID: ");
    Serial.println(uidString);

    sendCardUIDToDjango(uidString);

    delay(1000);
  }
}
