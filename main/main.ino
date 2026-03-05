#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#define NFC_INTERFACE_HSU

#include <PN532_HSU.h>
#include <PN532_HSU.cpp>
#include <PN532.h>

PN532_HSU pn532hsu(Serial1);
PN532 nfc(pn532hsu);

const int SERVO_LOCK_US   = 1100;
const int SERVO_UNLOCK_US = 1900;

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
  ledcWrite(SERVO_PIN, usToDuty(us)); // note: uses PIN
}

const int blueLedPin = 2;

const char* ssid = "name";
const char* password = "pass";

const char* DJANGO_BASE_URL = "http://192.168.X.X:8000"; 
const char* CARD_REQUEST_PATH = "/embedded/card_request/";
const char* STATUS_REQUEST_PATH  = "/embedded/request_status/";

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

bool authenticateDESFireAES() {

  uint8_t authCmd[] = { 
    0x90, 0xAA, 0x00, 0x00, 
    0x01, 0x00, 
    0x00
  };

  uint8_t response[32];
  uint8_t responseLength = sizeof(response);

  if (!nfc.inDataExchange(authCmd, sizeof(authCmd), response, &responseLength)) {
      Serial.println("Auth command failed");
      return false;
  }

  if (responseLength != 16) {
    Serial.println("Unexpected RndB length");
    return false;
  }

  uint8_t rndB[16];

  // Decrypt RndB
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, desfireKey, 128);
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, response, rndB);

  // Rotate RndB left
  uint8_t rndB_rot[16];
  memcpy(rndB_rot, rndB + 1, 15);
  rndB_rot[15] = rndB[0];

  // Generate RndA
  uint8_t rndA[16];
  for (int i = 0; i < 16; i++) {
    rndA[i] = esp_random() & 0xFF;
  }

  // Prepare challenge = RndA || Rot(RndB)
  uint8_t challenge[32];
  memcpy(challenge, rndA, 16);
  memcpy(challenge + 16, rndB_rot, 16);

  // Encrypt challenge
  uint8_t encChallenge[32];
  mbedtls_aes_setkey_enc(&aes, desfireKey, 128);
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, challenge, encChallenge);
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, challenge + 16, encChallenge + 16);

  mbedtls_aes_free(&aes);

  // Send encrypted challenge
  if (!nfc.inDataExchange(encChallenge, 32, response, &responseLength)) {
    Serial.println("Challenge send failed");
    return false;
  }

  if (responseLength != 16) {
    Serial.println("Invalid RndA response");
    return false;
  }

  uint8_t rndA_resp[16];

  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, desfireKey, 128);
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, response, rndA_resp);
  mbedtls_aes_free(&aes);

  // Rotate original RndA
  uint8_t rndA_rot[16];
  memcpy(rndA_rot, rndA + 1, 15);
  rndA_rot[15] = rndA[0];

  if (memcmp(rndA_rot, rndA_resp, 16) == 0) {
    Serial.println("AES Mutual Authentication SUCCESS");
    return true;
  } else {
    Serial.println("AES Mutual Authentication FAILED");
    return false;
  }
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
    return false;   // silently ignore
  }

  if (!doc.containsKey("result")) {
    return false;
  }

  outStatus = doc["result"];
  return true;
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

    if (payload.length() == 0) {
      http.end();
      return;   // silently ignore empty response
    }

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

  String body = String("{\"lock_id\":") + lockId + "}";
  
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

void hexdump(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
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