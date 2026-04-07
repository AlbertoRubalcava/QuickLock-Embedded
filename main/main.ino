#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <Preferences.h>

#include <esp_system.h>

#define NFC_INTERFACE_HSU

#include <PN532_HSU.h>
#include <PN532_HSU.cpp>
#include <PN532.h>

#include "mbedtls/cipher.h"
#include "mbedtls/cmac.h"

PN532_HSU pn532hsu(Serial1);
PN532 nfc(pn532hsu);

const int SERVO_LOCK_US   = 1100;
const int SERVO_UNLOCK_US = 1900;

const int SERVO_PIN  = 18;
const int SERVO_FREQ = 50;
const int SERVO_RES  = 16;

const int blueLedPin = 2;

const char* ssid = "IP When I Sneeze";
const char* password = "stophackingplz";

const char* DJANGO_BASE_URL = "http://192.168.5.7:8000";
const char* CARD_REQUEST_PATH = "/access/Locks/";
const char* STATUS_REQUEST_PATH = "/access/Locks/";

const String lockId = "1";

const bool ENABLE_DJANGO_STATUS_POLLING = true;
const bool REPORT_AUTHORIZED_UID_TO_DJANGO = false;
const unsigned long STATUS_POLL_INTERVAL_MS = 1000;
const unsigned long LOCAL_UNLOCK_WINDOW_MS = 5000;

const uint8_t MIFARE_RECORD_DATA_BLOCK = 4;
const uint8_t MIFARE_RECORD_MAC_BLOCK = 5;
const bool ENABLE_CARD_PROVISION_MODE = true;
const uint8_t CARD_RECORD_VERSION = 1;

const char* NVS_NAMESPACE = "quicklock";
const char* NVS_KEY_IS_PROVISIONED = "provisioned";
const char* NVS_KEY_CARD_ID = "card_id";
const char* NVS_KEY_LAST_COUNTER = "last_ctr";

// Replace this with your real 16-byte AES-CMAC key.
const uint8_t CMAC_KEY[16] = {
  0x51, 0x75, 0x69, 0x63,
  0x6B, 0x4C, 0x6F, 0x63,
  0x6B, 0x2D, 0x43, 0x6C,
  0x61, 0x73, 0x73, 0x31
};

// MIFARE Classic key used to authenticate sector 1.
// Factory/default cards commonly use FF FF FF FF FF FF.
uint8_t mifareKeyA[6] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

bool currentLockStatus = true;
String lastNFCUID = "";
unsigned long lastStatusPoll = 0;
unsigned long localUnlockUntilMs = 0;

struct PresentedCard {
  uint8_t uid[7];
  uint8_t uidLength;
  uint16_t atqa;
  uint8_t sak;
};

struct CardRecord {
  uint8_t version;
  uint32_t cardId;
  uint32_t counter;
  uint8_t reserved[7];
  uint8_t cmac[16];
};

struct EnrollmentState {
  bool isProvisioned;
  uint32_t enrolledCardId;
  uint32_t lastCounter;
};

Preferences preferences;
EnrollmentState enrollmentState = { false, 0, 0 };

void TaskPollLockStatus(void *pvParameters);
void pollLockStatusFromDjango();
void sendCardUIDToDjango(const String& uid);

static inline uint32_t usToDuty(int us) {
  const uint32_t period_us = 1000000UL / SERVO_FREQ;
  const uint32_t maxDuty = (1UL << SERVO_RES) - 1;
  us = constrain(us, 0, (int)period_us);
  return (uint32_t)((uint64_t)us * maxDuty / period_us);
}

static inline void servoWriteMicros(int us) {
  ledcWrite(SERVO_PIN, usToDuty(us));
}

String uidToString(const uint8_t *uid, uint8_t uidLength) {
  String uidString;
  for (uint8_t i = 0; i < uidLength; ++i) {
    if (uid[i] < 0x10) {
      uidString += "0";
    }
    uidString += String(uid[i], HEX);
    if (i + 1 < uidLength) {
      uidString += ":";
    }
  }
  uidString.toUpperCase();
  return uidString;
}

bool bytesEqual(const uint8_t *left, const uint8_t *right, size_t len) {
  return memcmp(left, right, len) == 0;
}

void printHexLine(const char *label, const uint8_t *data, size_t len) {
  Serial.print(label);
  for (size_t i = 0; i < len; ++i) {
    if (data[i] < 0x10) {
      Serial.print('0');
    }
    Serial.print(data[i], HEX);
    if (i + 1 < len) {
      Serial.print(' ');
    }
  }
  Serial.println();
}

uint32_t readUint32BE(const uint8_t *buffer) {
  return ((uint32_t)buffer[0] << 24) |
         ((uint32_t)buffer[1] << 16) |
         ((uint32_t)buffer[2] << 8) |
         (uint32_t)buffer[3];
}

void writeUint32BE(uint8_t *buffer, uint32_t value) {
  buffer[0] = (uint8_t)(value >> 24);
  buffer[1] = (uint8_t)(value >> 16);
  buffer[2] = (uint8_t)(value >> 8);
  buffer[3] = (uint8_t)value;
}

bool isLocalUnlockActive() {
  return localUnlockUntilMs != 0 &&
         (int32_t)(millis() - localUnlockUntilMs) < 0;
}

void lockDoor() {
  servoWriteMicros(SERVO_LOCK_US);
}

void unlockDoor() {
  servoWriteMicros(SERVO_UNLOCK_US);
}

void applyLockStatus(bool lockStatus) {
  if (lockStatus == currentLockStatus) {
    return;
  }

  currentLockStatus = lockStatus;
  digitalWrite(blueLedPin, lockStatus ? HIGH : LOW);

  if (lockStatus) {
    lockDoor();
    Serial.println("Servo: LOCK");
  } else {
    unlockDoor();
    Serial.println("Servo: UNLOCK");
  }

  delay(500);
}

void beginLocalUnlockWindow() {
  localUnlockUntilMs = millis() + LOCAL_UNLOCK_WINDOW_MS;
  applyLockStatus(false);
  Serial.print("Offline unlock granted for ");
  Serial.print(LOCAL_UNLOCK_WINDOW_MS);
  Serial.println(" ms");
}

void serviceLocalUnlockWindow() {
  if (localUnlockUntilMs == 0) {
    return;
  }

  if ((int32_t)(millis() - localUnlockUntilMs) >= 0) {
    localUnlockUntilMs = 0;
    applyLockStatus(true);
    Serial.println("Offline unlock window expired");
  }
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

bool openEnrollmentStorage() {
  if (!preferences.begin(NVS_NAMESPACE, false)) {
    Serial.println("Failed to open Preferences namespace");
    return false;
  }

  return true;
}

bool loadEnrollmentState() {
  enrollmentState.isProvisioned = preferences.getBool(NVS_KEY_IS_PROVISIONED, false);
  enrollmentState.enrolledCardId = preferences.getULong(NVS_KEY_CARD_ID, 0);
  enrollmentState.lastCounter = preferences.getULong(NVS_KEY_LAST_COUNTER, 0);

  if (!enrollmentState.isProvisioned) {
    enrollmentState.enrolledCardId = 0;
    enrollmentState.lastCounter = 0;
  }

  return true;
}

bool saveEnrollmentState(bool isProvisioned, uint32_t enrolledCardId, uint32_t lastCounter) {
  bool ok = true;

  ok = ok && preferences.putBool(NVS_KEY_IS_PROVISIONED, isProvisioned) > 0;
  ok = ok && preferences.putULong(NVS_KEY_CARD_ID, enrolledCardId) > 0;
  ok = ok && preferences.putULong(NVS_KEY_LAST_COUNTER, lastCounter) > 0;

  if (!ok) {
    Serial.println("Failed to persist enrollment state to NVS");
    return false;
  }

  enrollmentState.isProvisioned = isProvisioned;
  enrollmentState.enrolledCardId = enrolledCardId;
  enrollmentState.lastCounter = lastCounter;
  return true;
}

void serializeCardRecordData(const CardRecord &record, uint8_t *outDataBlock) {
  memset(outDataBlock, 0, 16);
  outDataBlock[0] = record.version;
  writeUint32BE(outDataBlock + 1, record.cardId);
  writeUint32BE(outDataBlock + 5, record.counter);
  memcpy(outDataBlock + 9, record.reserved, sizeof(record.reserved));
}

void deserializeCardRecord(const uint8_t *dataBlock, const uint8_t *macBlock, CardRecord &outRecord) {
  outRecord.version = dataBlock[0];
  outRecord.cardId = readUint32BE(dataBlock + 1);
  outRecord.counter = readUint32BE(dataBlock + 5);
  memcpy(outRecord.reserved, dataBlock + 9, sizeof(outRecord.reserved));
  memcpy(outRecord.cmac, macBlock, sizeof(outRecord.cmac));
}

bool computeCardRecordCmac(const CardRecord &record, uint8_t *outCmac) {
  uint8_t dataBlock[16];
  serializeCardRecordData(record, dataBlock);

  const mbedtls_cipher_info_t *cipherInfo =
      mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
  if (cipherInfo == nullptr) {
    Serial.println("Failed to resolve AES-128 cipher info for CMAC");
    return false;
  }

  int result = mbedtls_cipher_cmac(
      cipherInfo,
      CMAC_KEY,
      sizeof(CMAC_KEY) * 8,
      dataBlock,
      sizeof(dataBlock),
      outCmac);
  if (result != 0) {
    Serial.print("AES-CMAC computation failed: ");
    Serial.println(result);
    return false;
  }

  return true;
}

bool buildCardRecord(uint32_t cardId, uint32_t counter, CardRecord &outRecord) {
  memset(&outRecord, 0, sizeof(outRecord));
  outRecord.version = CARD_RECORD_VERSION;
  outRecord.cardId = cardId;
  outRecord.counter = counter;

  return computeCardRecordCmac(outRecord, outRecord.cmac);
}

bool verifyCardRecordMac(const CardRecord &record) {
  uint8_t expectedCmac[16];
  if (!computeCardRecordCmac(record, expectedCmac)) {
    return false;
  }

  if (!bytesEqual(expectedCmac, record.cmac, sizeof(expectedCmac))) {
    Serial.println("Card CMAC verification failed");
    printHexLine("Expected CMAC: ", expectedCmac, sizeof(expectedCmac));
    printHexLine("Stored CMAC:   ", record.cmac, sizeof(record.cmac));
    return false;
  }

  return true;
}

bool cardRecordsEqual(const CardRecord &left, const CardRecord &right) {
  return left.version == right.version &&
         left.cardId == right.cardId &&
         left.counter == right.counter &&
         bytesEqual(left.reserved, right.reserved, sizeof(left.reserved)) &&
         bytesEqual(left.cmac, right.cmac, sizeof(left.cmac));
}

void printCardRecord(const CardRecord &record) {
  uint8_t dataBlock[16];
  serializeCardRecordData(record, dataBlock);

  Serial.print("Record version: ");
  Serial.println(record.version);
  Serial.print("Record card_id: ");
  Serial.println(record.cardId);
  Serial.print("Record counter: ");
  Serial.println(record.counter);
  printHexLine("Record data block: ", dataBlock, sizeof(dataBlock));
  printHexLine("Record CMAC block: ", record.cmac, sizeof(record.cmac));
}

void sendCardUIDToDjango(const String& uid) {
  if (!REPORT_AUTHORIZED_UID_TO_DJANGO) {
    return;
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected, cannot report authorized card");
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
  if (!ENABLE_DJANGO_STATUS_POLLING || isLocalUnlockActive()) {
    return;
  }

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
  (void)pvParameters;

  for (;;) {
    serviceLocalUnlockWindow();

    unsigned long now = millis();
    if (now - lastStatusPoll >= STATUS_POLL_INTERVAL_MS) {
      lastStatusPoll = now;
      pollLockStatusFromDjango();
    }

    vTaskDelay(10 / portTICK_PERIOD_MS);
  }
}

bool readPresentedCard(PresentedCard &card) {
  memset(&card, 0, sizeof(card));

  if (!nfc.readPassiveTargetID(
        PN532_MIFARE_ISO14443A,
        card.uid,
        &card.uidLength,
        250,
        true)) {
    return false;
  }

  uint8_t packetBufferLength = 0;
  uint8_t *packetBuffer = nfc.getBuffer(&packetBufferLength);
  (void)packetBufferLength;

  card.atqa = ((uint16_t)packetBuffer[2] << 8) | packetBuffer[3];
  card.sak = packetBuffer[4];
  return true;
}

void printPresentedCard(const PresentedCard &card) {
  Serial.print("Card UID: ");
  Serial.println(uidToString(card.uid, card.uidLength));
  Serial.print("ATQA: 0x");
  Serial.println(card.atqa, HEX);
  Serial.print("SAK: 0x");
  Serial.println(card.sak, HEX);
}

bool authenticateRecordBlocks(const PresentedCard &card) {
  if (nfc.mifareclassic_IsTrailerBlock(MIFARE_RECORD_DATA_BLOCK) ||
      nfc.mifareclassic_IsTrailerBlock(MIFARE_RECORD_MAC_BLOCK)) {
    Serial.println("Configured record blocks must be MIFARE Classic data blocks");
    return false;
  }

  if (!nfc.mifareclassic_AuthenticateBlock(
        const_cast<uint8_t*>(card.uid),
        card.uidLength,
        MIFARE_RECORD_DATA_BLOCK,
        0,
        mifareKeyA)) {
    Serial.println("MIFARE Classic block authentication failed");
    return false;
  }

  return true;
}

bool readDataBlock(uint8_t blockNumber, uint8_t *outData) {
  if (!nfc.mifareclassic_ReadDataBlock(blockNumber, outData)) {
    Serial.print("Failed to read MIFARE Classic block ");
    Serial.println(blockNumber);
    return false;
  }

  return true;
}

bool writeDataBlock(uint8_t blockNumber, const uint8_t *data) {
  if (!nfc.mifareclassic_WriteDataBlock(blockNumber, const_cast<uint8_t*>(data))) {
    Serial.print("Failed to write MIFARE Classic block ");
    Serial.println(blockNumber);
    return false;
  }

  return true;
}

bool readCardRecord(const PresentedCard &card, CardRecord &outRecord) {
  if (!authenticateRecordBlocks(card)) {
    return false;
  }

  uint8_t dataBlock[16];
  uint8_t macBlock[16];

  if (!readDataBlock(MIFARE_RECORD_DATA_BLOCK, dataBlock)) {
    return false;
  }

  if (!readDataBlock(MIFARE_RECORD_MAC_BLOCK, macBlock)) {
    return false;
  }

  deserializeCardRecord(dataBlock, macBlock, outRecord);
  return true;
}

bool writeCardRecord(const PresentedCard &card, const CardRecord &record) {
  if (!authenticateRecordBlocks(card)) {
    return false;
  }

  uint8_t dataBlock[16];
  serializeCardRecordData(record, dataBlock);

  if (!writeDataBlock(MIFARE_RECORD_DATA_BLOCK, dataBlock)) {
    return false;
  }

  if (!writeDataBlock(MIFARE_RECORD_MAC_BLOCK, record.cmac)) {
    return false;
  }

  return true;
}

bool provisionCard(const PresentedCard &card) {
  CardRecord provisionedRecord;
  uint32_t cardId = 0;

  while (cardId == 0) {
    cardId = esp_random();
  }

  if (!buildCardRecord(cardId, 1, provisionedRecord)) {
    return false;
  }

  if (!writeCardRecord(card, provisionedRecord)) {
    return false;
  }

  CardRecord readBackRecord;
  if (!readCardRecord(card, readBackRecord)) {
    Serial.println("Provisioning verify read failed");
    return false;
  }

  if (!verifyCardRecordMac(readBackRecord)) {
    Serial.println("Provisioning verify CMAC failed");
    return false;
  }

  if (!cardRecordsEqual(readBackRecord, provisionedRecord)) {
    Serial.println("Provisioning verify mismatch");
    return false;
  }

  if (!saveEnrollmentState(true, cardId, 0)) {
    return false;
  }

  Serial.println("Card provisioned successfully");
  Serial.print("Provisioned card_id: ");
  Serial.println(cardId);
  return true;
}

bool validateAndAdvanceCard(const PresentedCard &card) {
  if (!enrollmentState.isProvisioned) {
    Serial.println("No enrolled card in NVS. Enable provision mode first.");
    return false;
  }

  CardRecord presentedRecord;
  if (!readCardRecord(card, presentedRecord)) {
    return false;
  }

  printCardRecord(presentedRecord);

  if (presentedRecord.version != CARD_RECORD_VERSION) {
    Serial.println("Unsupported card record version");
    return false;
  }

  if (!verifyCardRecordMac(presentedRecord)) {
    return false;
  }

  if (presentedRecord.cardId != enrollmentState.enrolledCardId) {
    Serial.println("Card ID mismatch");
    return false;
  }

  if (presentedRecord.counter <= enrollmentState.lastCounter) {
    Serial.println("Counter replay detected");
    return false;
  }

  if (presentedRecord.counter == UINT32_MAX) {
    Serial.println("Counter exhausted");
    return false;
  }

  CardRecord nextRecord;
  if (!buildCardRecord(presentedRecord.cardId, presentedRecord.counter + 1, nextRecord)) {
    return false;
  }

  if (!writeCardRecord(card, nextRecord)) {
    return false;
  }

  CardRecord verifiedRecord;
  if (!readCardRecord(card, verifiedRecord)) {
    Serial.println("Post-write verify read failed");
    return false;
  }

  if (!verifyCardRecordMac(verifiedRecord)) {
    Serial.println("Post-write verify CMAC failed");
    return false;
  }

  if (!cardRecordsEqual(verifiedRecord, nextRecord)) {
    Serial.println("Post-write record mismatch");
    return false;
  }

  if (!saveEnrollmentState(true, presentedRecord.cardId, presentedRecord.counter)) {
    return false;
  }

  Serial.print("Accepted card_id ");
  Serial.print(presentedRecord.cardId);
  Serial.print(" with counter ");
  Serial.println(presentedRecord.counter);
  return true;
}

void handleAuthorizedCard(const PresentedCard &card) {
  const String uidString = uidToString(card.uid, card.uidLength);
  beginLocalUnlockWindow();
  sendCardUIDToDjango(uidString);
}

void setup() {
  Serial.begin(115200);

  pinMode(blueLedPin, OUTPUT);
  digitalWrite(blueLedPin, HIGH);

  ledcAttach(SERVO_PIN, SERVO_FREQ, SERVO_RES);
  servoWriteMicros(SERVO_LOCK_US);
  delay(600);

  if (!openEnrollmentStorage()) {
    while (1) {
      delay(100);
    }
  }

  loadEnrollmentState();

  Serial.print("Stored provisioned state: ");
  Serial.println(enrollmentState.isProvisioned ? "yes" : "no");
  if (enrollmentState.isProvisioned) {
    Serial.print("Stored enrolled card_id: ");
    Serial.println(enrollmentState.enrolledCardId);
    Serial.print("Stored last counter: ");
    Serial.println(enrollmentState.lastCounter);
  }

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

  Serial1.begin(115200, SERIAL_8N1, 17, 16);
  delay(200);

  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata) {
    Serial.println("Didn't find PN532");
    while (1) {
      delay(100);
    }
  }

  Serial.print("Found chip PN5");
  Serial.println((versiondata >> 24) & 0xFF, HEX);

  nfc.SAMConfig();
  nfc.setPassiveActivationRetries(0x05);

  if (ENABLE_CARD_PROVISION_MODE) {
    Serial.println("Card provision mode enabled");
  } else if (!enrollmentState.isProvisioned) {
    Serial.println("No provisioned card found. Enable provision mode to enroll one.");
  } else {
    Serial.println("Waiting for MIFARE Classic card...");
  }

  xTaskCreatePinnedToCore(
      TaskPollLockStatus,
      "PollLockStatus",
      4096,
      NULL,
      1,
      NULL,
      0);
}

void loop() {
  PresentedCard card;
  serviceLocalUnlockWindow();

  if (!readPresentedCard(card)) {
    if (!lastNFCUID.isEmpty()) {
      Serial.println("Card removed");
      lastNFCUID = "";
      nfc.inRelease();
    }
    delay(50);
    return;
  }

  const String uidString = uidToString(card.uid, card.uidLength);
  if (uidString == lastNFCUID) {
    delay(150);
    return;
  }

  lastNFCUID = uidString;
  Serial.print("Detected UID: ");
  Serial.println(uidString);
  printPresentedCard(card);

  if (ENABLE_CARD_PROVISION_MODE) {
    if (provisionCard(card)) {
      Serial.println("Provisioning complete. Disable provision mode before normal use.");
    }
    nfc.inRelease();
    delay(250);
    return;
  }

  if (validateAndAdvanceCard(card)) {
    handleAuthorizedCard(card);
  } else {
    Serial.println("Access denied");
    nfc.inRelease();
  }

  delay(250);
}
