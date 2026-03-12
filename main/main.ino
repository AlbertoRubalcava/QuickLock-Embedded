#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "mbedtls/aes.h"
#define NFC_INTERFACE_HSU

#include <PN532_HSU.h>
#include <PN532_HSU.cpp>
#include <PN532.h>

// ── Corrected DES implementation ─────────────────────────────────────────────

static const uint8_t PC1[56] = {
  57,49,41,33,25,17, 9,
   1,58,50,42,34,26,18,
  10, 2,59,51,43,35,27,
  19,11, 3,60,52,44,36,
  63,55,47,39,31,23,15,
   7,62,54,46,38,30,22,
  14, 6,61,53,45,37,29,
  21,13, 5,28,20,12, 4
};
static const uint8_t PC2[48] = {
  14,17,11,24, 1, 5,
   3,28,15, 6,21,10,
  23,19,12, 4,26, 8,
  16, 7,27,20,13, 2,
  41,52,31,37,47,55,
  30,40,51,45,33,48,
  44,49,39,56,34,53,
  46,42,50,36,29,32
};
static const uint8_t IP_TABLE[64] = {
  58,50,42,34,26,18,10, 2,
  60,52,44,36,28,20,12, 4,
  62,54,46,38,30,22,14, 6,
  64,56,48,40,32,24,16, 8,
  57,49,41,33,25,17, 9, 1,
  59,51,43,35,27,19,11, 3,
  61,53,45,37,29,21,13, 5,
  63,55,47,39,31,23,15, 7
};
static const uint8_t IP_INV_TABLE[64] = {
  40, 8,48,16,56,24,64,32,
  39, 7,47,15,55,23,63,31,
  38, 6,46,14,54,22,62,30,
  37, 5,45,13,53,21,61,29,
  36, 4,44,12,52,20,60,28,
  35, 3,43,11,51,19,59,27,
  34, 2,42,10,50,18,58,26,
  33, 1,41, 9,49,17,57,25
};
static const uint8_t E_TABLE[48] = {
  32, 1, 2, 3, 4, 5,
   4, 5, 6, 7, 8, 9,
   8, 9,10,11,12,13,
  12,13,14,15,16,17,
  16,17,18,19,20,21,
  20,21,22,23,24,25,
  24,25,26,27,28,29,
  28,29,30,31,32, 1
};
static const uint8_t P_TABLE[32] = {
  16, 7,20,21,
  29,12,28,17,
   1,15,23,26,
   5,18,31,10,
   2, 8,24,14,
  32,27, 3, 9,
  19,13,30, 6,
  22,11, 4,25
};
static const uint8_t SHIFTS[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
static const uint8_t SBOX[8][64] = {
  {14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7,
    0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8,
    4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0,
   15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13},
  {15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10,
    3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5,
    0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15,
   13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9},
  {10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8,
   13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1,
   13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7,
    1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12},
  { 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15,
   13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9,
   10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4,
    3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14},
  { 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9,
   14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6,
    4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14,
   11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3},
  {12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11,
   10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8,
    9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6,
    4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13},
  { 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1,
   13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6,
    1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2,
    6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12},
  {13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7,
    1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2,
    7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8,
    2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11}
};

// Bit access helpers (1-indexed from MSB)
static inline int getBit(const uint8_t* data, int n) {
  n--;
  return (data[n / 8] >> (7 - (n % 8))) & 1;
}
static inline void setBit(uint8_t* data, int n, int val) {
  n--;
  if (val) data[n / 8] |=  (1 << (7 - (n % 8)));
  else     data[n / 8] &= ~(1 << (7 - (n % 8)));
}

static void desProcessBlock(const uint8_t* key8, const uint8_t* in,
                             uint8_t* out, bool encrypt) {
  // Apply IP
  uint8_t ipOut[8] = {0};
  for (int i = 0; i < 64; i++)
    setBit(ipOut, i+1, getBit(in, IP_TABLE[i]));

  uint8_t L[4], R[4];
  memcpy(L, ipOut,     4);
  memcpy(R, ipOut + 4, 4);

  // Key schedule
  uint8_t kp[7] = {0};
  for (int i = 0; i < 56; i++)
    setBit(kp, i+1, getBit(key8, PC1[i]));

  uint8_t C[4] = {0}, D[4] = {0};
  for (int i = 0; i < 28; i++) setBit(C, i+1, getBit(kp, i+1));
  for (int i = 0; i < 28; i++) setBit(D, i+1, getBit(kp, i+29));

  // Rotate 28-bit half left by n bits
  auto rot28 = [](uint8_t* blk, int n) {
    for (int s = 0; s < n; s++) {
      int msb = getBit(blk, 1);
      for (int i = 1; i < 28; i++) setBit(blk, i, getBit(blk, i+1));
      setBit(blk, 28, msb);
    }
  };

  uint8_t subkeys[16][6];
  for (int r = 0; r < 16; r++) {
    rot28(C, SHIFTS[r]);
    rot28(D, SHIFTS[r]);
    uint8_t CD[7] = {0};
    for (int i = 0; i < 28; i++) setBit(CD, i+1,  getBit(C, i+1));
    for (int i = 0; i < 28; i++) setBit(CD, i+29, getBit(D, i+1));
    memset(subkeys[r], 0, 6);
    for (int i = 0; i < 48; i++)
      setBit(subkeys[r], i+1, getBit(CD, PC2[i]));
  }

  // 16 Feistel rounds
  for (int round = 0; round < 16; round++) {
    int r = encrypt ? round : (15 - round);

    // Expand R to 48 bits
    uint8_t Rexp[6] = {0};
    for (int i = 0; i < 48; i++)
      setBit(Rexp, i+1, getBit(R, E_TABLE[i]));

    // XOR with subkey
    for (int i = 0; i < 6; i++) Rexp[i] ^= subkeys[r][i];

    // S-box substitution
    uint8_t f[4] = {0};
    for (int s = 0; s < 8; s++) {
      int base = s * 6;
      int row  = (getBit(Rexp, base+1) << 1) | getBit(Rexp, base+6);
      int col  = (getBit(Rexp, base+2) << 3) |
                 (getBit(Rexp, base+3) << 2) |
                 (getBit(Rexp, base+4) << 1) |
                  getBit(Rexp, base+5);
      uint8_t val = SBOX[s][row * 16 + col];
      for (int b = 0; b < 4; b++)
        setBit(f, s*4 + b + 1, (val >> (3-b)) & 1);
    }

    // P permutation
    uint8_t fp[4] = {0};
    for (int i = 0; i < 32; i++)
      setBit(fp, i+1, getBit(f, P_TABLE[i]));

    // Feistel swap
    uint8_t newR[4];
    for (int i = 0; i < 4; i++) newR[i] = L[i] ^ fp[i];
    memcpy(L, R,    4);
    memcpy(R, newR, 4);
  }

  // Final permutation (R and L swapped before IP^-1)
  uint8_t preOut[8];
  memcpy(preOut,     R, 4);
  memcpy(preOut + 4, L, 4);

  memset(out, 0, 8);
  for (int i = 0; i < 64; i++)
    setBit(out, i+1, getBit(preOut, IP_INV_TABLE[i]));
}

static void desEncryptBlock(const uint8_t* key8, const uint8_t* in, uint8_t* out) {
  desProcessBlock(key8, in, out, true);
}
static void desDecryptBlock(const uint8_t* key8, const uint8_t* in, uint8_t* out) {
  desProcessBlock(key8, in, out, false);
}

// 3DES EDE with 16-byte key (k1=bytes 0-7, k2=bytes 8-15)
static void tdesEncryptBlock(const uint8_t* key16, const uint8_t* in, uint8_t* out) {
  uint8_t tmp[8];
  desEncryptBlock(key16,     in,  tmp);
  desDecryptBlock(key16 + 8, tmp, tmp);
  desEncryptBlock(key16,     tmp, out);
}
static void tdesDecryptBlock(const uint8_t* key16, const uint8_t* in, uint8_t* out) {
  uint8_t tmp[8];
  desDecryptBlock(key16,     in,  tmp);
  desEncryptBlock(key16 + 8, tmp, tmp);
  desDecryptBlock(key16,     tmp, out);
}

static void tdesCbcEncrypt(const uint8_t* key16, uint8_t* iv,
                           const uint8_t* in, uint8_t* out, size_t len) {
  for (size_t i = 0; i < len; i += 8) {
    uint8_t tmp[8];
    for (int j = 0; j < 8; j++) tmp[j] = in[i+j] ^ iv[j];
    tdesEncryptBlock(key16, tmp, out + i);
    memcpy(iv, out + i, 8);
  }
}
static void tdesCbcDecrypt(const uint8_t* key16, uint8_t* iv,
                           const uint8_t* in, uint8_t* out, size_t len) {
  for (size_t i = 0; i < len; i += 8) {
    uint8_t tmp[8];
    tdesDecryptBlock(key16, in + i, tmp);
    for (int j = 0; j < 8; j++) out[i+j] = tmp[j] ^ iv[j];
    memcpy(iv, in + i, 8);
  }
}

// ─────────────────────────────────────────────────────────────────────────────

PN532_HSU pn532hsu(Serial1);
PN532 nfc(pn532hsu);

const int SERVO_LOCK_US   = 1100;
const int SERVO_UNLOCK_US = 1900;
const int SERVO_PIN  = 18;
const int SERVO_FREQ = 50;
const int SERVO_RES  = 16;

static inline uint32_t usToDuty(int us) {
  const uint32_t period_us = 1000000UL / SERVO_FREQ;
  const uint32_t maxDuty   = (1UL << SERVO_RES) - 1;
  us = constrain(us, 0, (int)period_us);
  return (uint32_t)((uint64_t)us * maxDuty / period_us);
}
static inline void servoWriteMicros(int us) { ledcWrite(SERVO_PIN, usToDuty(us)); }

const int blueLedPin = 2;
const char* ssid     = "IP When I Sneeze";
const char* password = "stophackingplz";
const char* DJANGO_BASE_URL     = "http://192.168.5.7:8000";
const char* CARD_REQUEST_PATH   = "/embedded/card_request/";
const char* STATUS_REQUEST_PATH = "/embedded/request_status/";

String lockId            = "1";
bool   currentLockStatus = false;

uint8_t desfireKey[16] = {
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

const unsigned long STATUS_POLL_INTERVAL_MS = 1000;
unsigned long lastStatusPoll = 0;

void TaskPollLockStatus(void *pvParameters);
void lockDoor()   { servoWriteMicros(SERVO_LOCK_US); }
void unlockDoor() { servoWriteMicros(SERVO_UNLOCK_US); }

static void rotateLeft(const uint8_t* in, uint8_t* out) {
  memcpy(out, in + 1, 15);
  out[15] = in[0];
}

static void aesCbcEncrypt(const uint8_t* key, uint8_t* iv,
                          const uint8_t* plaintext, uint8_t* ciphertext, size_t len) {
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, key, 128);
  mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, len, iv, plaintext, ciphertext);
  mbedtls_aes_free(&ctx);
}
static void aesCbcDecrypt(const uint8_t* key, uint8_t* iv,
                          const uint8_t* ciphertext, uint8_t* plaintext, size_t len) {
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_dec(&ctx, key, 128);
  mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, iv, ciphertext, plaintext);
  mbedtls_aes_free(&ctx);
}

static bool desfireExchange(const uint8_t* cmd, uint8_t cmdLen,
                             uint8_t* resp, uint8_t* respLen) {
  bool ok = nfc.inDataExchange(const_cast<uint8_t*>(cmd), cmdLen, resp, respLen);
  if (!ok) Serial.println("[DESFire] inDataExchange RF error");
  return ok;
}

void testDES() {
  uint8_t key[8]   = {0};
  uint8_t plain[8] = {0};
  uint8_t cipher[8];
  desEncryptBlock(key, plain, cipher);
  Serial.print("[DES Test] Got:      ");
  for (int i = 0; i < 8; i++) Serial.printf("%02X ", cipher[i]);
  Serial.println();
  Serial.println("[DES Test] Expected: 8C A6 4D E9 C1 B1 23 A7");
}

bool migrateKeyToAES() {
  uint8_t resp[64];
  uint8_t respLen;

  // Native SelectApplication: [5A] [AID 3 bytes]
  uint8_t selectApp[] = { 0x5A, 0x00, 0x00, 0x00 };
  respLen = sizeof(resp);
  nfc.inDataExchange(const_cast<uint8_t*>(selectApp), sizeof(selectApp), resp, &respLen);
  Serial.print("[Migrate] SelectApp: ");
  for (int i = 0; i < respLen; i++) Serial.printf("%02X ", resp[i]); Serial.println();
  if (respLen < 1 || resp[0] != 0x00) { Serial.println("[Migrate] SelectApp failed"); return false; }

  // Native Authenticate DES: [0A] [keyNo]
  uint8_t tdesKey[16] = {0};
  uint8_t authCmd[] = { 0x0A, 0x00 };
  respLen = sizeof(resp);
  nfc.inDataExchange(const_cast<uint8_t*>(authCmd), sizeof(authCmd), resp, &respLen);
  Serial.print("[Migrate] Auth Step1: ");
  for (int i = 0; i < respLen; i++) Serial.printf("%02X ", resp[i]); Serial.println();

  // Native response: 0xAF + 8 bytes encRndB = 9 bytes
  if (respLen < 9 || resp[0] != 0xAF) {
    Serial.println("[Migrate] Auth Step1 failed");
    return false;
  }

  uint8_t encRndB[8];
  memcpy(encRndB, resp + 1, 8);
  uint8_t rndB[8];
  uint8_t iv1[8] = {0};
  tdesCbcDecrypt(tdesKey, iv1, encRndB, rndB, 8);
  Serial.print("[Migrate] RndB: ");
  for (int i = 0; i < 8; i++) Serial.printf("%02X ", rndB[i]); Serial.println();

  // RotL(RndB)
  uint8_t rndB_rot[8];
  memcpy(rndB_rot, rndB + 1, 7);
  rndB_rot[7] = rndB[0];

  // Generate RndA
  uint8_t rndA[8];
  for (int i = 0; i < 8; i++) rndA[i] = esp_random() & 0xFF;

  // Encrypt token = 3DES-CBC(IV=0) { RndA || RotL(RndB) }
  uint8_t token[16], encToken[16];
  memcpy(token,     rndA,     8);
  memcpy(token + 8, rndB_rot, 8);
  uint8_t iv2[8] = {0};
  tdesCbcEncrypt(tdesKey, iv2, token, encToken, 16);

  // Native DESFire continuation: [AF] [16 bytes encToken]
  uint8_t contCmd[17];
  contCmd[0] = 0xAF;
  memcpy(contCmd + 1, encToken, 16);

  respLen = sizeof(resp);
  nfc.inDataExchange(const_cast<uint8_t*>(contCmd), sizeof(contCmd), resp, &respLen);
  Serial.print("[Migrate] Auth Step2: ");
  for (int i = 0; i < respLen; i++) Serial.printf("%02X ", resp[i]); Serial.println();

  // Native success = 0x00 + 8 bytes RotL(RndA)
  if (respLen < 1 || resp[0] != 0x00) {
    Serial.printf("[Migrate] 3DES Auth failed, code: %02X\n", resp[0]);
    return false;
  }
  Serial.println("[Migrate] 3DES Auth SUCCESS — changing key to AES...");

  // DES session key: RndA[0-3] || RndB[0-3] || RndA[4-7] || RndB[4-7]
  uint8_t sessionKey[16];
  sessionKey[0]  = rndA[0]; sessionKey[1]  = rndA[1];
  sessionKey[2]  = rndA[2]; sessionKey[3]  = rndA[3];
  sessionKey[4]  = rndB[0]; sessionKey[5]  = rndB[1];
  sessionKey[6]  = rndB[2]; sessionKey[7]  = rndB[3];
  sessionKey[8]  = rndA[4]; sessionKey[9]  = rndA[5];
  sessionKey[10] = rndA[6]; sessionKey[11] = rndA[7];
  sessionKey[12] = rndB[4]; sessionKey[13] = rndB[5];
  sessionKey[14] = rndB[6]; sessionKey[15] = rndB[7];

  Serial.print("[Migrate] Session key: ");
  for (int i = 0; i < 16; i++) Serial.printf("%02X ", sessionKey[i]); Serial.println();

  // CRC32 over: newKey(16) + keyVersion(1)
  uint8_t newAESKey[16] = {0};
  uint8_t keyVersion    = 0x10;
  uint8_t crcInput[17];
  memcpy(crcInput, newAESKey, 16);
  crcInput[16] = keyVersion;

  uint32_t crc = 0xFFFFFFFF;
  for (int i = 0; i < 17; i++) {
    crc ^= crcInput[i];
    for (int b = 0; b < 8; b++)
      crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
  }
  crc ^= 0xFFFFFFFF;

  // Payload = newKey(16) + keyVersion(1) + CRC32(4) = 21 bytes, pad to 24
  uint8_t changeKeyData[24] = {0};
  memcpy(changeKeyData, newAESKey, 16);
  changeKeyData[16] = keyVersion;
  changeKeyData[17] = (crc >>  0) & 0xFF;
  changeKeyData[18] = (crc >>  8) & 0xFF;
  changeKeyData[19] = (crc >> 16) & 0xFF;
  changeKeyData[20] = (crc >> 24) & 0xFF;

  uint8_t encPayload[24];
  uint8_t iv3[8] = {0};
  tdesCbcEncrypt(sessionKey, iv3, changeKeyData, encPayload, 24);

  Serial.print("[Migrate] rndA:          ");
  for (int i = 0; i < 8; i++) Serial.printf("%02X ", rndA[i]); Serial.println();
  Serial.print("[Migrate] rndB:          ");
  for (int i = 0; i < 8; i++) Serial.printf("%02X ", rndB[i]); Serial.println();
  Serial.print("[Migrate] sessionKey:    ");
  for (int i = 0; i < 16; i++) Serial.printf("%02X ", sessionKey[i]); Serial.println();
  Serial.print("[Migrate] changeKeyData: ");
  for (int i = 0; i < 24; i++) Serial.printf("%02X ", changeKeyData[i]); Serial.println();
  Serial.printf("[Migrate] CRC32:         %08X\n", crc);
  Serial.print("[Migrate] encPayload:    ");
  for (int i = 0; i < 24; i++) Serial.printf("%02X ", encPayload[i]); Serial.println();

  // Native DESFire ChangeKey: [C4] [keyNo] [24 bytes encrypted payload]
  uint8_t changeKeyCmd[26];
  changeKeyCmd[0] = 0xC4;
  changeKeyCmd[1] = 0x00;
  memcpy(changeKeyCmd + 2, encPayload, 24);

  Serial.print("[Migrate] Raw changeKeyCmd: ");
  for (int i = 0; i < sizeof(changeKeyCmd); i++) Serial.printf("%02X ", changeKeyCmd[i]);
  Serial.println();

  respLen = sizeof(resp);
  bool ckOk = nfc.inDataExchange(const_cast<uint8_t*>(changeKeyCmd), sizeof(changeKeyCmd), resp, &respLen);

  Serial.printf("[Migrate] ChangeKey returned: %d, respLen: %u\n", ckOk, respLen);
  Serial.print("[Migrate] ChangeKey resp: ");
  for (int i = 0; i < respLen; i++) Serial.printf("%02X ", resp[i]); Serial.println();

  if (!ckOk) {
    Serial.println("[Migrate] ChangeKey RF failure");
    return false;
  }

  if (respLen >= 1 && resp[0] == 0x00) {
    Serial.println("[Migrate] SUCCESS — key changed to AES!");
    Serial.println("[Migrate] *** Comment out migrateKeyToAES() in loop() now ***");
    return true;
  }

  Serial.printf("[Migrate] ChangeKey failed code: %02X\n", resp[0]);
  return false;
}

void applyLockStatus(bool lockStatus) {
  if (lockStatus == currentLockStatus) return;
  currentLockStatus = lockStatus;
  digitalWrite(blueLedPin, lockStatus ? HIGH : LOW);
  if (lockStatus) { lockDoor();   Serial.println("Servo: LOCK"); }
  else            { unlockDoor(); Serial.println("Servo: UNLOCK"); }
  delay(500);
}

bool parseLockStatus(const String& payload, bool& outStatus) {
  StaticJsonDocument<256> doc;
  if (deserializeJson(doc, payload) || !doc.containsKey("result")) return false;
  outStatus = doc["result"];
  return true;
}

void sendCardUIDToDjango(const String& uid) {
  if (WiFi.status() != WL_CONNECTED) return;
  HTTPClient http;
  http.begin(String(DJANGO_BASE_URL) + CARD_REQUEST_PATH);
  http.addHeader("Content-Type", "application/json");
  String body = String("{\"lock_id\":") + lockId + ",\"uid\":\"" + uid + "\"}";
  Serial.print("Request body: "); Serial.println(body);
  int httpCode = http.POST(body);
  if (httpCode > 0) {
    String payload = http.getString();
    Serial.printf("card_request response (%d): %s\n", httpCode, payload.c_str());
    bool lockStatus;
    if (payload.length() > 0 && parseLockStatus(payload, lockStatus))
      applyLockStatus(lockStatus);
  } else {
    Serial.print("card_request POST failed: ");
    Serial.println(http.errorToString(httpCode));
  }
  http.end();
}

void pollLockStatusFromDjango() {
  if (WiFi.status() != WL_CONNECTED) return;
  HTTPClient http;
  http.begin(String(DJANGO_BASE_URL) + STATUS_REQUEST_PATH);
  http.addHeader("Content-Type", "application/json");
  int httpCode = http.POST(String("{\"lock_id\":") + lockId + "}");
  if (httpCode > 0) {
    bool lockStatus;
    if (parseLockStatus(http.getString(), lockStatus))
      applyLockStatus(lockStatus);
  }
  http.end();
}

void TaskPollLockStatus(void *pvParameters) {
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

  Serial.printf("Connecting to WiFi %s\n", ssid);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.printf("\nConnected! IP: %s\n", WiFi.localIP().toString().c_str());

  pollLockStatusFromDjango();

  Serial1.begin(115200, SERIAL_8N1, 17, 16);
  delay(200);
  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata) { Serial.println("Didn't find PN532"); while (1); }
  Serial.printf("Found chip PN5%02X\n", (versiondata >> 24) & 0xFF);

  nfc.SAMConfig();
  Serial.println("Waiting for NFC card...");
  testDES();  // ← confirm DES is correct before scanning

  xTaskCreatePinnedToCore(TaskPollLockStatus, "PollLockStatus", 4096, NULL, 1, NULL, 0);
}

void loop() {
  uint8_t uid[7];
  uint8_t uidLength;

  if (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 2000, true)) {
    delay(100);
    return;
  }

  String uidString = "";
  for (uint8_t i = 0; i < uidLength; i++) {
    if (uid[i] < 0x10) uidString += "0";
    uidString += String(uid[i], HEX);
    if (i < uidLength - 1) uidString += ":";
  }
  uidString.toUpperCase();
  Serial.printf("Card detected, UID: %s\n", uidString.c_str());

  // RATS — activate ISO 14443-4
  uint8_t rats[]      = { 0xE0, 0x80 };
  uint8_t ratsResp[32];
  uint8_t ratsRespLen = sizeof(ratsResp);
  if (!nfc.inDataExchange(const_cast<uint8_t*>(rats), sizeof(rats), ratsResp, &ratsRespLen)) {
    Serial.println("[ISO4] RATS failed");
    delay(1500);
    return;
  }
  Serial.print("[ISO4] ATS: ");
  for (int i = 0; i < ratsRespLen; i++) Serial.printf("%02X ", ratsResp[i]); Serial.println();

  // ── PHASE 1: run once to migrate key, then comment out and switch to PHASE 2
  migrateKeyToAES();

  // ── PHASE 2: normal operation after migration (uncomment when ready)
  // if (!authenticateDESFireAES(0x00)) {
  //   Serial.println("Auth failed."); delay(1500); return;
  // }
  // sendCardUIDToDjango(uidString);

  delay(3000);
}