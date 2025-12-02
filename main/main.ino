#include <Wire.h>
#include <Adafruit_PN532.h>

Adafruit_PN532 nfc(-1, -1);

const int blueLedPin = 2;                     

String authorizedUID = "4C:05:3F:06";   

void setup() {
  Serial.begin(115200);

  pinMode(blueLedPin, OUTPUT);
  digitalWrite(blueLedPin, LOW);              

  nfc.begin();
  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata) {
    Serial.println("Didn't find PN532");
    while (1); 
  }
  nfc.SAMConfig();
  Serial.println("Waiting for an NFC card...");
}

void loop() {
  uint8_t uid[7];
  uint8_t uidLength;

  if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 3000)) {

    String uidString = "";
    for (uint8_t i = 0; i < uidLength; i++) {
      if (uid[i] < 0x10) uidString += "0";
      uidString += String(uid[i], HEX);
      if (i < uidLength - 1) uidString += ":";
    }
    uidString.toUpperCase();

    Serial.print("Card UID: ");
    Serial.println(uidString);

    if (uidString == authorizedUID) {
      Serial.println("Authorized.");

      digitalWrite(blueLedPin, HIGH);   
      delay(2000);                     
      digitalWrite(blueLedPin, LOW);    
    } else {
      Serial.println("Unauthorized card.");
    }

    delay(1000);
  }
}
