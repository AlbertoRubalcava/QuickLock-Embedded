# QuickLock Embedded Firmware (ESP32)

This repository contains the embedded firmware for QuickLock, built on an **ESP32** microcontroller.  
It is one part of a **three-component architecture**:

1. [Embedded Repository](https://github.com/AlbertoRubalcava/QuickLock-Embedded) - Controls hardware (servo lock, PN532 NFC reader, and blue LED) and communicates with the backend.
2. [Backend Repository](https://github.com/albertodsandoval/quicklock-be) - Handles authentication, card validation, lock state management, and APIs.
3. [Frontend Repository](https://github.com/DylanOseida/QuickLock-FE) - Provides a user interface for managing locks, users, and access permissions.

---

## System Overview

The ESP32 does the following tasks:

- Reads NFC card UIDs using a **PN532** module over UART/HSU
- Sends card UIDs to a **Django backend** over Wi-Fi (HTTP/JSON)
- Polls the backend for lock state changes
- Controls a **servo motor** to lock or unlock the door
- Updates the blue LED to match the lock status
  
---

## Software Dependencies

- Arduino framework for ESP32
- Libraries:
  - `WiFi.h`
  - `HTTPClient.h`
  - `ArduinoJson`
  - `PN532`
  - `PN532_HSU`

---

## Local Secrets

Copy `main/secrets.example.h` to `main/secrets.h` and fill in your Wi-Fi name, Wi-Fi password, and backend URL. `main/secrets.h` is ignored by Git so local network credentials do not get committed.

---

## Pin Configuration

| Component     | ESP32 Pin |
|---------------|-----------|
| Servo Signal  | GPIO 18   |
| PN532 RX      | GPIO 17   |
| PN532 TX      | GPIO 16   |
| Blue LED      | GPIO 2    |
