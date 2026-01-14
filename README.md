# Smart Lock System – Embedded Firmware (ESP32)

This repository contains the embedded firmware for a smart lock system, built on an **ESP32** microcontroller.  
It is one part of a **three-component architecture**:

1. **Embedded firmware (this repo)** – Controls hardware (servo lock, NFC reader, LEDs) and communicates with the backend.
2. **[Backend Repository](https://github.com/albertodsandoval/quicklock-be) ** – Handles authentication, card validation, lock state management, and APIs.
3. **[Frontend Repository](https://github.com/DylanOseida/QuickLock-FE) ** – Provides a user interface for managing locks, users, and access permissions.

---

## System Overview

The ESP32 does the following tasks:

- Reads NFC card UIDs using a **PN532** module
- Sends card data to a **Django backend** over Wi-Fi (HTTP/JSON)
- Receives lock/unlock decisions from the backend
- Controls a **servo motor** to lock or unlock the door
- Polls the backend for lock state changes
  
---

## Software Dependencies

- Arduino framework for ESP32
- Libraries:
  - `WiFi.h`
  - `HTTPClient.h`
  - `Adafruit_PN532`

---

## Pin Configuration

| Component     | ESP32 Pin |
|---------------|-----------|
| Servo Signal  | GPIO 18   |
| PN532 I²C     | Default ESP32 I²C pins |

