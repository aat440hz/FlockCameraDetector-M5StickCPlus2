# Flock Camera Detector — M5StickC PLUS2 Edition

A pocket-sized, passive RF/BLE scanner that flags known [Flock Safety](https://www.flocksafety.com/) ALPR camera and "Raven" hardware signatures — WiFi SSIDs, MAC prefixes, BLE manufacturer IDs, and BLE service UUIDs — with a confidence score, GPS-tagged logging, and on-device screens for stats, live feed, and signal proximity.

This is a hardware port of [zmattmanz/flock-detection](https://github.com/zmattmanz/flock-detection) for the **M5StickC PLUS2**, rebuilt around its color TFT, built-in speaker, built-in button, and internal flash storage instead of an external OLED/SD/button setup. The detection engine itself — pattern matching, confidence scoring, RSSI stationary-signature tracking, time-windowed dedup — is unchanged from the original.

> This is a passive listener only. It never transmits, connects to, or interacts with any device it detects — it just watches WiFi management frames and BLE advertisements that are already public over the air and checks them against known signatures.

## What it does

- Sniffs WiFi beacon/probe frames across all 13 channels (adaptive dwell — longer on 1/6/11) and BLE advertisements, in parallel, on separate cores.
- Scores each observed device 0–100 using multiple independent signals (MAC prefix, SSID pattern, BLE name, manufacturer ID, Raven BLE service UUIDs, RSSI strength, and a "stationary RF signature" bonus for devices that show a rise-peak-fall RSSI curve as you drive past — as opposed to a phone-like device passing at close range).
- Alarms only above a confidence threshold, with three escalating tiers (MEDIUM / HIGH / CERTAIN).
- Logs every new detection to a CSV on internal flash, GPS-tagged when a fix is available.
- Persists lifetime detection counts and uptime across power cycles.

## Hardware

- **M5StickC PLUS2**
- A UART GPS module (e.g. NEO-6M / NEO-8M) wired to the Grove (HY2.0-4P) port

No other wiring is required — display, button, buzzer, and storage all use the Stick's built-in hardware.

### Wiring

| GPS module | M5StickC PLUS2 |
|---|---|
| TX | G32 |
| RX | G33 |
| VCC | 5V |
| GND | GND |

## Libraries

Install via Arduino Library Manager:

- `M5Unified`
- `NimBLE-Arduino` (2.x — the version bundled with the M5Stack ESP32 board package)
- `TinyGPSPlus`
- `ArduinoJson`

**Board:** select `M5StickCPlus2` from the M5Stack board package, with a partition scheme that includes a LittleFS/SPIFFS data partition (e.g. *"8M with spiffs (3MB APP/1.5MB SPIFFS)"*).

### Required: `build_opt.h`

WiFi promiscuous mode + the full NimBLE stack together are right at the edge of the ESP32's internal IRAM. This sketch only *scans* for BLE (it never advertises or connects out), so unused NimBLE roles are disabled at compile time to fit. Place a file named `build_opt.h` in the **same folder as the `.ino`** containing:

```
-DCONFIG_BT_NIMBLE_ROLE_CENTRAL_DISABLED
-DCONFIG_BT_NIMBLE_ROLE_PERIPHERAL_DISABLED
-DCONFIG_BT_NIMBLE_ROLE_BROADCASTER_DISABLED
```

If a build still fails to link after adding this, delete the sketch's temp build folder (or restart the IDE) to force a clean rebuild — Arduino sometimes caches a stale build config.

## Controls

- **Short press (front button)** — cycle through the 7 screens
- **Long press (~1s)** — toggle stealth mode (display sleeps, alarm buzzer/flash suppressed)

### Screens

1. **Scanner** — live channel/scan animation, uptime, storage status
2. **Stats** — session vs. lifetime WiFi/BLE/Raven detection counts
3. **Last Capture** — most recent detection: time, RSSI, type, method, MAC, confidence
4. **Live Feed** — rolling log of the last 5 observations (flagged ones highlighted)
5. **GPS** — lat/lon, speed, heading, satellite/fix status
6. **Activity Chart** — detections per second over the last ~40 seconds
7. **Proximity** — signal-strength bar and distance estimate for the last capture

## Confidence scoring

Each match method contributes points; multiple independent methods and strong RSSI add bonuses. A device only alarms once its total crosses the alarm threshold, and is labeled by tier:

| Score | Label |
|---|---|
| ≥ 85 | CERTAIN |
| ≥ 70 | HIGH |
| ≥ 40 | MEDIUM (alarm threshold) |
| < 40 | LOW (logged to the live feed only, no alarm) |

Detections of the same MAC are suppressed for 5 minutes so you don't get re-alarmed sitting at a red light near the same camera, then re-armed automatically as you move on.

## Logging

M5StickC PLUS2 has **no SD card slot**, so logging goes to internal flash via LittleFS instead of an SD card. Each session writes a numbered `/FlockLog_NNN.csv` with columns for timestamp, GPS position/speed/heading, detection type, RSSI, MAC, confidence, and detection method. Internal flash capacity is much smaller than an SD card (roughly 1–1.5MB usable, depending on partition scheme) — plan to pull logs off periodically rather than logging for days unattended.

Lifetime counters (total WiFi/BLE detections, uptime) persist across power cycles and are restored on boot.

## Disclaimer

This tool identifies devices based on publicly broadcast RF signatures (SSIDs, MAC address vendor prefixes, BLE advertisement data). It does not intercept, decode, or interact with any private communications, and detections are probabilistic pattern matches, not confirmed identifications — treat the confidence score as a guide, not proof. Signature lists may go stale as hardware changes; false positives and false negatives are both possible. Check your local laws regarding RF monitoring and camera/surveillance-detection devices before use.

## Credits

Detection logic and signature database originally from [zmattmanz/flock-detection](https://github.com/zmattmanz/flock-detection). This repository adapts it to M5StickC PLUS2 hardware.
