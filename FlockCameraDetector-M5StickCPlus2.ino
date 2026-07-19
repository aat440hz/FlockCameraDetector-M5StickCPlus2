// ============================================================================
// Flock Safety / ALPR Detector — ported for M5StickC PLUS2
// Original: https://github.com/zmattmanz/flock-detection
// Detection logic (MAC/SSID/mfg-ID/UUID pattern matching, confidence scoring,
// RSSI stationary-signature tracking, time-windowed dedup) is unchanged.
// Platform layer (display, button, buzzer, storage, GPS wiring) rewritten
// for M5StickC PLUS2 hardware.
//
// REQUIRED LIBRARIES (Arduino Library Manager):
//   M5Unified          (display, button, speaker, power)
//   NimBLE-Arduino     (BLE scanning — 1.4.x API used here)
//   TinyGPSPlus
//   ArduinoJson
// Board: "M5StickCPlus2" (installed via M5Stack board package), or generic
// ESP32-PICO-D4 with partition scheme "Default 4MB with spiffs (1.2MB APP/1.5MB SPIFFS)"
// or similar — LittleFS needs a data partition.
//
// HARDWARE NOTES:
//   - M5StickC PLUS2 has NO SD card slot. Logging goes to internal flash via
//     LittleFS instead of SD. Capacity is small (roughly 1-1.5MB depending on
//     partition scheme) — expect to pull logs off periodically, not run for days.
//   - Buzzer is driven through M5.Speaker (I2S), not a bare GPIO tone() pin.
//   - GPS module wires to the Grove (HY2.0-4P) port: G32/G33.
//   - Front button (BtnA) replaces the external push-button: short press =
//     cycle screens, long press (1s) = toggle stealth mode (display sleep).
// ============================================================================

#include <M5Unified.h>
#include <WiFi.h>
#include <NimBLEDevice.h>
#include <NimBLEScan.h>
#include <NimBLEAdvertisedDevice.h>
#include <ArduinoJson.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include <LittleFS.h>
#include <TinyGPSPlus.h>
#include <HardwareSerial.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

// ============================================================================
// CONFIGURATION
// ============================================================================

// --- GPS wiring: Grove port (HY2.0-4P) on M5StickC PLUS2 ---
#define RX_PIN 32   // GPS TX -> here
#define TX_PIN 33   // GPS RX <- here
#define GPS_BAUD 9600
TinyGPSPlus gps;
HardwareSerial SerialGPS(2);   // UART2 (UART0 is used by USB Serial)

#define LOW_FREQ 200
#define HIGH_FREQ 800
#define DETECT_FREQ 1000
#define DETECT_FREQ_HIGH 1200
#define DETECT_FREQ_CERTAIN 1500
#define BOOT_BEEP_DURATION 300
#define DETECT_BEEP_DURATION 150

#define MAX_CHANNEL 13
#define BLE_SCAN_DURATION 2
#define BLE_SCAN_INTERVAL 3000
#define BUZZER_COOLDOWN 60000
#define LOG_UPDATE_DELAY 500
#define IGNORE_WEAK_RSSI -80

#define MAX_LOG_BUFFER 10
#define LOG_FLUSH_INTERVAL 10000

// --- Adaptive channel dwell times (milliseconds) ---
#define DWELL_PRIMARY   500
#define DWELL_SECONDARY 200

// --- Time-windowed re-detection ---
#define REDETECT_WINDOW_MS 300000

// --- RSSI trend tracking ---
#define RSSI_TRACK_MAX_DEVICES 16
#define RSSI_TRACK_SAMPLES 5
#define RSSI_TRACK_EXPIRY_MS 15000
#define CONF_BONUS_STATIONARY 15

// --- Session persistence ---
#define PERSIST_INTERVAL_MS 60000
#define PERSIST_FILE "/flock_session.dat"

// ============================================================================
// CONFIDENCE SCORING (unchanged from original)
// ============================================================================

#define CONF_MAC_PREFIX       40
#define CONF_SSID_PATTERN     50
#define CONF_SSID_FLOCK_FMT   65
#define CONF_BLE_NAME         45
#define CONF_MFG_ID           60
#define CONF_RAVEN_UUID       70
#define CONF_RAVEN_MULTI_UUID 90
#define CONF_PENGUIN_SERIAL   80

#define CONF_BONUS_STRONG_RSSI  10
#define CONF_BONUS_MULTI_METHOD 20
#define CONF_BONUS_BLE_STATIC_ADDR 10

#define CONFIDENCE_ALARM_THRESHOLD 40
#define CONFIDENCE_HIGH    70
#define CONFIDENCE_CERTAIN 85

// ============================================================================
// DISPLAY (M5Canvas sprite mirrors old "display.display()" push pattern)
// ============================================================================
#define SCR_W 240
#define SCR_H 135
M5Canvas canvas(&M5.Display);

// ============================================================================
// GLOBAL VARIABLES
// ============================================================================
TaskHandle_t ScannerTaskHandle;
SemaphoreHandle_t dataMutex;

static uint8_t current_channel = 1;
static unsigned long last_channel_hop = 0;
static unsigned long last_ble_scan = 0;
static unsigned long last_buzzer_time = 0;
static NimBLEScan* pBLEScan;
bool storage_available = false;   // LittleFS mounted + writable
volatile int trigger_alarm_confidence = 0;

std::vector<String> log_write_buffer;
unsigned long last_log_flush = 0;

String current_log_file = "/FlockLog_001.csv";

int current_screen = 0;
bool stealth_mode = false;
bool button_hold_handled = false;

long session_wifi = 0;
long session_ble = 0;
unsigned long session_start_time = 0;
long lifetime_wifi = 0;
long lifetime_ble = 0;
unsigned long lifetime_seconds = 0;
long lifetime_flock_total = 0;

// --- Time-windowed MAC dedup ring buffer ---
#define MAX_SEEN_MACS 200
struct SeenMAC {
    String mac;
    unsigned long timestamp;
};
SeenMAC seen_macs[MAX_SEEN_MACS];
int seen_macs_count = 0;
int seen_macs_write_idx = 0;

String last_cap_type = "None";
String last_cap_mac = "--:--:--:--:--:--";
int last_cap_rssi = 0;
int last_cap_confidence = 0;
String last_cap_time = "00:00:00";
String last_cap_det_method = "";
String live_logs[5] = {"", "", "", "", ""};

unsigned long last_uptime_update = 0;
unsigned long last_anim_update = 0;
unsigned long last_stats_screen_update = 0;
unsigned long last_capture_screen_update = 0;
unsigned long last_livelog_screen_update = 0;
unsigned long last_gps_screen_update = 0;
unsigned long last_chart_screen_update = 0;
unsigned long last_proximity_screen_update = 0;
unsigned long last_time_save = 0;
unsigned long last_log_update = 0;
unsigned long last_persist_save = 0;
int scan_line_x = 0;
bool force_redraw = true;   // set true on screen switch so the new screen draws immediately

#define CHART_BARS 40
int activity_history[CHART_BARS] = {0};
unsigned long last_chart_update = 0;
long last_total_dets = 0;

long session_flock_wifi = 0;
long session_flock_ble = 0;
long session_raven = 0;

// --- RSSI trend tracker ---
struct RSSITrack {
    String mac;
    int samples[RSSI_TRACK_SAMPLES];
    int sample_count;
    unsigned long last_seen;
    bool scored;
};
RSSITrack rssi_tracker[RSSI_TRACK_MAX_DEVICES];
int rssi_tracker_count = 0;

// ============================================================================
// UI BITMAPS (8x8 monochrome, unchanged)
// ============================================================================
const unsigned char map_pin_icon[] PROGMEM = { 0x3C, 0x7E, 0x66, 0x66, 0x7E, 0x3C, 0x18, 0x00 };
const unsigned char clock_icon[] PROGMEM = { 0x3C, 0x42, 0x42, 0x52, 0x4A, 0x42, 0x3C, 0x00 };

// ============================================================================
// DETECTION SIGNATURE DATABASE (unchanged)
// ============================================================================

static const char* wifi_ssid_patterns[] = {
    "flock", "Flock", "FLOCK",
    "FS Ext Battery", "FS_",
    "Penguin", "Pigvision",
    "FlockOS", "flocksafety",
};
static const int NUM_SSID_PATTERNS = sizeof(wifi_ssid_patterns) / sizeof(wifi_ssid_patterns[0]);

static const char* mac_prefixes[] = {
    "58:8e:81", "cc:cc:cc", "ec:1b:bd", "90:35:ea",
    "f0:82:c0", "1c:34:f1", "38:5b:44", "94:34:69",
    "b4:e3:f9", "3c:91:80", "d8:f3:bc", "80:30:49",
    "14:5a:fc", "9c:2f:9d", "94:08:53", "e4:aa:ea",
    "48:e7:29", "c8:c9:a3",
    "74:4c:a1", "70:c9:4e",
    "04:0d:84",
    "08:3a:88",
    "a4:cf:12",
    "d8:a0:d8",
};
static const int NUM_MAC_PREFIXES = sizeof(mac_prefixes) / sizeof(mac_prefixes[0]);

static const char* device_name_patterns[] = {
    "FS Ext Battery", "Penguin", "Flock", "Pigvision", "FlockCam", "FS-",
};
static const int NUM_NAME_PATTERNS = sizeof(device_name_patterns) / sizeof(device_name_patterns[0]);

static const char* raven_service_uuids[] = {
    "0000180a-0000-1000-8000-00805f9b34fb",
    "00003100-0000-1000-8000-00805f9b34fb",
    "00003200-0000-1000-8000-00805f9b34fb",
    "00003300-0000-1000-8000-00805f9b34fb",
    "00003400-0000-1000-8000-00805f9b34fb",
    "00003500-0000-1000-8000-00805f9b34fb",
    "00001809-0000-1000-8000-00805f9b34fb",
    "00001819-0000-1000-8000-00805f9b34fb",
};
static const int NUM_RAVEN_UUIDS = sizeof(raven_service_uuids) / sizeof(raven_service_uuids[0]);

#define FLOCK_MFG_COMPANY_ID 0x09C8

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

void beep(int frequency, int duration_ms) {
    M5.Speaker.tone(frequency, duration_ms);
    delay(duration_ms + 50);
}

void boot_beep_sequence() {
    beep(LOW_FREQ, BOOT_BEEP_DURATION);
    beep(HIGH_FREQ, BOOT_BEEP_DURATION);
}

String format_time(unsigned long total_sec) {
    unsigned long m = (total_sec / 60) % 60;
    unsigned long h = (total_sec / 3600);
    if (h > 99) return String(h) + "h " + String(m) + "m";
    unsigned long s = total_sec % 60;
    char timeStr[10];
    sprintf(timeStr, "%02lu:%02lu:%02lu", h, m, s);
    return String(timeStr);
}

String short_mac(const String& mac) {
    if (mac.length() > 8) return mac.substring(9);
    return mac;
}

String bytesToHexStr(const std::string& data) {
    String res = "";
    for (size_t i = 0; i < data.length(); i++) {
        char buf[4]; sprintf(buf, "%02X", (uint8_t)data[i]); res += buf;
    }
    return res;
}

String get_gps_datetime() {
    if (!gps.date.isValid() || !gps.time.isValid()) return "No_GPS_Time";
    char dt[24];
    sprintf(dt, "%04d-%02d-%02d %02d:%02d:%02d",
            gps.date.year(), gps.date.month(), gps.date.day(),
            gps.time.hour(), gps.time.minute(), gps.time.second());
    return String(dt);
}

const char* confidence_label(int score) {
    if (score >= CONFIDENCE_CERTAIN) return "CERTAIN";
    if (score >= CONFIDENCE_HIGH) return "HIGH";
    if (score >= CONFIDENCE_ALARM_THRESHOLD) return "MEDIUM";
    return "LOW";
}

// ============================================================================
// SESSION PERSISTENCE (LittleFS)
// ============================================================================

void save_session_to_flash() {
    if (!storage_available) return;
    File f = LittleFS.open(PERSIST_FILE, "w");
    if (!f) return;

    xSemaphoreTake(dataMutex, portMAX_DELAY);
    f.printf("%ld\n%ld\n%lu\n%ld\n", lifetime_wifi, lifetime_ble, lifetime_seconds, lifetime_flock_total);
    xSemaphoreGive(dataMutex);

    f.close();
    last_persist_save = millis();
}

void load_session_from_flash() {
    if (!LittleFS.exists(PERSIST_FILE)) return;

    File f = LittleFS.open(PERSIST_FILE, "r");
    if (!f) return;

    String line;
    line = f.readStringUntil('\n'); if (line.length() > 0) lifetime_wifi = line.toInt();
    line = f.readStringUntil('\n'); if (line.length() > 0) lifetime_ble = line.toInt();
    line = f.readStringUntil('\n'); if (line.length() > 0) lifetime_seconds = line.toInt();
    line = f.readStringUntil('\n'); if (line.length() > 0) lifetime_flock_total = line.toInt();

    f.close();
    Serial.print(F("Restored: WiFi=")); Serial.print(lifetime_wifi);
    Serial.print(F(" BLE=")); Serial.print(lifetime_ble);
    Serial.print(F(" Time=")); Serial.print(format_time(lifetime_seconds));
    Serial.print(F(" Total=")); Serial.println(lifetime_flock_total);
}

// ============================================================================
// TIME-WINDOWED MAC DEDUPLICATION (unchanged)
// ============================================================================

bool is_mac_recently_seen(const String& mac) {
    unsigned long now = millis();
    int limit = min(seen_macs_count, MAX_SEEN_MACS);
    for (int i = 0; i < limit; i++) {
        if (seen_macs[i].mac == mac) {
            if ((now - seen_macs[i].timestamp) < REDETECT_WINDOW_MS) {
                return true;
            } else {
                seen_macs[i].timestamp = now;
                return false;
            }
        }
    }
    return false;
}

void add_seen_mac(const String& mac) {
    seen_macs[seen_macs_write_idx].mac = mac;
    seen_macs[seen_macs_write_idx].timestamp = millis();
    seen_macs_write_idx = (seen_macs_write_idx + 1) % MAX_SEEN_MACS;
    if (seen_macs_count < MAX_SEEN_MACS) seen_macs_count++;
}

// ============================================================================
// RSSI TREND TRACKING (unchanged)
// ============================================================================

void rssi_track_update(const String& mac, int rssi) {
    unsigned long now = millis();

    for (int i = 0; i < rssi_tracker_count; i++) {
        if (rssi_tracker[i].mac == mac) {
            if (rssi_tracker[i].sample_count < RSSI_TRACK_SAMPLES) {
                rssi_tracker[i].samples[rssi_tracker[i].sample_count++] = rssi;
            } else {
                for (int j = 0; j < RSSI_TRACK_SAMPLES - 1; j++) {
                    rssi_tracker[i].samples[j] = rssi_tracker[i].samples[j + 1];
                }
                rssi_tracker[i].samples[RSSI_TRACK_SAMPLES - 1] = rssi;
            }
            rssi_tracker[i].last_seen = now;
            return;
        }
    }

    if (rssi_tracker_count >= RSSI_TRACK_MAX_DEVICES) {
        int oldest_idx = 0;
        unsigned long oldest_time = rssi_tracker[0].last_seen;
        for (int i = 1; i < rssi_tracker_count; i++) {
            if (rssi_tracker[i].last_seen < oldest_time) {
                oldest_time = rssi_tracker[i].last_seen;
                oldest_idx = i;
            }
        }
        rssi_tracker[oldest_idx].mac = mac;
        rssi_tracker[oldest_idx].samples[0] = rssi;
        rssi_tracker[oldest_idx].sample_count = 1;
        rssi_tracker[oldest_idx].last_seen = now;
        rssi_tracker[oldest_idx].scored = false;
        return;
    }

    rssi_tracker[rssi_tracker_count].mac = mac;
    rssi_tracker[rssi_tracker_count].samples[0] = rssi;
    rssi_tracker[rssi_tracker_count].sample_count = 1;
    rssi_tracker[rssi_tracker_count].last_seen = now;
    rssi_tracker[rssi_tracker_count].scored = false;
    rssi_tracker_count++;
}

bool rssi_track_is_stationary(const String& mac) {
    for (int i = 0; i < rssi_tracker_count; i++) {
        if (rssi_tracker[i].mac == mac && rssi_tracker[i].sample_count >= 3 && !rssi_tracker[i].scored) {
            int n = rssi_tracker[i].sample_count;
            int* s = rssi_tracker[i].samples;

            int peak_idx = 0;
            for (int j = 1; j < n; j++) {
                if (s[j] > s[peak_idx]) peak_idx = j;
            }

            int range = s[peak_idx] - min(s[0], s[n - 1]);

            if (peak_idx > 0 && peak_idx < n - 1 && range >= 6) {
                rssi_tracker[i].scored = true;
                return true;
            }
            return false;
        }
    }
    return false;
}

void rssi_track_expire() {
    unsigned long now = millis();
    for (int i = rssi_tracker_count - 1; i >= 0; i--) {
        if ((now - rssi_tracker[i].last_seen) > RSSI_TRACK_EXPIRY_MS) {
            for (int j = i; j < rssi_tracker_count - 1; j++) {
                rssi_tracker[j] = rssi_tracker[j + 1];
            }
            rssi_tracker_count--;
        }
    }
}

// ============================================================================
// WiFi SSID FORMAT VALIDATION (unchanged)
// ============================================================================

bool is_flock_ssid_format(const char* ssid) {
    if (!ssid) return false;
    if (strncmp(ssid, "Flock-", 6) != 0 && strncmp(ssid, "flock-", 6) != 0) return false;
    const char* suffix = ssid + 6;
    int len = strlen(suffix);
    if (len < 2 || len > 12) return false;
    for (int i = 0; i < len; i++) {
        if (!isxdigit(suffix[i])) return false;
    }
    return true;
}

// ============================================================================
// PENGUIN / RAVEN HELPERS (unchanged)
// ============================================================================

bool is_penguin_numeric_name(const char* name) {
    if (!name) return false;
    int len = strlen(name);
    if (len < 8 || len > 12) return false;
    for (int i = 0; i < len; i++) {
        if (!isdigit(name[i])) return false;
    }
    return true;
}

bool has_tn_serial(const std::string& mfg_data) {
    if (mfg_data.length() < 10) return false;
    for (size_t i = 8; i < mfg_data.length() - 1; i++) {
        if (mfg_data[i] == 'T' && mfg_data[i + 1] == 'N') return true;
    }
    return false;
}

String classify_raven_firmware(const NimBLEAdvertisedDevice* device) {
    if (!device || !device->haveServiceUUID()) return "Unknown";
    bool has_health = false, has_location = false;
    bool has_gps = false, has_power = false, has_network = false;
    bool has_upload = false, has_error = false;
    int count = device->getServiceUUIDCount();
    for (int i = 0; i < count; i++) {
        std::string uuid = device->getServiceUUID(i).toString();
        if (strcasestr(uuid.c_str(), "00001809")) has_health = true;
        if (strcasestr(uuid.c_str(), "00001819")) has_location = true;
        if (strcasestr(uuid.c_str(), "00003100")) has_gps = true;
        if (strcasestr(uuid.c_str(), "00003200")) has_power = true;
        if (strcasestr(uuid.c_str(), "00003300")) has_network = true;
        if (strcasestr(uuid.c_str(), "00003400")) has_upload = true;
        if (strcasestr(uuid.c_str(), "00003500")) has_error = true;
    }
    if (has_gps && has_power && has_network && has_upload && has_error) return "1.3.x";
    if (has_gps && has_power && has_network) return "1.2.x";
    if (has_health || has_location) return "1.1.x";
    return "Unknown";
}

int count_raven_uuids(const NimBLEAdvertisedDevice* device) {
    if (!device || !device->haveServiceUUID()) return 0;
    int matched = 0;
    int count = device->getServiceUUIDCount();
    for (int i = 0; i < count; i++) {
        std::string uuid = device->getServiceUUID(i).toString();
        for (int j = 0; j < NUM_RAVEN_UUIDS; j++) {
            if (strcasecmp(uuid.c_str(), raven_service_uuids[j]) == 0) { matched++; break; }
        }
    }
    return matched;
}

// ============================================================================
// PATTERN MATCHING (unchanged)
// ============================================================================

bool check_mac_prefix(const uint8_t* mac) {
    char mac_str[9];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x", mac[0], mac[1], mac[2]);
    for (int i = 0; i < NUM_MAC_PREFIXES; i++) {
        if (strncasecmp(mac_str, mac_prefixes[i], 8) == 0) return true;
    }
    return false;
}

bool check_ssid_pattern(const char* ssid) {
    if (!ssid || strlen(ssid) == 0) return false;
    for (int i = 0; i < NUM_SSID_PATTERNS; i++) {
        if (strcasestr(ssid, wifi_ssid_patterns[i])) return true;
    }
    return false;
}

bool check_device_name_pattern(const char* name) {
    if (!name || strlen(name) == 0) return false;
    for (int i = 0; i < NUM_NAME_PATTERNS; i++) {
        if (strcasestr(name, device_name_patterns[i])) return true;
    }
    return false;
}

bool check_manufacturer_id(const std::string& mfg_data) {
    if (mfg_data.length() >= 2) {
        uint16_t mfg_id = (uint8_t)mfg_data[0] | ((uint8_t)mfg_data[1] << 8);
        if (mfg_id == FLOCK_MFG_COMPANY_ID) return true;
    }
    return false;
}

// ============================================================================
// STORAGE (LittleFS — replaces SD card, which M5StickC PLUS2 does not have)
// ============================================================================

void flush_log_buffer() {
    xSemaphoreTake(dataMutex, portMAX_DELAY);
    if (log_write_buffer.empty() || !storage_available) { xSemaphoreGive(dataMutex); return; }
    std::vector<String> temp_buffer = log_write_buffer;
    log_write_buffer.clear();
    xSemaphoreGive(dataMutex);
    File file = LittleFS.open(current_log_file.c_str(), FILE_APPEND);
    if (file) {
        for (const String &line : temp_buffer) { file.println(line); }
        file.close(); last_log_flush = millis();
    }
}

// ============================================================================
// LOGGING (unchanged apart from SD -> LittleFS)
// ============================================================================

void log_detection(const char* type, const char* proto, int rssi, const char* mac,
                   const String& name, int channel, int tx_power, const String& extra_data,
                   const char* detection_method, int confidence) {
    String mac_str = String(mac);

    xSemaphoreTake(dataMutex, portMAX_DELAY);

    bool is_new = !is_mac_recently_seen(mac_str);
    if (is_new) add_seen_mac(mac_str);

    if (is_new) {
        if (strcmp(proto, "WIFI") == 0) { session_wifi++; lifetime_wifi++; session_flock_wifi++; }
        else { session_ble++; lifetime_ble++; }
        if (strstr(type, "RAVEN") != NULL) session_raven++;
        else if (strcmp(proto, "BLE") == 0) session_flock_ble++;
        lifetime_flock_total++;
    }

    last_cap_type = String(type);
    last_cap_mac = mac_str;
    last_cap_rssi = rssi;
    last_cap_confidence = confidence;
    last_cap_time = format_time((millis() - session_start_time) / 1000);
    last_cap_det_method = String(detection_method);

    String logEntry;
    if (name != "Hidden" && name != "Unknown" && name != "") {
        String cleanName = name;
        if (cleanName.length() > 10) cleanName = cleanName.substring(0, 10);
        logEntry = "!" + cleanName + " " + String(confidence) + "%";
    } else {
        logEntry = "!" + String(proto) + " " + short_mac(mac_str) + " " + String(confidence) + "%";
    }
    if (millis() - last_log_update > LOG_UPDATE_DELAY) {
        for (int i = 4; i > 0; i--) live_logs[i] = live_logs[i - 1];
        live_logs[0] = logEntry;
        last_log_update = millis();
    }

    if (is_new && storage_available) {
        String clean_name = name; clean_name.replace(",", " ");
        String clean_extra = extra_data; clean_extra.replace(",", " ");
        String csv_line;
        csv_line.reserve(200);
        csv_line = String(millis()) + "," + get_gps_datetime() + "," +
                   String(channel) + "," + String(type) + "," + String(proto) + "," +
                   String(rssi) + "," + mac_str + "," + clean_name + "," +
                   String(tx_power) + "," + String(detection_method) + "," +
                   String(confidence) + "," + String(confidence_label(confidence)) + "," +
                   clean_extra + ",";
        bool gps_is_fresh = gps.location.isValid() && (gps.location.age() < 2000);
        if (gps_is_fresh) {
            csv_line += String(gps.location.lat(), 6) + "," + String(gps.location.lng(), 6) + ",";
            csv_line += String(gps.speed.isValid() && gps.speed.age() < 2000 ? gps.speed.mph() : 0.0, 1) + ",";
            csv_line += String(gps.course.isValid() && gps.course.age() < 2000 ? gps.course.deg() : 0.0, 1) + ",";
            csv_line += String(gps.altitude.isValid() ? gps.altitude.meters() : 0.0, 1);
        } else {
            csv_line += "0.000000,0.000000,0.0,0.0,0.0";
        }
        log_write_buffer.push_back(csv_line);
    }

    xSemaphoreGive(dataMutex);
}

// ============================================================================
// CORE 0 SCANNER TASK (unchanged)
// ============================================================================
void ScannerLoopTask(void * pvParameters) {
    for (;;) {
        unsigned long now = millis();

        bool is_primary = (current_channel == 1 || current_channel == 6 || current_channel == 11);
        unsigned long dwell = is_primary ? DWELL_PRIMARY : DWELL_SECONDARY;

        if (now - last_channel_hop > dwell) {
            current_channel++;
            if (current_channel > MAX_CHANNEL) current_channel = 1;
            esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
            last_channel_hop = now;
        }

        if (millis() - last_ble_scan >= BLE_SCAN_INTERVAL) {
            if (!pBLEScan->isScanning()) {
                pBLEScan->start(BLE_SCAN_DURATION, false);
                last_ble_scan = millis();
            }
        }
        if (!pBLEScan->isScanning() && (millis() - last_ble_scan > (unsigned long)(BLE_SCAN_DURATION * 1000 + 500))) {
            pBLEScan->clearResults();
        }
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
}

// ============================================================================
// WIFI PACKET HANDLER (unchanged)
// ============================================================================
typedef struct {
    unsigned frame_ctrl:16; unsigned duration_id:16;
    uint8_t addr1[6]; uint8_t addr2[6]; uint8_t addr3[6];
    unsigned sequence_ctrl:16; uint8_t addr4[6];
} wifi_ieee80211_mac_hdr_t;
typedef struct { wifi_ieee80211_mac_hdr_t hdr; uint8_t payload[0]; } wifi_ieee80211_packet_t;

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    if (ppkt->rx_ctrl.sig_len < 24) return;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    uint8_t frame_type = (hdr->frame_ctrl & 0x0C) >> 2;
    uint8_t frame_subtype = (hdr->frame_ctrl & 0xF0) >> 4;
    if (frame_type != 0) return;
    bool is_beacon = (frame_subtype == 8);
    bool is_probe_req = (frame_subtype == 4);
    if (!is_beacon && !is_probe_req) return;

    char ssid[33] = {0};
    uint8_t *frame_body = (uint8_t *)ipkt + 24;
    uint8_t *tagged_params;
    int remaining;
    if (is_beacon) {
        if (ppkt->rx_ctrl.sig_len < 24 + 12 + 2) return;
        tagged_params = frame_body + 12;
        remaining = ppkt->rx_ctrl.sig_len - 24 - 12 - 4;
    } else {
        tagged_params = frame_body;
        remaining = ppkt->rx_ctrl.sig_len - 24 - 4;
    }
    if (remaining > 2 && tagged_params[0] == 0 && tagged_params[1] <= 32 && tagged_params[1] <= remaining - 2) {
        memcpy(ssid, &tagged_params[2], tagged_params[1]);
        ssid[tagged_params[1]] = '\0';
    }

    int confidence = 0;
    String methods = "";

    bool mac_match = check_mac_prefix(hdr->addr2);
    bool ssid_generic = (strlen(ssid) > 0 && check_ssid_pattern(ssid));
    bool ssid_flock_fmt = (strlen(ssid) > 0 && is_flock_ssid_format(ssid));

    if (ssid_flock_fmt)      { confidence += CONF_SSID_FLOCK_FMT; methods += "ssid_fmt "; }
    else if (ssid_generic)   { confidence += CONF_SSID_PATTERN;    methods += "ssid "; }
    if (mac_match)           { confidence += CONF_MAC_PREFIX;      methods += "mac "; }

    int wifi_methods = 0;
    if (ssid_flock_fmt || ssid_generic) wifi_methods++;
    if (mac_match) wifi_methods++;
    if (wifi_methods >= 2) confidence += CONF_BONUS_MULTI_METHOD;
    if (ppkt->rx_ctrl.rssi > -50) confidence += CONF_BONUS_STRONG_RSSI;

    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
             hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
    String name_str = strlen(ssid) > 0 ? String(ssid) : "Hidden";
    String frame_type_str = is_beacon ? "Beacon" : "ProbeReq";

    if (confidence >= CONFIDENCE_ALARM_THRESHOLD) {
        rssi_track_update(String(mac_str), ppkt->rx_ctrl.rssi);
        if (rssi_track_is_stationary(String(mac_str))) {
            confidence += CONF_BONUS_STATIONARY;
        }
        if (confidence > 100) confidence = 100;

        methods.trim();
        log_detection("FLOCK_WIFI", "WIFI", ppkt->rx_ctrl.rssi, mac_str, name_str,
                      ppkt->rx_ctrl.channel, 0, frame_type_str, methods.c_str(), confidence);
        if (millis() - last_buzzer_time > BUZZER_COOLDOWN || last_buzzer_time == 0) {
            trigger_alarm_confidence = confidence;
            last_buzzer_time = millis();
        }
    } else if (ppkt->rx_ctrl.rssi > IGNORE_WEAK_RSSI) {
        if (millis() - last_log_update > LOG_UPDATE_DELAY) {
            xSemaphoreTake(dataMutex, portMAX_DELAY);
            String logEntry;
            if (name_str != "Hidden" && name_str != "") {
                String cn = name_str; if (cn.length() > 12) cn = cn.substring(0, 12);
                logEntry = cn + " (" + String(ppkt->rx_ctrl.rssi) + ")";
            } else {
                logEntry = "WiFi " + short_mac(String(mac_str)) + " (" + String(ppkt->rx_ctrl.rssi) + ")";
            }
            for (int i = 4; i > 0; i--) live_logs[i] = live_logs[i - 1];
            live_logs[0] = logEntry; last_log_update = millis();
            xSemaphoreGive(dataMutex);
        }
    }
}

// ============================================================================
// BLE CALLBACK
// NOTE: uses the NimBLE-Arduino 2.x callback API (NimBLEScanCallbacks /
// setScanCallbacks). If your installed NimBLE-Arduino is 1.x instead, change
// this back to "public NimBLEAdvertisedDeviceCallbacks" with a non-const
// pointer parameter, and use setAdvertisedDeviceCallbacks() in setup().
// ============================================================================
class AdvertisedDeviceCallbacks: public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* advertisedDevice) override {
        NimBLEAddress addr = advertisedDevice->getAddress();
        uint8_t mac[6];
        sscanf(addr.toString().c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

        int confidence = 0;
        String methods = "";
        String capture_type = "FLOCK_BLE";

        if (check_mac_prefix(mac)) { confidence += CONF_MAC_PREFIX; methods += "mac "; }

        String dev_name = advertisedDevice->haveName() ? String(advertisedDevice->getName().c_str()) : "Unknown";
        if (advertisedDevice->haveName()) {
            if (check_device_name_pattern(advertisedDevice->getName().c_str())) {
                confidence += CONF_BLE_NAME; methods += "name ";
            } else if (is_penguin_numeric_name(advertisedDevice->getName().c_str())) {
                confidence += 15; methods += "penguin_num ";
            }
        }

        bool has_xuntong = false;
        if (advertisedDevice->haveManufacturerData()) {
            std::string mfg = advertisedDevice->getManufacturerData();
            if (check_manufacturer_id(mfg)) {
                has_xuntong = true;
                confidence += CONF_MFG_ID; methods += "mfg_0x09C8 ";
                if (has_tn_serial(mfg)) {
                    confidence += (CONF_PENGUIN_SERIAL - CONF_MFG_ID);
                    methods += "tn_serial ";
                }
            }
        }

        int raven_uuid_count = count_raven_uuids(advertisedDevice);
        if (raven_uuid_count > 0) {
            capture_type = "RAVEN_BLE";
            if (raven_uuid_count >= 3) { confidence += CONF_RAVEN_MULTI_UUID; methods += "raven_multi "; }
            else { confidence += CONF_RAVEN_UUID; methods += "raven_uuid "; }
        }

        uint8_t addr_type = addr.getType();
        if (addr_type == 0) {
            confidence += CONF_BONUS_BLE_STATIC_ADDR;
            methods += "pub_addr ";
        } else if (addr_type == 1) {
            uint8_t top_bits = mac[0] >> 6;
            if (top_bits == 0x03) {
                confidence += CONF_BONUS_BLE_STATIC_ADDR;
                methods += "static_addr ";
            }
        }

        int method_count = 0;
        if (methods.indexOf("mac") >= 0) method_count++;
        if (methods.indexOf("name") >= 0 || methods.indexOf("penguin_num") >= 0) method_count++;
        if (methods.indexOf("mfg_") >= 0) method_count++;
        if (methods.indexOf("raven") >= 0) method_count++;
        if (method_count >= 2) confidence += CONF_BONUS_MULTI_METHOD;

        if (advertisedDevice->getRSSI() > -50) confidence += CONF_BONUS_STRONG_RSSI;

        String mac_string = String(addr.toString().c_str());
        if (confidence >= CONFIDENCE_ALARM_THRESHOLD) {
            rssi_track_update(mac_string, advertisedDevice->getRSSI());
            if (rssi_track_is_stationary(mac_string)) {
                confidence += CONF_BONUS_STATIONARY;
            }
        }

        if (confidence > 100) confidence = 100;

        if (confidence >= CONFIDENCE_ALARM_THRESHOLD) {
            int tx_power = advertisedDevice->haveTXPower() ? advertisedDevice->getTXPower() : 0;
            String mfg_hex = advertisedDevice->haveManufacturerData() ?
                bytesToHexStr(advertisedDevice->getManufacturerData()) : "";

            String extra_data = mfg_hex;
            if (capture_type == "RAVEN_BLE") {
                String fw = classify_raven_firmware(advertisedDevice);
                extra_data = "FW:" + fw + " UUIDs:" + String(raven_uuid_count);
                if (advertisedDevice->haveServiceUUID()) {
                    extra_data += " SVCS:";
                    int sc = advertisedDevice->getServiceUUIDCount();
                    for (int i = 0; i < sc && i < 8; i++) {
                        if (i > 0) extra_data += "|";
                        extra_data += String(advertisedDevice->getServiceUUID(i).toString().c_str()).substring(0, 8);
                    }
                }
            }

            methods.trim();
            log_detection(capture_type.c_str(), "BLE", advertisedDevice->getRSSI(),
                          addr.toString().c_str(), dev_name, 0, tx_power, extra_data,
                          methods.c_str(), confidence);

            if (millis() - last_buzzer_time > BUZZER_COOLDOWN || last_buzzer_time == 0) {
                trigger_alarm_confidence = confidence;
                last_buzzer_time = millis();
            }
        } else if (advertisedDevice->getRSSI() > IGNORE_WEAK_RSSI) {
            if (millis() - last_log_update > LOG_UPDATE_DELAY) {
                xSemaphoreTake(dataMutex, portMAX_DELAY);
                String logEntry;
                if (dev_name != "Unknown" && dev_name != "") {
                    String cn = dev_name; if (cn.length() > 12) cn = cn.substring(0, 12);
                    logEntry = cn + " (" + String(advertisedDevice->getRSSI()) + ")";
                } else {
                    logEntry = "BLE " + short_mac(mac_string) + " (" + String(advertisedDevice->getRSSI()) + ")";
                }
                for (int i = 4; i > 0; i--) live_logs[i] = live_logs[i - 1];
                live_logs[0] = logEntry; last_log_update = millis();
                xSemaphoreGive(dataMutex);
            }
        }
    }
};

// ============================================================================
// UI SCREENS — rebuilt for 240x135 color TFT via M5Canvas
// ============================================================================

void draw_header(const char* title) {
    canvas.setTextSize(1); canvas.setTextColor(TFT_WHITE, TFT_BLACK); canvas.setCursor(4, 2);
    canvas.print(title);
    canvas.drawLine(0, 12, SCR_W, 12, TFT_DARKGREY);
    int sats = gps.satellites.isValid() ? gps.satellites.value() : 0;
    String sat_str = String(sats);
    int text_w = canvas.textWidth(sat_str) + 2;
    canvas.drawBitmap(SCR_W - text_w - 12, 2, map_pin_icon, 8, 8, TFT_WHITE);
    canvas.setCursor(SCR_W - text_w, 2); canvas.print(sat_str);
}

void update_animation() {
    int y_min = 32, y_max = SCR_H - 16;
    canvas.fillScreen(TFT_BLACK);
    draw_header("Flock Detection");
    for (int i = 0; i < 6; i++) {
        int x = (scan_line_x + i * 20) % SCR_W;
        canvas.drawFastVLine(x, y_min, (y_max - y_min), TFT_DARKGREEN);
    }
    if (random(0, 100) < 40) canvas.drawPixel(random(0, SCR_W), random(y_min, y_max), TFT_GREEN);
    scan_line_x += 3; if (scan_line_x >= SCR_W) scan_line_x = 0;
    canvas.drawFastVLine(scan_line_x, y_min, (y_max - y_min), TFT_GREEN);
}

void draw_scanner_screen() {
    if (millis() - last_uptime_update > 60) {
        update_animation();
        canvas.setCursor(4, SCR_H - 10);
        canvas.drawBitmap(4, SCR_H - 10, clock_icon, 8, 8, TFT_WHITE);
        canvas.setCursor(14, SCR_H - 10); canvas.print(format_time((millis() - session_start_time) / 1000));
        if (storage_available) { canvas.setCursor(SCR_W - 40, SCR_H - 10); canvas.print(F("FS:OK")); }

        canvas.setCursor(4, 18);
        if (pBLEScan->isScanning()) canvas.print(F("Scanning: BLE..."));
        else {
            canvas.print(F("Ch:")); canvas.print(current_channel);
            bool pri = (current_channel == 1 || current_channel == 6 || current_channel == 11);
            canvas.print(pri ? F(" WiFi*") : F(" WiFi"));
        }
        canvas.pushSprite(0, 0);
        last_uptime_update = millis();
    }
}

void draw_stats_screen() {
    if (force_redraw || millis() - last_stats_screen_update > 500) {
        xSemaphoreTake(dataMutex, portMAX_DELAY);
        long tw = session_flock_wifi, tb = session_flock_ble, tr = session_raven;
        long lw = lifetime_wifi, lb = lifetime_ble, lt = lifetime_flock_total;
        unsigned long ls = lifetime_seconds;
        xSemaphoreGive(dataMutex);
        canvas.fillScreen(TFT_BLACK); draw_header("Detections");
        canvas.setCursor(4, 20); canvas.print(F("            SESS   ALL"));
        canvas.setCursor(4, 34); canvas.print(F("WiFi:")); canvas.setCursor(90, 34); canvas.print(tw); canvas.setCursor(160, 34); canvas.print(lw);
        canvas.setCursor(4, 48); canvas.print(F("BLE: "));  canvas.setCursor(90, 48); canvas.print(tb); canvas.setCursor(160, 48); canvas.print(lb);
        canvas.setCursor(4, 62); canvas.print(F("Raven:")); canvas.setCursor(90, 62); canvas.print(tr);
        canvas.setCursor(4, 78); canvas.print(F("Lifetime total: ")); canvas.print(lt);
        canvas.setCursor(4, 92); canvas.print(F("Uptime: ")); canvas.print(format_time(ls));
        canvas.pushSprite(0, 0);
        last_stats_screen_update = millis();
        force_redraw = false;
    }
}

void draw_last_capture_screen() {
    if (force_redraw || millis() - last_capture_screen_update > 500) {
        xSemaphoreTake(dataMutex, portMAX_DELAY);
        String t_type = last_cap_type, t_time = last_cap_time;
        String t_mac = last_cap_mac, t_method = last_cap_det_method;
        int t_rssi = last_cap_rssi, t_conf = last_cap_confidence;
        xSemaphoreGive(dataMutex);
        canvas.fillScreen(TFT_BLACK); draw_header("Last Capture");
        if (t_type == "None") { canvas.setCursor(4, 50); canvas.print(F("NO DATA YET")); }
        else {
            canvas.setCursor(4, 22); canvas.print(F("Time: ")); canvas.print(t_time);
            canvas.setCursor(140, 22); canvas.print(F("RSSI: ")); canvas.print(t_rssi);
            canvas.setCursor(4, 36); canvas.print(t_type);
            canvas.setCursor(4, 50); canvas.print(F("Method: ")); canvas.print(t_method);
            canvas.setCursor(4, 64); canvas.print(t_mac);
            canvas.setTextColor(t_conf >= CONFIDENCE_CERTAIN ? TFT_RED : (t_conf >= CONFIDENCE_HIGH ? TFT_ORANGE : TFT_YELLOW), TFT_BLACK);
            canvas.setCursor(4, 82); canvas.print(String(t_conf) + "% " + String(confidence_label(t_conf)));
            canvas.setTextColor(TFT_WHITE, TFT_BLACK);
        }
        canvas.pushSprite(0, 0);
        last_capture_screen_update = millis();
        force_redraw = false;
    }
}

void draw_live_log_screen() {
    if (force_redraw || millis() - last_livelog_screen_update > 100) {
        xSemaphoreTake(dataMutex, portMAX_DELAY);
        String t_logs[5]; for (int i = 0; i < 5; i++) t_logs[i] = live_logs[i];
        xSemaphoreGive(dataMutex);
        canvas.fillScreen(TFT_BLACK); draw_header("Live Feed");
        int y = 20;
        for (int i = 0; i < 5; i++) {
            if (t_logs[i] != "") {
                canvas.setCursor(4, y);
                if (t_logs[i].startsWith("!")) canvas.setTextColor(TFT_RED, TFT_BLACK);
                else canvas.setTextColor(TFT_WHITE, TFT_BLACK);
                canvas.print(t_logs[i]); canvas.setTextColor(TFT_WHITE, TFT_BLACK); y += 20;
            }
        }
        canvas.pushSprite(0, 0);
        last_livelog_screen_update = millis();
        force_redraw = false;
    }
}

void draw_gps_screen() {
    if (force_redraw || millis() - last_gps_screen_update > 500) {
        canvas.fillScreen(TFT_BLACK); draw_header("GPS Coordinates");
        bool has_loc = gps.location.isValid();
        bool stale = has_loc && (gps.location.age() > 2000);
        if (has_loc && !stale) {
            canvas.setCursor(4, 24); canvas.print(F("Lat: ")); canvas.print(gps.location.lat(), 6);
            canvas.setCursor(4, 42); canvas.print(F("Lon: ")); canvas.print(gps.location.lng(), 6);
            canvas.setCursor(4, 60); canvas.print(F("Spd: ")); canvas.print(gps.speed.mph(), 1);
            canvas.print(F("mph  Hdg: ")); canvas.print(gps.course.deg(), 0);
        } else if (has_loc && stale) {
            canvas.setCursor(4, 24); canvas.print(F("STATUS: SIGNAL LOST"));
            canvas.setCursor(4, 42); canvas.print(F("Last fix: ")); canvas.print(gps.location.age()/1000); canvas.print(F("s ago"));
            canvas.setCursor(4, 60); canvas.print(F("Waiting for sats..."));
        } else {
            int sats = gps.satellites.isValid() ? gps.satellites.value() : 0;
            canvas.setCursor(4, 24); canvas.print(F("Status: Searching Sky"));
            canvas.setCursor(4, 42); canvas.print(F("Sats: ")); canvas.print(sats); canvas.print(F(" / 4 Req"));
            canvas.setCursor(4, 60); canvas.print(F("Rx: ")); canvas.print(gps.charsProcessed()); canvas.print(F(" bytes"));
        }
        canvas.pushSprite(0, 0);
        last_gps_screen_update = millis();
        force_redraw = false;
    }
}

void draw_chart_screen() {
    if (force_redraw || millis() - last_chart_screen_update > 500) {
        canvas.fillScreen(TFT_BLACK); draw_header("Activity History");
        int max_val = 1;
        for (int i = 0; i < CHART_BARS; i++) { if (activity_history[i] > max_val) max_val = activity_history[i]; }
        int bar_w = SCR_W / CHART_BARS;
        for (int i = 0; i < CHART_BARS; i++) {
            int bar_h = (activity_history[i] * (SCR_H - 20)) / max_val;
            canvas.fillRect(i * bar_w, SCR_H - bar_h, bar_w - 1, bar_h, TFT_GREEN);
        }
        canvas.pushSprite(0, 0);
        last_chart_screen_update = millis();
        force_redraw = false;
    }
}

void draw_proximity_screen() {
    if (force_redraw || millis() - last_proximity_screen_update > 250) {
        xSemaphoreTake(dataMutex, portMAX_DELAY);
        int rssi = last_cap_rssi; String cap_type = last_cap_type; int conf = last_cap_confidence;
        xSemaphoreGive(dataMutex);
        canvas.fillScreen(TFT_BLACK); draw_header("Signal Proximity");
        if (cap_type == "None") { canvas.setCursor(4, 50); canvas.print(F("NO DATA YET")); }
        else {
            int pct = constrain(map(rssi, -100, -30, 0, 100), 0, 100);
            int bar_w = (pct * (SCR_W - 16)) / 100;
            canvas.setCursor(4, 22); canvas.print(F("RSSI: ")); canvas.print(rssi);
            canvas.print(F(" dBm   Conf: ")); canvas.print(conf); canvas.print(F("%"));
            canvas.drawRect(6, 44, SCR_W - 12, 20, TFT_WHITE);
            if (bar_w > 0) canvas.fillRect(8, 46, bar_w, 16, pct > 75 ? TFT_RED : (pct > 50 ? TFT_ORANGE : TFT_YELLOW));
            canvas.setCursor(4, 78);
            if (pct > 75) canvas.print(F(">> VERY CLOSE <<"));
            else if (pct > 50) canvas.print(F("> NEARBY <"));
            else if (pct > 25) canvas.print(F("Moderate range"));
            else canvas.print(F("Weak / distant"));
        }
        canvas.pushSprite(0, 0);
        last_proximity_screen_update = millis();
        force_redraw = false;
    }
}

void refresh_screen_layout() {
    if (stealth_mode) return;
    canvas.fillScreen(TFT_BLACK); draw_header("Flock Detection"); canvas.pushSprite(0, 0);
}

// ============================================================================
// ALARM ESCALATION (unchanged logic, M5.Speaker + M5.Display.invertDisplay)
// ============================================================================

void play_escalated_alarm(int confidence) {
    if (confidence >= CONFIDENCE_CERTAIN) {
        for (int i = 0; i < 5; i++) {
            if (!stealth_mode) M5.Display.invertDisplay(true);
            if (!stealth_mode) M5.Speaker.tone(DETECT_FREQ_CERTAIN, 100);
            delay(100);
            if (!stealth_mode) M5.Display.invertDisplay(false);
            if (i < 4) delay(30);
        }
    } else if (confidence >= CONFIDENCE_HIGH) {
        for (int i = 0; i < 3; i++) {
            if (!stealth_mode) M5.Display.invertDisplay(true);
            if (!stealth_mode) M5.Speaker.tone(DETECT_FREQ_HIGH, DETECT_BEEP_DURATION);
            delay(DETECT_BEEP_DURATION);
            if (!stealth_mode) M5.Display.invertDisplay(false);
            if (i < 2) delay(50);
        }
    } else {
        if (!stealth_mode) M5.Display.invertDisplay(true);
        if (!stealth_mode) M5.Speaker.tone(DETECT_FREQ, DETECT_BEEP_DURATION);
        delay(DETECT_BEEP_DURATION);
        if (!stealth_mode) M5.Display.invertDisplay(false);
    }
}

// ============================================================================
// SETUP
// ============================================================================

void setup() {
    auto cfg = M5.config();
    M5.begin(cfg);

    Serial.begin(115200);
    SerialGPS.begin(GPS_BAUD, SERIAL_8N1, RX_PIN, TX_PIN);
    setCpuFrequencyMhz(240);
    dataMutex = xSemaphoreCreateMutex();

    M5.Display.setRotation(1);          // landscape, USB/Grove on the left
    M5.Display.setBrightness(80);
    canvas.setColorDepth(8);
    canvas.createSprite(SCR_W, SCR_H);
    canvas.setTextSize(1);
    canvas.setTextColor(TFT_WHITE, TFT_BLACK);

    M5.Speaker.begin();
    M5.Speaker.setVolume(200);

    M5.BtnA.setHoldThresh(1000);        // matches original 1s long-press threshold

    // Initialize LittleFS (replaces SD — M5StickC PLUS2 has no SD slot)
    if (!LittleFS.begin(true)) {        // true = format on first use
        Serial.println(F("LittleFS mount failed"));
        storage_available = false;
    } else {
        storage_available = true;
        load_session_from_flash();

        int file_num = 1; char file_name[32];
        while (file_num <= 999) {
            sprintf(file_name, "/FlockLog_%03d.csv", file_num);
            if (!LittleFS.exists(file_name)) { current_log_file = String(file_name); break; }
            file_num++;
        }
        File file = LittleFS.open(current_log_file.c_str(), FILE_WRITE);
        if (file) {
            file.println("Uptime_ms,Date_Time,Channel,Capture_Type,Protocol,RSSI,MAC_Address,Device_Name,TX_Power,Detection_Method,Confidence,Confidence_Label,Extra_Data,Latitude,Longitude,Speed_MPH,Heading_Deg,Altitude_M");
            file.close();
        }
        Serial.print(F("Logging to (LittleFS): ")); Serial.println(current_log_file);
    }

    session_start_time = millis(); refresh_screen_layout();

    // WiFi promiscuous mode with MGMT-only filter
    WiFi.mode(WIFI_STA); WiFi.disconnect(); esp_wifi_set_ps(WIFI_PS_NONE);
    wifi_promiscuous_filter_t filt;
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
    esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);

    // BLE
    NimBLEDevice::init(""); NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    pBLEScan = NimBLEDevice::getScan();
    pBLEScan->setScanCallbacks(new AdvertisedDeviceCallbacks(), false);
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(97); pBLEScan->setWindow(97);

    boot_beep_sequence();
    last_channel_hop = millis(); last_log_flush = millis(); last_persist_save = millis();

    xTaskCreatePinnedToCore(ScannerLoopTask, "ScannerTask", 8192, NULL, 1, &ScannerTaskHandle, 0);

    Serial.println(F("=== Flock Detector v3.0 (M5StickC PLUS2) ==="));
    Serial.print(F("MAC:")); Serial.print(NUM_MAC_PREFIXES);
    Serial.print(F(" SSID:")); Serial.print(NUM_SSID_PATTERNS);
    Serial.print(F(" BLE:")); Serial.print(NUM_NAME_PATTERNS);
    Serial.print(F(" Raven:")); Serial.println(NUM_RAVEN_UUIDS);
    Serial.print(F("Alarm threshold:")); Serial.print(CONFIDENCE_ALARM_THRESHOLD);
    Serial.print(F("% Redetect window:")); Serial.print(REDETECT_WINDOW_MS / 1000);
    Serial.println(F("s"));
}

// ============================================================================
// MAIN LOOP
// ============================================================================

#define NUM_SCREENS 7

void loop() {
    M5.update();

    while (SerialGPS.available() > 0) { gps.encode(SerialGPS.read()); yield(); }

    // Activity chart
    if (millis() - last_chart_update >= 1000) {
        last_chart_update = millis();
        xSemaphoreTake(dataMutex, portMAX_DELAY);
        long current_total = session_wifi + session_ble;
        xSemaphoreGive(dataMutex);
        int new_dets = current_total - last_total_dets;
        last_total_dets = current_total;
        for (int i = 0; i < CHART_BARS - 1; i++) activity_history[i] = activity_history[i + 1];
        activity_history[CHART_BARS - 1] = new_dets;
    }

    // Escalated alarm
    if (trigger_alarm_confidence > 0) {
        int conf = trigger_alarm_confidence;
        trigger_alarm_confidence = 0;
        play_escalated_alarm(conf);
    }

    // Button (front button BtnA): short press = cycle screens, hold 1s = stealth toggle
    if (M5.BtnA.wasHold()) {
        stealth_mode = !stealth_mode;
        if (stealth_mode) M5.Display.sleep();
        else { M5.Display.wakeup(); force_redraw = true; }
        button_hold_handled = true;
    }
    if (M5.BtnA.wasReleased()) {
        if (!button_hold_handled && !stealth_mode) {
            current_screen++; if (current_screen >= NUM_SCREENS) current_screen = 0;
            force_redraw = true;
        }
        button_hold_handled = false;
    }

    // Lifetime timer
    if (millis() - last_time_save >= 1000) { lifetime_seconds++; last_time_save = millis(); }

    // Session persistence to flash
    if (millis() - last_persist_save >= PERSIST_INTERVAL_MS) {
        save_session_to_flash();
    }

    // RSSI tracker expiry
    rssi_track_expire();

    // Log flush
    xSemaphoreTake(dataMutex, portMAX_DELAY);
    bool should_flush = (log_write_buffer.size() >= MAX_LOG_BUFFER ||
                         (millis() - last_log_flush > LOG_FLUSH_INTERVAL && !log_write_buffer.empty()));
    xSemaphoreGive(dataMutex);
    if (should_flush) flush_log_buffer();

    // Screens
    if (!stealth_mode) {
        switch (current_screen) {
            case 0: draw_scanner_screen(); break;
            case 1: draw_stats_screen(); break;
            case 2: draw_last_capture_screen(); break;
            case 3: draw_live_log_screen(); break;
            case 4: draw_gps_screen(); break;
            case 5: draw_chart_screen(); break;
            case 6: draw_proximity_screen(); break;
        }
    }

    vTaskDelay(10 / portTICK_PERIOD_MS);
}
