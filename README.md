# Flock Detector CYD

A passive WiFi-based Flock Safety camera detector built for the **ESP32-2432S028R** (Cheap Yellow Display / CYD) board. Sniffs 2.4GHz management and data frames for known Flock Safety MAC OUI prefixes without transmitting — completely passive reconnaissance.

## Credits

This project is a CYD port inspired by and based on the original **[Flock You](https://github.com/colonelpanichacks/flock-you)** project by **[colonelpanichacks](https://github.com/colonelpanichacks)**. The OUI signature list, detection methodology, and core concept all originate from that project. Full credit to the original creator for the research identifying Flock Safety camera MAC prefixes and building the first detection firmware.

## How It Works

Flock Safety cameras use WiFi-enabled ESP32 modules to communicate. Each manufacturer assigns a unique OUI (Organizationally Unique Identifier) as the first 3 bytes of every MAC address. This firmware puts the ESP32 into promiscuous mode and passively listens for WiFi packets whose source or destination MAC matches one of the 31 known Flock Safety OUI prefixes.

### Detection Methods

| Method | Description | Confidence |
|--------|-------------|------------|
| `WILD_PROBE` | Wildcard probe request from a Flock OUI — the camera is actively searching for networks | Highest |
| `OUI_TX` | Transmitter MAC (addr2) matches a Flock OUI | High |
| `OUI_RX` | Receiver MAC (addr1) matches a Flock OUI — unicast frame to a Flock device | Medium |

### Channel Hopping

The detector cycles through WiFi channels **1, 6, and 11** (the three non-overlapping 2.4GHz channels) with a 350ms dwell time per channel, ensuring comprehensive coverage of all standard WiFi traffic.

## Hardware

### ESP32-2432S028R (CYD) Specs
- **MCU:** ESP32-D0WD-V3 (dual-core 240MHz)
- **Display:** 3.5" ILI9488 TFT, 320x480 pixels
- **Interface:** SPI (MOSI:13, SCLK:14, CS:15, DC:2)
- **Touch:** Resistive (CS:33)
- **RGB LED:** R:4, G:16, B:17 (active low)
- **Speaker:** Pin 26 (PWM tone output)
- **Backlight:** Pin 21
- **USB:** USB-C (CH340 serial)

## UI Screens

### Boot Screen
Displays "Flock You" title crediting the original project, "Flock Camera Detector" subtitle, version info, OUI signature count, and an animated progress bar.

### Scanning Screen
- Green header bar with "FLOCK DETECTOR" title
- Animated "SCANNING..." text with cycling dots
- Three channel indicator boxes (CH 1, CH 6, CH 11) highlighting the active channel
- Live packet counter and detection counter
- Network info (passive mode, 2.4GHz, 802.11, 31 OUI signatures)
- Uptime display

### Alert Screen
Triggered on new camera detection:
- Red flashing border for 1 second, then solid display for 4 seconds
- "FLOCK CAMERA DETECTED" banner
- Full details: MAC address, signal strength (dBm), channel, frequency, detection method, hit count, status, OUI prefix
- Audio alert tone (800-2000Hz sweep)
- RGB LED turns red

### Camera List Screen
- Shows all detected cameras with MAC address, RSSI, channel, hit count, and detection method
- Green/red status dots for active/stale cameras
- Displays for 5 seconds before returning to scan mode

## LED Indicators

| State | LED Color | Behavior |
|-------|-----------|----------|
| Scanning | Green | Pulsing (sine wave breathing) |
| Detection | Red | Solid during alert |
| Boot | Green | Solid |

## 31 Flock Safety OUI Prefixes

```
70:C9:4E  3C:91:80  D8:F3:BC  80:30:49  B8:35:32
14:5A:FC  74:4C:A1  08:3A:88  9C:2F:9D  C0:35:32
94:08:53  E4:AA:EA  F4:6A:DD  F8:A2:D6  24:B2:B9
00:F4:8D  D0:39:57  E8:D0:FC  E0:4F:43  B8:1E:A4
70:08:94  58:8E:81  EC:1B:BD  3C:71:BF  58:00:E3
90:35:EA  5C:93:A2  64:6E:69  48:27:EA  A4:CF:12
82:6B:F2
```

## Building & Flashing

### Prerequisites
- [PlatformIO](https://platformio.org/) (CLI or IDE)
- USB-C cable
- ESP32-2432S028R board

### Flash
```bash
# Clone the repo
git clone https://github.com/LuxStatera/flock-detector-cyd.git
cd flock-detector-cyd

# Build and upload (adjust upload_port in platformio.ini for your system)
pio run -t upload

# Monitor serial output
pio device monitor -b 115200
```

### Configuration
All display driver settings are defined in `platformio.ini` via build flags — the TFT_eSPI `User_Setup.h` is intentionally blank. If you need to change pins or display settings, edit the `build_flags` section in `platformio.ini`.

## Serial Output

The device logs detection events over serial at 115200 baud:
```
[FLOCK DETECTOR] Booting...
[DISPLAY] w=320 h=480 (ILI9488)
[FLOCK DETECTOR] Scanning channels 1, 6, 11
[ALERT] 70:C9:4E:AB:CD:EF RSSI:-72 CH:6 OUI_TX
```

## Legal Disclaimer

This device is a **passive receiver only**. It does not transmit, deauthenticate, jam, or interfere with any wireless communications. It operates the same way any WiFi-enabled device does when scanning for available networks. Monitoring publicly broadcast WiFi management frames is generally legal, but laws vary by jurisdiction. Check your local laws before use. This project is for educational and research purposes.

## License

This project follows the same open-source spirit as the original [Flock You](https://github.com/colonelpanichacks/flock-you) project.
