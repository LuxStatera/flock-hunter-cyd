# Flock Detector CYD

A passive WiFi-based Flock Safety camera detector built for the **ESP32-3248S035** (Cheap Yellow Display / CYD) board. Sniffs 2.4GHz management and data frames for known Flock Safety MAC OUI prefixes without transmitting — completely passive reconnaissance.

![Flock detector devices](images/devices.jpg)

![Boot screen](images/boot.jpg)

## Credits

This project is a CYD port inspired by and based on the original **[Flock You](https://github.com/colonelpanichacks/flock-you)** project by **[colonelpanichacks](https://github.com/colonelpanichacks)**. The OUI signature list, detection methodology, and core concept all originate from that project. Full credit to the original creator for the research identifying Flock Safety camera MAC prefixes and building the first detection firmware.

This firmware and this documentation were all written by Claude.

## How It Works

Flock Safety cameras periodically emit WiFi probe requests and other management frames as part of their normal operation. Each network device's MAC address begins with a 3-byte OUI (Organizationally Unique Identifier) assigned to the hardware manufacturer. Researchers identified 31 OUI prefixes consistently associated with Flock Safety camera deployments through field testing. This firmware puts the ESP32 into promiscuous mode and passively listens for WiFi packets whose source or destination MAC matches one of those 31 known OUI prefixes.

### Detection Methods

| Method | Description | Confidence |
|--------|-------------|------------|
| `WILD_PROBE` | Wildcard probe request from a Flock OUI — the camera is actively searching for networks | Highest |
| `OUI_TX` | Transmitter MAC (addr2) matches a Flock OUI | High |
| `OUI_RX` | Receiver MAC (addr1) matches a Flock OUI — unicast frame to a Flock device | Medium |

### Channel Hopping

The detector cycles through WiFi channels **1, 6, and 11** (the three non-overlapping 2.4GHz channels) with a 350ms dwell time per channel, ensuring comprehensive coverage of all standard WiFi traffic.

## Hardware

### ESP32-3248S035 (CYD) Specs
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
- Audio alert tone (800–1900Hz sweep)
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

### What You Need
- **ESP32-3248S035** board (the 3.5" CYD with ILI9488 display) — available on AliExpress/Amazon for ~$10-15
- **USB-C cable** (data cable, not charge-only)
- A computer (Windows, macOS, or Linux)

### Step 1: Install PlatformIO

**Option A — VS Code (recommended for beginners):**
1. Install [VS Code](https://code.visualstudio.com/)
2. Open VS Code, go to Extensions (Ctrl+Shift+X / Cmd+Shift+X)
3. Search for "PlatformIO IDE" and install it
4. Restart VS Code when prompted

**Option B — CLI only:**
```bash
pip install platformio
```

### Step 2: Download This Project
```bash
git clone https://github.com/LuxStatera/flock-detector-cyd.git
cd flock-detector-cyd
```
Or download the ZIP from GitHub and extract it.

### Step 3: Find Your Serial Port

Plug in the CYD via USB-C. Then find your port:

- **macOS:** `ls /dev/cu.usb*` (usually `/dev/cu.usbserial-XXXX`)
- **Windows:** Open Device Manager > Ports (COM & LPT) — look for CH340 (e.g. `COM3`)
- **Linux:** `ls /dev/ttyUSB*` (usually `/dev/ttyUSB0`)

> **Note:** If nothing shows up, you may need to install the [CH340 driver](https://sparks.gogo.co.nz/ch340.html) for your OS.

### Step 4: Update the Port in Config

Open `platformio.ini` and change the `upload_port` and `monitor_port` to match your port:
```ini
upload_port = /dev/cu.usbserial-110    ; <-- change this
monitor_port = /dev/cu.usbserial-110   ; <-- change this
```
On Windows it would look like:
```ini
upload_port = COM3
monitor_port = COM3
```

### Step 5: Flash the Firmware

**VS Code:** Open the project folder in VS Code, then click the arrow (Upload) button in the PlatformIO toolbar at the bottom.

**CLI:**
```bash
pio run -t upload
```

The first build takes a few minutes to download dependencies. Subsequent builds are faster. Once flashing completes, the device will reboot and start scanning automatically.

### Step 6: Monitor Serial Output (Optional)
```bash
pio device monitor -b 115200
```
This shows detection events and debug info in your terminal.

### Troubleshooting

| Problem | Solution |
|---------|----------|
| "Unable to verify flash chip connection" | Try a different USB cable (must be data, not charge-only). Reduce `upload_speed` to `115200` in platformio.ini |
| Port not found | Install the [CH340 driver](https://sparks.gogo.co.nz/ch340.html). Try a different USB port |
| Display is white/blank | The TFT_eSPI `User_Setup.h` in `.pio/libdeps/` must be blank — if it has pin definitions, clear the file and rebuild |
| Colors are inverted | The firmware already handles this with `tft.invertDisplay(true)`. If colors are wrong, your board may have a different panel variant |
| Display is rotated | Change `tft.setRotation(2)` in `src/main.cpp` — try values 0-3 to find the correct orientation for your board |

### Configuration Notes
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
