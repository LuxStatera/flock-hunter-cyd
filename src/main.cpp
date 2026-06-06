#include <Arduino.h>
#include <SPI.h>
#include <SD.h>
#include <FS.h>
#include <TFT_eSPI.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"

TFT_eSPI tft = TFT_eSPI();

// Portrait: 320 wide x 480 tall with rotation 2
int SW = 320;
int SH = 480;

#define LED_R 4
#define LED_G 16
#define LED_B 17
#define SPEAKER_PIN 26
#define BACKLIGHT_PIN 21
#define SD_CS 5

#define BG    0x0000
#define GRN   0x07E0
#define DGRN  0x0320
#define DDGRN 0x0180
#define RED   0xF800
#define DRED  0x3800
#define GRAY  0x4A69

static const uint8_t FLOCK_OUIS[][3] = {
    {0x70,0xC9,0x4E},{0x3C,0x91,0x80},{0xD8,0xF3,0xBC},{0x80,0x30,0x49},
    {0xB8,0x35,0x32},{0x14,0x5A,0xFC},{0x74,0x4C,0xA1},{0x08,0x3A,0x88},
    {0x9C,0x2F,0x9D},{0xC0,0x35,0x32},{0x94,0x08,0x53},{0xE4,0xAA,0xEA},
    {0xF4,0x6A,0xDD},{0xF8,0xA2,0xD6},{0x24,0xB2,0xB9},{0x00,0xF4,0x8D},
    {0xD0,0x39,0x57},{0xE8,0xD0,0xFC},{0xE0,0x4F,0x43},{0xB8,0x1E,0xA4},
    {0x70,0x08,0x94},{0x58,0x8E,0x81},{0xEC,0x1B,0xBD},{0x3C,0x71,0xBF},
    {0x58,0x00,0xE3},{0x90,0x35,0xEA},{0x5C,0x93,0xA2},{0x64,0x6E,0x69},
    {0x48,0x27,0xEA},{0xA4,0xCF,0x12},{0x82,0x6B,0xF2},
    {0xB4,0x1E,0x52}  // registered Flock Safety OUI
};
static const int NUM_OUIS = 32;

static const uint8_t SCAN_CH[] = {1, 6, 11};
static int chIdx = 0;
static unsigned long lastHop = 0;

struct Det {
    uint8_t mac[6];
    int8_t rssi;
    uint8_t ch;
    char method[12];
    unsigned long first, last;
    uint16_t count;
    bool active;
};
#define MAX_DET 50
static Det dets[MAX_DET];
static int nDet = 0;
static volatile int totalPkt = 0;

struct Alert { uint8_t mac[6]; int8_t rssi; uint8_t ch, method; };
#define AQ_SZ 32
static volatile Alert aq[AQ_SZ];
static volatile int aqH = 0, aqT = 0;
static portMUX_TYPE aqMux = portMUX_INITIALIZER_UNLOCKED;

// ═══════════════════════════════════════════════════════════════════════════
// PCAP CAPTURE BUFFER
// ═══════════════════════════════════════════════════════════════════════════
#define PCAP_BUF_SIZE 8
#define PCAP_MAX_PKT  512
struct PcapPkt {
    uint8_t  data[PCAP_MAX_PKT];
    uint16_t len;
    unsigned long ts_ms;
};
static volatile PcapPkt pcapBuf[PCAP_BUF_SIZE];
static volatile int pcapH = 0, pcapT = 0;
static portMUX_TYPE pcapMux = portMUX_INITIALIZER_UNLOCKED;

// SD card state
static bool sdReady = false;
static fs::File pcapFile;
static char sessionPath[32];
static int pcapCount = 0;
static unsigned long lastFlush = 0;

enum State { ST_BOOT, ST_SCAN, ST_ALERT, ST_LIST };
static State st = ST_BOOT;
static unsigned long bootT = 0, alertT = 0, lastUI = 0, lastDot = 0;
static int alertIdx = -1, dots = 0;
static State prevSt = ST_BOOT;
static bool needFull = true;
static int prevDots = -1, prevChIdx = -1, prevPkt = -1, prevDet = -1;
static int prevFlash = -1;
static unsigned long listT = 0;

bool matchOui(const uint8_t* m) {
    if (m[0] & 0x02) return false;
    for (int i = 0; i < NUM_OUIS; i++)
        if (m[0]==FLOCK_OUIS[i][0] && m[1]==FLOCK_OUIS[i][1] && m[2]==FLOCK_OUIS[i][2])
            return true;
    return false;
}

void fmtMac(const uint8_t* m, char* b) {
    sprintf(b, "%02X:%02X:%02X:%02X:%02X:%02X", m[0],m[1],m[2],m[3],m[4],m[5]);
}

void setLED(bool r, bool g, bool b) {
    digitalWrite(LED_R, !r); digitalWrite(LED_G, !g); digitalWrite(LED_B, !b);
}

void playTone() {
    ledcAttachPin(SPEAKER_PIN, 0);
    for (int f = 800; f < 2000; f += 100) { ledcWriteTone(0, f); delay(30); }
    ledcWriteTone(0, 0);
    ledcDetachPin(SPEAKER_PIN);
}

// ═══════════════════════════════════════════════════════════════════════════
// SD CARD + PCAP
// ═══════════════════════════════════════════════════════════════════════════

static int findNextSession() {
    int maxNum = 0;
    fs::File root = SD.open("/flock");
    if (!root) return 1;
    fs::File f = root.openNextFile();
    while (f) {
        const char* name = f.name();
        // name looks like "session_001" or "/session_001"
        const char* p = strstr(name, "session_");
        if (p) {
            int n = atoi(p + 8);
            if (n > maxNum) maxNum = n;
        }
        f = root.openNextFile();
    }
    return maxNum + 1;
}

static void writePcapHeader(fs::File& f) {
    // PCAP global header — LINKTYPE_IEEE802_11 (105)
    uint32_t magic = 0xA1B2C3D4;
    uint16_t ver_major = 2, ver_minor = 4;
    int32_t  thiszone = 0;
    uint32_t sigfigs = 0, snaplen = PCAP_MAX_PKT, network = 105;
    f.write((uint8_t*)&magic, 4);
    f.write((uint8_t*)&ver_major, 2);
    f.write((uint8_t*)&ver_minor, 2);
    f.write((uint8_t*)&thiszone, 4);
    f.write((uint8_t*)&sigfigs, 4);
    f.write((uint8_t*)&snaplen, 4);
    f.write((uint8_t*)&network, 4);
    f.flush();
}

static void writePcapPacket(fs::File& f, const uint8_t* data, uint16_t len, unsigned long ts_ms) {
    uint32_t ts_sec = ts_ms / 1000;
    uint32_t ts_usec = (ts_ms % 1000) * 1000;
    uint32_t caplen = len;
    uint32_t origlen = len;
    f.write((uint8_t*)&ts_sec, 4);
    f.write((uint8_t*)&ts_usec, 4);
    f.write((uint8_t*)&caplen, 4);
    f.write((uint8_t*)&origlen, 4);
    f.write(data, len);
}

static bool initSD() {
    // SD card uses VSPI (default SPI) — different bus from display (HSPI)
    if (!SD.begin(SD_CS)) {
        Serial.println("[SD] Card init failed");
        return false;
    }
    Serial.printf("[SD] Card ready — %lluMB\n", SD.cardSize() / (1024*1024));

    // Create /flock if needed
    if (!SD.exists("/flock")) SD.mkdir("/flock");

    // Find next session number
    int sessNum = findNextSession();
    sprintf(sessionPath, "/flock/session_%03d", sessNum);

    // Create session directories
    SD.mkdir(sessionPath);
    char pcapDir[48], csvDir[48];
    sprintf(pcapDir, "%s/pcap", sessionPath);
    sprintf(csvDir, "%s/csv", sessionPath);
    SD.mkdir(pcapDir);
    SD.mkdir(csvDir);

    // Open pcap file and write header
    char pcapPath[64];
    sprintf(pcapPath, "%s/pcap/capture.pcap", sessionPath);
    pcapFile = SD.open(pcapPath, FILE_WRITE);
    if (!pcapFile) {
        Serial.println("[SD] Failed to create pcap file");
        return false;
    }
    writePcapHeader(pcapFile);

    Serial.printf("[SD] Session: %s\n", sessionPath);
    return true;
}

static void drainPcapBuffer() {
    if (!sdReady || !pcapFile) return;

    while (pcapT != pcapH) {
        portENTER_CRITICAL(&pcapMux);
        PcapPkt pkt;
        memcpy(&pkt, (void*)&pcapBuf[pcapT], sizeof(PcapPkt));
        pcapT = (pcapT + 1) % PCAP_BUF_SIZE;
        portEXIT_CRITICAL(&pcapMux);

        writePcapPacket(pcapFile, pkt.data, pkt.len, pkt.ts_ms);
        pcapCount++;
    }

    // Flush every 5 seconds to avoid data loss
    if (millis() - lastFlush > 5000) {
        pcapFile.flush();
        lastFlush = millis();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SNIFFER
// ═══════════════════════════════════════════════════════════════════════════

void IRAM_ATTR sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    const wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;
    const uint8_t* d = p->payload;
    int len = p->rx_ctrl.sig_len;
    if (len < 24 || p->rx_ctrl.rssi < -95) return;
    totalPkt++;

    uint8_t ft = d[0] & 0x0C, fs = (d[0] & 0xF0) >> 4;
    const uint8_t* a1 = d+4, *a2 = d+10;
    uint8_t am = 255;

    if (ft==0x00 && fs==4 && matchOui(a2)) {
        am = (len>=26 && d[25]==0) ? 0 : 1;
    } else if (matchOui(a2)) { am = 1; }
    else if (!(a1[0]&0x01) && matchOui(a1)) { am = 2; }
    if (am == 255) return;

    const uint8_t* mac = (am==2) ? a1 : a2;

    // Enqueue alert
    portENTER_CRITICAL(&aqMux);
    int nx = (aqH+1) % AQ_SZ;
    if (nx != aqT) {
        memcpy((void*)aq[aqH].mac, mac, 6);
        aq[aqH].rssi = p->rx_ctrl.rssi;
        aq[aqH].ch = p->rx_ctrl.channel;
        aq[aqH].method = am;
        aqH = nx;
    }
    portEXIT_CRITICAL(&aqMux);

    // Enqueue raw packet for PCAP
    portENTER_CRITICAL(&pcapMux);
    int pnx = (pcapH + 1) % PCAP_BUF_SIZE;
    if (pnx != pcapT) {
        uint16_t caplen = (len > PCAP_MAX_PKT) ? PCAP_MAX_PKT : len;
        memcpy((void*)pcapBuf[pcapH].data, d, caplen);
        pcapBuf[pcapH].len = caplen;
        pcapBuf[pcapH].ts_ms = millis();
        pcapH = pnx;
    }
    portEXIT_CRITICAL(&pcapMux);
}

void processAlerts() {
    while (aqT != aqH) {
        portENTER_CRITICAL(&aqMux);
        Alert e; memcpy(&e, (void*)&aq[aqT], sizeof(Alert));
        aqT = (aqT+1) % AQ_SZ;
        portEXIT_CRITICAL(&aqMux);

        int f = -1;
        for (int i = 0; i < nDet; i++)
            if (memcmp(dets[i].mac, e.mac, 6)==0) { f=i; break; }

        if (f >= 0) {
            dets[f].rssi = e.rssi; dets[f].ch = e.ch;
            dets[f].last = millis(); dets[f].count++; dets[f].active = true;
        } else if (nDet < MAX_DET) {
            Det& d = dets[nDet];
            memcpy(d.mac, e.mac, 6); d.rssi = e.rssi; d.ch = e.ch;
            d.first = d.last = millis(); d.count = 1; d.active = true;
            const char* ms[] = {"WILD_PROBE","OUI_TX","OUI_RX"};
            strncpy(d.method, ms[e.method], 11); d.method[11] = 0;
            alertIdx = nDet; alertT = millis();
            st = ST_ALERT; needFull = true;
            playTone(); nDet++;
        }
    }
    for (int i = 0; i < nDet; i++)
        if (millis() - dets[i].last > 30000) dets[i].active = false;
}

void drawCorners() {
}

// ═══════════════════════════════════════════════════════════════════════════
// BOOT SCREEN — 320x480 portrait
// ═══════════════════════════════════════════════════════════════════════════
void drawBoot() {
    if (needFull) {
        tft.fillScreen(BG);
        drawCorners();
        for (int y = 0; y < SH; y += 8)
            tft.drawFastHLine(0, y, SW, DDGRN);

        tft.setTextDatum(MC_DATUM);
        tft.setTextColor(GRN, BG);
        tft.setTextFont(4); tft.setTextSize(2);
        tft.drawString("Flock Hunter", SW/2, 80);
        tft.setTextSize(1);

        tft.drawFastHLine(40, 120, SW-80, GRN);
        tft.drawFastHLine(60, 122, SW-120, DGRN);

        tft.setTextFont(2); tft.setTextColor(DGRN, BG);
        tft.drawString("Based on Flock You", SW/2, 145);

        tft.setTextFont(2); tft.setTextColor(DDGRN, BG);
        tft.drawString("ESP32-CYD // v2.0", SW/2, 185);
        tft.drawString("32 OUI SIGNATURES", SW/2, 205);

        tft.drawRect(40, 240, SW-80, 16, DGRN);

        tft.setTextFont(2); tft.setTextColor(DGRN, BG);
        tft.drawString("INITIALIZING", SW/2, 270);
        tft.setTextDatum(TL_DATUM);
        needFull = false;
    }
    unsigned long el = millis() - bootT;
    int barW = SW - 82;
    int prog = min((int)(el * barW / 3000), barW);
    if (prog > 0) tft.fillRect(41, 241, prog, 14, GRN);
}

// ═══════════════════════════════════════════════════════════════════════════
// SCANNING SCREEN — 320x480 portrait
// ═══════════════════════════════════════════════════════════════════════════
void drawScan() {
    if (needFull) {
        tft.fillScreen(BG);
        drawCorners();

        // Header bar
        tft.fillRect(0, 0, SW, 30, GRN);
        tft.setTextDatum(MC_DATUM);
        tft.setTextColor(BG, GRN);
        tft.setTextFont(4);
        tft.drawString("FLOCK HUNTER", SW/2, 16);
        tft.setTextDatum(TL_DATUM);

        // Divider after channels
        tft.drawFastHLine(8, 120, SW-16, DDGRN);

        // Packets label
        tft.setTextFont(2); tft.setTextColor(DGRN, BG);
        tft.drawString("PACKETS", 15, 130);

        // Detections label
        tft.drawString("DETECTIONS", SW/2 + 10, 130);

        // Divider
        tft.drawFastHLine(8, 195, SW-16, DDGRN);

        // Bottom info
        tft.setTextFont(2); tft.setTextColor(DDGRN, BG);
        tft.drawString("PASSIVE  2.4GHz  802.11", 15, 205);
        tft.drawString("32 OUI SIGNATURES LOADED", 15, 225);

        // SD + PCAP status — bottom left
        tft.setTextFont(2);
        if (sdReady) {
            tft.setTextColor(DGRN, BG);
            tft.drawString("SD:OK  PCAP:REC", 15, SH - 20);
        } else {
            tft.setTextColor(DRED, BG);
            tft.drawString("SD:NONE", 15, SH - 20);
        }

        prevDots = -1; prevChIdx = -1; prevPkt = -1; prevDet = -1;
        needFull = false;
    }

    // "SCANNING..." centered
    if (dots != prevDots) {
        tft.setTextColor(GRN, BG);
        tft.setTextFont(4); tft.setTextSize(1);
        tft.setTextDatum(TL_DATUM);
        int tx = 80;
        int ty = 38;
        tft.drawString("SCANNING", tx, ty);
        int dotX = tx + tft.textWidth("SCANNING");
        tft.fillRect(dotX, ty, 50, 26, BG);
        char ds[4] = "";
        for (int i = 0; i < dots; i++) strcat(ds, ".");
        tft.drawString(ds, dotX, ty);
        prevDots = dots;
    }

    // 3 channel boxes
    if (chIdx != prevChIdx) {
        int bw = 85, bh = 30;
        int gap = (SW - 3*bw) / 4;
        for (int i = 0; i < 3; i++) {
            int x = gap + i*(bw+gap);
            int y = 78;
            bool act = (i == chIdx);
            tft.fillRoundRect(x, y, bw, bh, 6, act ? GRN : BG);
            if (!act) tft.drawRoundRect(x, y, bw, bh, 6, DGRN);
            tft.setTextColor(act ? BG : DGRN, act ? GRN : BG);
            tft.setTextFont(2);
            tft.setTextDatum(MC_DATUM);
            char c[8]; sprintf(c, "CH %d", SCAN_CH[i]);
            tft.drawString(c, x+bw/2, y+bh/2);
            tft.setTextDatum(TL_DATUM);
        }
        prevChIdx = chIdx;
    }

    // Packet count
    if (totalPkt != prevPkt) {
        tft.setTextFont(4);
        tft.setTextColor(GRN, BG);
        char b[16]; sprintf(b, "%-8d", totalPkt);
        tft.drawString(b, 15, 150);
        prevPkt = totalPkt;
    }

    // Detection count
    if (nDet != prevDet) {
        tft.setTextFont(4);
        tft.setTextColor(nDet > 0 ? RED : GRN, BG);
        char b[16]; sprintf(b, "%-6d", nDet);
        tft.drawString(b, SW/2 + 10, 150);
        prevDet = nDet;
    }

    // Uptime — bottom right
    unsigned long sec = millis()/1000;
    char ut[16]; sprintf(ut, "%02lu:%02lu  ", sec/60, sec%60);
    tft.setTextFont(2); tft.setTextColor(DDGRN, BG);
    tft.drawString(ut, SW - 70, SH - 20);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALERT SCREEN — 320x480 portrait
// ═══════════════════════════════════════════════════════════════════════════
void drawAlert(int idx) {
    if (idx < 0 || idx >= nDet) return;
    Det& d = dets[idx];
    unsigned long el = millis() - alertT;
    int flashState = (el < 1000) ? (int)((el / 150) % 2) : 2;

    if (flashState == prevFlash && !needFull) return;
    prevFlash = flashState;

    uint16_t bg = (flashState == 1) ? tft.color565(30,0,0) : BG;
    tft.fillScreen(bg);

    uint16_t bc = (flashState < 2) ? RED : DRED;
    for (int i = 0; i < 3; i++)
        tft.drawRect(i, i, SW-2*i, SH-2*i, bc);

    // Banner
    uint16_t hbg = (flashState == 0) ? RED : DRED;
    tft.fillRect(4, 4, SW-8, 26, hbg);
    tft.setTextDatum(MC_DATUM);
    tft.setTextColor((flashState == 0) ? BG : RED, hbg);
    tft.setTextFont(2);
    tft.drawString("FLOCK CAMERA DETECTED", SW/2, 17);
    tft.setTextDatum(TL_DATUM);
    needFull = false;

    int y = 40;

    // MAC Address
    tft.setTextFont(2); tft.setTextColor(DGRN, bg);
    tft.drawString("MAC ADDRESS", 12, y);
    char mb[18]; fmtMac(d.mac, mb);
    tft.setTextColor(GRN, bg);
    tft.drawString(mb, 140, y);

    y += 22;
    tft.drawFastHLine(8, y, SW-16, DRED);
    y += 8;

    // Signal
    tft.setTextFont(2); tft.setTextColor(DGRN, bg);
    tft.drawString("SIGNAL", 12, y);
    tft.setTextColor(GRN, bg);
    char rb[12]; sprintf(rb, "%d dBm", d.rssi);
    tft.drawString(rb, 140, y);

    y += 20;

    // Channel
    tft.setTextColor(DGRN, bg);
    tft.drawString("CHANNEL", 12, y);
    tft.setTextColor(GRN, bg);
    char cf[8]; sprintf(cf, "%d", d.ch);
    tft.drawString(cf, 140, y);

    y += 20;

    // Freq
    tft.setTextColor(DGRN, bg);
    tft.drawString("FREQUENCY", 12, y);
    tft.setTextColor(GRN, bg);
    char fb[16]; sprintf(fb, "%d MHz", 2407+5*d.ch);
    tft.drawString(fb, 140, y);

    y += 22;
    tft.drawFastHLine(8, y, SW-16, DRED);
    y += 8;

    // Method
    tft.setTextColor(DGRN, bg);
    tft.drawString("METHOD", 12, y);
    tft.setTextColor(GRN, bg);
    tft.drawString(d.method, 140, y);

    y += 20;

    // Hits
    tft.setTextColor(DGRN, bg);
    tft.drawString("HITS", 12, y);
    tft.setTextColor(GRN, bg);
    char hb[8]; sprintf(hb, "%d", d.count);
    tft.drawString(hb, 140, y);

    y += 20;

    // Status
    tft.setTextColor(DGRN, bg);
    tft.drawString("STATUS", 12, y);
    tft.setTextColor(d.active ? GRN : RED, bg);
    tft.drawString(d.active ? "LIVE" : "STALE", 140, y);

    y += 22;
    tft.drawFastHLine(8, y, SW-16, DRED);
    y += 8;

    // OUI
    tft.setTextColor(DGRN, bg);
    tft.drawString("OUI PREFIX", 12, y);
    char oui[12]; sprintf(oui, "%02X:%02X:%02X", d.mac[0], d.mac[1], d.mac[2]);
    tft.setTextColor(GRN, bg);
    tft.drawString(oui, 140, y);
}

// ═══════════════════════════════════════════════════════════════════════════
// LIST SCREEN — 320x480 portrait
// ═══════════════════════════════════════════════════════════════════════════
void drawList() {
    if (needFull) {
        tft.fillScreen(BG);

        // Header
        tft.fillRect(0, 0, SW, 30, GRN);
        tft.setTextDatum(MC_DATUM);
        tft.setTextColor(BG, GRN);
        tft.setTextFont(4);
        char hdr[24]; sprintf(hdr, "FLOCK CAMERAS: %d", nDet);
        tft.drawString(hdr, SW/2, 16);
        tft.setTextDatum(TL_DATUM);

        if (nDet == 0) {
            tft.setTextFont(4); tft.setTextColor(DGRN, BG);
            tft.setTextDatum(MC_DATUM);
            tft.drawString("NO CAMERAS", SW/2, SH/2 - 15);
            tft.drawString("DETECTED", SW/2, SH/2 + 15);
            tft.setTextDatum(TL_DATUM);
            return;
        }

        int maxVis = 4;
        int show = min(nDet, maxVis);

        for (int r = 0; r < show; r++) {
            Det& d = dets[nDet - 1 - r];
            int y = 45 + r * 50;
            uint16_t fg = d.active ? GRN : GRAY;

            tft.fillCircle(10, y+8, 4, d.active ? GRN : RED);

            char mb[18]; fmtMac(d.mac, mb);
            tft.setTextFont(2); tft.setTextColor(fg, BG);
            tft.drawString(mb, 22, y);

            tft.setTextFont(2); tft.setTextColor(DGRN, BG);
            char info[48];
            sprintf(info, "%ddBm  CH%d  x%d  %s", d.rssi, d.ch, d.count, d.method);
            tft.drawString(info, 22, y + 22);

            tft.drawFastHLine(8, y + 42, SW-16, DDGRN);
        }
        needFull = false;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SETUP
// ═══════════════════════════════════════════════════════════════════════════
void setup() {
    Serial.begin(115200);
    Serial.println("\n[FLOCK HUNTER] Booting...");

    pinMode(LED_R, OUTPUT); pinMode(LED_G, OUTPUT); pinMode(LED_B, OUTPUT);
    setLED(false, true, false);

    pinMode(BACKLIGHT_PIN, OUTPUT);
    digitalWrite(BACKLIGHT_PIN, LOW);

    tft.init();
    tft.setRotation(2);
    tft.invertDisplay(true);
    tft.fillScreen(BG);
    digitalWrite(BACKLIGHT_PIN, HIGH);

    SW = tft.width();
    SH = tft.height();
    Serial.printf("[DISPLAY] w=%d h=%d (ILI9488)\n", SW, SH);

    // Draw boot screen
    bootT = millis();
    st = ST_BOOT;
    needFull = true;
    drawBoot();

    // Init SD card
    sdReady = initSD();

    // WiFi init
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(sniffer);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(SCAN_CH[0], WIFI_SECOND_CHAN_NONE);

    // Animate progress bar for 3 seconds
    int barW = SW - 82;
    while (millis() - bootT < 3000) {
        int prog = (millis() - bootT) * barW / 3000;
        tft.fillRect(41, 241, prog, 14, GRN);
        delay(30);
    }
    tft.fillRect(41, 241, barW, 14, GRN);

    st = ST_SCAN;
    needFull = true;
    Serial.println("[FLOCK HUNTER] Scanning channels 1, 6, 11");
}

// ═══════════════════════════════════════════════════════════════════════════
// LOOP
// ═══════════════════════════════════════════════════════════════════════════
void loop() {
    unsigned long now = millis();

    if (now - lastHop >= 150) {
        lastHop = now;
        chIdx = (chIdx + 1) % 3;
        esp_wifi_set_channel(SCAN_CH[chIdx], WIFI_SECOND_CHAN_NONE);
    }

    processAlerts();
    drainPcapBuffer();

    if (now - lastDot >= 500) { lastDot = now; dots = (dots+1) % 4; }
    if (st != prevSt) { needFull = true; prevSt = st; }

    switch (st) {
        case ST_BOOT:
            st = ST_SCAN; needFull = true;
            break;

        case ST_ALERT:
            setLED(true, false, false);
            if (now - alertT < 5000) {
                if (now - lastUI >= 200) { lastUI = now; drawAlert(alertIdx); }
            } else {
                st = nDet > 0 ? ST_LIST : ST_SCAN;
                listT = now;
                setLED(false,true,false); needFull = true;
            }
            break;

        case ST_SCAN:
            if (now - lastUI >= 200) { lastUI = now; drawScan(); }
            break;

        case ST_LIST:
            if (now - lastUI >= 500) { lastUI = now; drawList(); }
            if (now - listT > 5000) {
                st = ST_SCAN; needFull = true;
            }
            break;
    }

    static int lastRep = 0;
    if (nDet > lastRep) {
        for (int i = lastRep; i < nDet; i++) {
            char mb[18]; fmtMac(dets[i].mac, mb);
            Serial.printf("[ALERT] %s RSSI:%d CH:%d %s\n",
                          mb, dets[i].rssi, dets[i].ch, dets[i].method);
        }
        lastRep = nDet;
    }

    if (st == ST_SCAN) {
        int b = (sin(now / 500.0) + 1.0) * 127;
        analogWrite(LED_G, 255-b);
    }

    delay(1);
}
