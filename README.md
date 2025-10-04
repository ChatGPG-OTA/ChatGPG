# ChatGPG — Ephemeral GPG Signer for Raspberry Pi Zero

ChatGPG is an **air-gapped**, SeedSigner-inspired application for:
- Managing **ephemeral GPG keys** (stored only in RAM)
- Offline message signing
- Transferring data through **QR codes** (chunked / animated)
- Running on **Raspberry Pi Zero 1.3** + **Waveshare 1.3” 240×240 LCD** + **ZeroCam**
- Running and testing on **desktop** using webcam and virtual display emulator

---

## Project structure

```
pi-gpg/
├── camera_qr.py          # QR scanning: ZeroCam / Desktop webcam
├── display.py            # Display driver: ST7789 or VirtualGPIO
├── gpg_ephemeral.py      # Ephemeral in-memory GPG logic
├── menu.py               # Menu system: Scan / Keys / Settings
├── main.py               # Entry point — initializes system and starts main_menu()
├── qr_utils.py           # QR code generation and animation
├── state.py              # Persistent settings (display / camera)
├── requirements.txt      # Dependencies for Raspberry Pi
├── requirements-lite.txt # Dependencies for desktop emulator
└── README.md
```

---

## 1. Installation (with virtual environment)

### Create and activate a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Upgrade pip
```bash
pip install --upgrade pip
```

---

## 2. Desktop installation (emulator + webcam)

### System dependencies
```bash
sudo apt update
sudo apt install -y libzbar0
```

### Python packages
```bash
pip install -r requirements-lite.txt
```

---

## 3. Raspberry Pi Zero installation (real hardware)

### System dependencies
```bash
sudo apt update
sudo apt install -y libcap-dev libzbar0 python3-picamera2 python3-zbar
```

### Python packages
```bash
pip install -r requirements.txt
```

---

## 4. Initial configuration

On first run, the app creates a temporary settings file:
```
/dev/shm/pi_gpg_settings.json
```

Default values:
```json
{
  "display_driver": "VirtualGPIO",
  "camera_source": "Desktop"
}
```

You can later change these from the `Settings` menu.

---

## 5. Running the app

```bash
source venv/bin/activate
python3 main.py
```

---

## 6. Navigation

### Main menu
```
== PI-GPG ==
[1] Scan
[2] Keys
[3] Settings
```

- **Scan** — reads a QR code (private key or GPG message)  
  - if it’s a private key → imports it into RAM  
  - if it’s a message → signs it and displays animated QR output  
- **Keys** — shows temporary key list / generate new key  
- **Settings** — select display driver and camera type (Desktop / ZeroCam)

---

## 7. Security

- Private keys are **ephemeral**, kept only in memory.  
- When you power off the Pi or close the app, **keys are destroyed**.  
- No private key material is ever written to disk or SD card.

---

## 8. Camera selection

- `Desktop` — uses **webcam** via OpenCV + pyzbar  
- `ZeroCam` — uses **Pi Zero camera** via Picamera2 + zbarlight  

You can switch between them in Settings:
```
Camera source: Desktop
→ New camera (Desktop/ZeroCam): ZeroCam
```

---

## 9. Quick desktop test

1. Run:
   ```bash
   python3 main.py
   ```
2. Select `[1] Scan`
3. Hold a QR code (any text) in front of your webcam  
4. The decoded data will appear in the terminal

---

## 10. Developer notes

To run on **real Pi hardware** with the ST7789 LCD:
- Enable SPI via `sudo raspi-config`
- Connect Waveshare 1.3” 240×240 LCD to SPI0 pins
- In **Settings**, choose:
  ```
  Display driver: ST7789
  Camera source: ZeroCam
  ```

ST7789 display logic is in `display.py` (you can adapt it using the `luma.lcd` library).

---

## 11. Clean up / reset

```bash
deactivate
rm -rf venv
rm /dev/shm/pi_gpg_settings.json
```

---

## 12. Minimum hardware requirements

| Component | Minimum recommended |
|------------|----------------------|
| Raspberry Pi | Zero 1.3 / Zero 2W |
| Display | Waveshare ST7789 1.3” (240×240) |
| Camera | Pi ZeroCam / Desktop webcam |
| OS | Raspberry Pi OS Bullseye+ |
| Python | 3.9+ |

---

## 13. License

MIT © 2025 — Educational demo project, provided without warranty.  
Use for real GPG signing at your own risk.
