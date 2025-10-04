# main.py
"""
ChatGPG / Pi-GPG
================

Ephemeral air-gapped GPG signer for Raspberry Pi Zero or desktop emulator.

Hardware:
 - Pi Zero 1.3
 - Waveshare 1.3" LCD 240x240 (ST7789)
 - PiCamera (ZeroCam)
 
Features:
 - Ephemeral GPG keyring (RAM-only)
 - QR scan to import key / decrypt / sign / verify
 - Menu navigation with Back
 - Display + Camera settings (switch between real/virtual)

Author: Razvan ⚡
"""

import os
from time import sleep
from gpg_ephemeral import EphemeralGPG
from menu import main_menu


# -------------------------------------------------------------
# SETTINGS (can be persisted later in a JSON if you want)
# -------------------------------------------------------------
DEFAULT_SETTINGS = {
    "display_type": "virtual",  # "st7789" for pi zero camera
    "camera_type": "webcam",    # "picam" for pi zero
}


# -------------------------------------------------------------
# DISPLAY MANAGER LOADER
# -------------------------------------------------------------
def get_display(settings):
    """
    Returns a display interface object with:
      .clear()
      .text(msg)
    Works with ST7789 (Pi) or virtual console display (desktop).
    """
    disp_type = settings.get("display_type", "st7789")
    if disp_type == "virtual":
        from display import VirtualDisplay
        return VirtualDisplay()
    else:
        from display import ST7789Display
        return ST7789Display()


# -------------------------------------------------------------
# INITIALIZATION
# -------------------------------------------------------------
def init():
    print("🔐 Initializing ChatGPG environment...")

    # 1. Ensure temporary GPG home (RAM)
    gpg = EphemeralGPG()

    # 2. Load settings
    settings = DEFAULT_SETTINGS.copy()

    # 3. Get display
    display = get_display(settings)

    display.clear()
    display.text("ChatGPG starting...")
    sleep(0.5)

    return display, gpg, settings


# -------------------------------------------------------------
# MAIN ENTRY POINT
# -------------------------------------------------------------
if __name__ == "__main__":
    display, gpg, settings = init()

    try:
        main_menu(display, gpg, settings)
    except KeyboardInterrupt:
        display.text("🧹 Exiting & wiping RAM...")
        try:
            gpg._cleanup()
        except Exception as e:
            print(f"[WARN] Cleanup error: {e}")
        sleep(1)
        os._exit(0)