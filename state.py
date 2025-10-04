import json, os

SETTINGS_FILE = "/dev/shm/pi_gpg_settings.json"

DEFAULTS = {
    "display_driver": "VirtualGPIO",
    "camera_source": "Desktop"  # or "ZeroCam"
}

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            try:
                data = json.load(f)
                for k,v in DEFAULTS.items():
                    if k not in data: data[k] = v
                return data
            except Exception:
                pass
    return DEFAULTS.copy()

def save_settings(s):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(s, f)
