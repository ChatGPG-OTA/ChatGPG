"""
ChatGPG Menu System
===================

Handles:
  - main_menu()
  - scan_menu()
  - keys_menu()
  - settings_menu()

Features:
  • Detects recipient role
  • Displays decrypted message before signing
  • Offers "Sign original ciphertext" to preserve recipients
  • Works on Pi LCD or virtual display
"""

from time import sleep
from textwrap import shorten


# ========== MAIN MENU ==========

def main_menu(display, gpg, settings):
    """Main menu navigation."""
    while True:
        display.clear()
        display.text("ChatGPG Main Menu")
        display.text("1) Scan Message / Key")
        display.text("2) Manage Keys")
        display.text("3) Settings")
        display.text("4) Exit")
        choice = input("Select: ").strip()

        if choice == "1":
            scan_menu(display, gpg, settings)
        elif choice == "2":
            keys_menu(display, gpg)
        elif choice == "3":
            settings_menu(display, settings)
        elif choice == "4":
            display.text("Bye! Wiping ephemeral memory...")
            try:
                gpg._cleanup()
            except Exception as e:
                print(f"[WARN] Cleanup failed: {e}")
            sleep(1)
            break
        else:
            display.text("Invalid option.")


# ========== SCAN MENU ==========

def scan_menu(display, gpg, settings):
    """Scan & process any QR (message or key)."""
    display.clear()
    display.text("📷 Scan QR...")
    sleep(0.5)

    # Select camera
    if settings["camera_type"] == "webcam":
        from camera_qr import scan_qr_chunks_continuous
        data = scan_qr_chunks_continuous()
    else:
        from camera_qr import scan_qr_from_zerocam_continuous
        data = scan_qr_from_zerocam_continuous()

    if not data:
        display.text("No QR detected.")
        sleep(1)
        return

    # --- Key import ---
    if "PRIVATE KEY BLOCK" in data:
        display.text("Importing private key...")
        gpg.import_private_key(data)
        display.text("Private key imported successfully.")
        sleep(1.5)
        return
    elif "PUBLIC KEY BLOCK" in data:
        display.text("Importing public key...")
        gpg.import_public_key(data)
        display.text("Public key imported successfully.")
        sleep(1.0)
        return

    # --- Message handling ---
    result = gpg.process_scanned(data, ask_passphrase_fn=input)
    print(result)
    display.clear()

    # Show decrypted/plain preview if any
    if result.get("plaintext"):
        preview = shorten(result["plaintext"].strip(), width=100, placeholder="…")
        display.text("Message Preview:")
        display.text(preview)
        print("\n--- FULL DECRYPTED MESSAGE ---\n")
        print(result["plaintext"])
        print("\n------------------------------\n")

    # ---- Decision tree ----

    # 1) Encrypted but cannot decrypt
    if result["type"] == "encrypted" and not result.get("plaintext"):
        display.text("Encrypted message (cannot decrypt).")
        if result.get("warning"):
            display.text(result["warning"])
        input("Press Enter to go back...")
        return

    # 2) Unsigned plaintext
    if result["type"] == "unsigned":
        display.text("Plain unsigned message.")
        input("Press Enter to go back...")
        return

    # Unsigned encrypted message (ready to sign if we are recipient)
    if result["type"] == "encrypted_unsigned":
        display.text("Decrypted unsigned message.")
        if result.get("is_recipient"):
            display.text("You are a recipient.")
            choice = input("Sign the ORIGINAL encrypted message to preserve recipients? (y/n): ").strip().lower()[:1]
            if choice == "y":
                # choose signing key
                keys = gpg.list_keys()
                if not keys:
                    display.text("No private keys available.")
                    input("Press Enter to go back...")
                    return
                for k in keys:
                    meta = gpg.keys[k]
                    label = f"{meta['name']} <{meta['email']}>"
                    display.text(f"- {k} | {label}")
                signer = input("Sign with key (last 8 chars): ").strip()

                try:
                    # IMPORTANT: sign the ORIGINAL encrypted blob to keep recipients
                    signed_blob = gpg.sign_ciphertext(data, signer, ask_passphrase_fn=input)
                except Exception as e:
                    display.text(f"Signing failed: {e}")
                    input("Press Enter to go back...")
                    return

                display.clear()
                display.text("Message signed successfully.")
                from qr_utils import qr_animate
                qr_animate(display, signed_blob)
                display.text("Signed QR ready for scanning.")
                input("Press Enter to go back...")
                return
            else:
                # user said no (or empty) → just return to menu without extra pause
                return
        else:
            display.text("You are not a recipient for this message.")
            input("Press Enter to go back...")
            return

    # 4) Signed (clearsigned) or encrypted_signed
    if result["type"] in ("signed", "signed_ciphertext", "encrypted_signed", "clearsigned"):
        display.text("Signed message detected.")
        if result.get("signer_fpr"):
            display.text(f"Signer: ...{result['signer_fpr'][-8:]}")
        if result.get("signature_valid") is not None:
            ok_txt = "(valid)" if result["signature_valid"] else "(invalid)"
            display.text(f"Signature: {ok_txt}")
        if result.get("warning"):
            display.text(result["warning"])
        input("Press Enter to go back...")
        return

    # 5) Fallback
    display.text("Unknown message type.")
    if result.get("warning"):
        display.text(result["warning"])
    input("Press Enter to go back...")


# ========== KEYS MENU ==========

def keys_menu(display, gpg):
    """Show key management options."""
    while True:
        display.clear()
        display.text("Keys Menu")
        display.text("1) List Keys")
        display.text("2) Generate New Key")
        display.text("3) Delete Key")
        display.text("4) ⬅ Back")
        choice = input("Select: ").strip()

        # === List keys ===
        if choice == "1":
            display.clear()
            if not gpg.keys:
                display.text("No keys available.")
            else:
                display.text("Available keys:")
                for short, meta in gpg.keys.items():
                    label = f"{meta['name']} <{meta['email']}>"
                    display.text(f"{short} | {label}")
            input("Press Enter...")

        # === Generate new ===
        elif choice == "2":
            display.clear()
            name = input("Name: ")
            email = input("Email: ")
            pw = input("Passphrase (optional): ") or None
            display.text("Generating keypair...")
            fpr = gpg.generate_key(name, email, pw)
            if fpr:
                display.text(f"Key created: ...{fpr[-8:]}")
            else:
                display.text("Key generation failed.")
            input("Press Enter...")

        # === Delete ===
        elif choice == "3":
            display.clear()
            if not gpg.keys:
                display.text("No keys available to delete.")
                input("Press Enter...")
                continue

            display.text("Available keys:")
            for short, meta in gpg.keys.items():
                label = f"{meta['name']} <{meta['email']}>"
                display.text(f"{short} | {label}")

            keyid = input("Enter last 8 chars of key to delete: ").strip().upper()
            confirm = input(f"Delete key ...{keyid}? (y/n): ").strip().lower()
            if confirm == "y":
                success = gpg.delete_key_by_shortid(keyid)
                if success:
                    display.text(f"Key ...{keyid} deleted (public ok).")
                else:
                    display.text(f"Key ...{keyid} not found or locked.")
            else:
                display.text("Cancelled.")
            input("Press Enter...")

        elif choice in ("4", "b", "B"):
            return
        else:
            display.text("Invalid option.")


# ========== SETTINGS MENU ==========

def settings_menu(display, settings):
    """Settings main menu."""
    while True:
        display.clear()
        display.text("⚙️ Settings")
        display.text(f"Display: {settings['display_type']}")
        display.text(f"Camera: {settings['camera_type']}")
        display.text("1) Display Settings")
        display.text("2) Camera Settings")
        display.text("3) About")
        display.text("4) ⬅ Back")
        choice = input("Select: ").strip()

        if choice == "1":
            display_settings_menu(display, settings)
        elif choice == "2":
            camera_settings_menu(display, settings)
        elif choice == "3":
            display.clear()
            display.text("ChatGPG v0.3")
            display.text("Ephemeral GPG signer")
            display.text("By Razvan")
            input("Press Enter to go back.")
        elif choice in ("4", "b", "B"):
            return
        else:
            display.text("Invalid option.")


# ========== DISPLAY SETTINGS ==========

def display_settings_menu(display, settings):
    while True:
        display.clear()
        display.text("isplay Settings")
        display.text(f"Current: {settings['display_type']}")
        display.text("1) ST7789 (real)")
        display.text("2) Virtual (desktop)")
        display.text("3) ⬅ Back")
        choice = input("Select: ").strip()

        if choice == "1":
            settings["display_type"] = "st7789"
            display.text("Using ST7789.")
            sleep(1)
        elif choice == "2":
            settings["display_type"] = "virtual"
            display.text("Using Virtual Display.")
            sleep(1)
        elif choice in ("3", "b", "B"):
            return
        else:
            display.text("Invalid option.")


# ========== CAMERA SETTINGS ==========

def camera_settings_menu(display, settings):
    while True:
        display.clear()
        display.text("Camera Settings")
        display.text(f"Current: {settings['camera_type']}")
        display.text("1) Pi Camera (ZeroCam)")
        display.text("2) Desktop Webcam")
        display.text("3) ⬅ Back")
        choice = input("Select: ").strip()

        if choice == "1":
            settings["camera_type"] = "picam"
            display.text("Using Pi Camera.")
            sleep(1)
        elif choice == "2":
            settings["camera_type"] = "webcam"
            display.text("Using Desktop Webcam.")
            sleep(1)
        elif choice in ("3", "b", "B"):
            return
        else:
            display.text("Invalid option.")
