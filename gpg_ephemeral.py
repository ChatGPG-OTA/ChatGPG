"""
Ephemeral GPG manager for ChatGPG (final clean version)

- Ephemeral GNUPG home (RAM)
- Key management (generate, import, list)
- Encrypt / decrypt / sign / verify
- Detects: encrypted, signed, unsigned, key blocks
- No metadata parsing — logic purely by cryptographic roles
"""

import gnupg
import tempfile
import shutil
import atexit
import os
import re
from typing import Optional, Dict, List, Callable

DECRYPT_KEY_RE = re.compile(r'key,?\s*(?:ID|id)?\s*([A-Fa-f0-9]{8,40})')


def _short8(fp: str) -> str:
    return fp[-8:].upper() if fp else ""


def _endswith8(a: str, b: str) -> bool:
    if not a or not b:
        return False
    return a[-8:].upper() == b[-8:].upper()


class EphemeralGPG:
    def __init__(self, gpg_home: Optional[str] = None, use_ram: bool = True):
        if gpg_home:
            os.makedirs(gpg_home, exist_ok=True)
            self.gpg_home = gpg_home
            self._cleanup_on_exit = False
        else:
            tmpdir_base = "/dev/shm" if use_ram and os.path.isdir("/dev/shm") else None
            self.gpg_home = tempfile.mkdtemp(prefix="gpg_", dir=tmpdir_base)
            self._cleanup_on_exit = True

        self.gpg = gnupg.GPG(gnupghome=self.gpg_home)
        self.keys: Dict[str, Dict] = {}

        if self._cleanup_on_exit:
            atexit.register(self._cleanup)

    # =========================
    # Key Management
    # =========================
    def generate_key(self, name: str, email: str, passphrase: Optional[str] = None,
                     key_type="RSA", key_length=2048, expire_date=0) -> Optional[str]:
        params = self.gpg.gen_key_input(
            name_real=name,
            name_email=email,
            passphrase=passphrase,
            key_type=key_type,
            key_length=key_length,
            expire_date=expire_date
        )
        key = self.gpg.gen_key(params)
        fpr = str(key)
        if not fpr:
            return None
        self.keys[_short8(fpr)] = {
            "fpr": fpr,
            "name": name,
            "email": email,
            "has_passphrase": bool(passphrase)
        }
        return fpr

    def import_private_key(self, armored: str) -> Dict:
        res = self.gpg.import_keys(armored)
        for r in res.results:
            fpr = r.get("fingerprint")
            if fpr:
                short = _short8(fpr)
                self.keys[short] = {
                    "fpr": fpr,
                    "name": "Imported",
                    "email": "",
                    "has_passphrase": False
                }
        return res

    def list_keys(self) -> Dict[str, Dict]:
        return self.keys

    # =========================
    # Core Crypto
    # =========================
    def encrypt_to_recipients(self, plaintext: str, recipients: List[str]) -> str:
        res = self.gpg.encrypt(plaintext, recipients, always_trust=True, armor=True)
        if not res.ok:
            raise RuntimeError(f"GPG encrypt failed: {res.status}")
        return str(res)

    def decrypt(self, armored_text: str, passphrase: Optional[str] = None) -> Dict:
        dec = self.gpg.decrypt(armored_text, passphrase=passphrase)
        ok = bool(getattr(dec, "ok", False))
        status = getattr(dec, "status", "") or getattr(dec, "stderr", "")

        try:
            plaintext = dec.data.decode("utf-8") if isinstance(dec.data, (bytes, bytearray)) else str(dec)
        except Exception:
            plaintext = str(dec)

        key_used = None
        if hasattr(dec, "key_id") and dec.key_id:
            key_used = str(dec.key_id).upper()
        else:
            m = DECRYPT_KEY_RE.search(status)
            if m:
                key_used = m.group(1).upper()

        return {"ok": ok, "status": status, "plaintext": plaintext, "key_used": key_used}

    def verify_clearsign(self, text: str) -> Dict:
        v = self.gpg.verify(text)
        return {
            "valid": bool(getattr(v, "valid", False)),
            "fingerprint": getattr(v, "fingerprint", None) or getattr(v, "key_id", None),
            "status": getattr(v, "status", None)
        }

    def sign_message(self, message: str, signer_fpr: str, passphrase: Optional[str] = None) -> str:
        key_full = signer_fpr if len(signer_fpr) > 8 else self.keys[signer_fpr]["fpr"]
        sig = self.gpg.sign(message, keyid=key_full, passphrase=passphrase, clearsign=True)
        if not getattr(sig, "data", None):
            raise RuntimeError(f"Signing failed: {getattr(sig, 'status', '')}")
        return str(sig)

    # =========================
    # Message Processing
    # =========================
    def process_scanned(self, armored_text: str, ask_passphrase_fn: Optional[Callable] = None) -> Dict:
        """
        Determine message type and decrypt if possible.
        Detect if our key was used for decryption.
        """
        out = {
            "type": None,
            "plaintext": None,
            "signature_valid": None,
            "signer_fpr": None,
            "is_recipient": False,
            "status": "",
            "warning": None,
            "decrypted_with": None
        }

        # --- Key blocks ---
        if "BEGIN PGP PRIVATE KEY BLOCK" in armored_text:
            out["type"] = "private_key"
            out["status"] = "Private key block"
            return out
        if "BEGIN PGP PUBLIC KEY BLOCK" in armored_text:
            out["type"] = "public_key"
            out["status"] = "Public key block"
            return out

        # --- Signed message ---
        if "BEGIN PGP SIGNED MESSAGE" in armored_text:
            out["type"] = "signed"
            v = self.verify_clearsign(armored_text)
            out["signature_valid"] = v["valid"]
            out["signer_fpr"] = v["fingerprint"]

            payload = armored_text.split("-----BEGIN PGP SIGNATURE-----")[0]
            lines = [ln for ln in payload.splitlines() if not ln.startswith(("-----", "Hash:"))]
            out["plaintext"] = "\n".join(lines).strip()
            return out

        # --- Encrypted message ---
        if "BEGIN PGP MESSAGE" in armored_text:
            out["type"] = "encrypted"

            if not self.keys:
                out["status"] = "No private keys loaded"
                out["warning"] = "Cannot decrypt: no keys."
                return out

            dec = self.decrypt(armored_text)
            if not dec["ok"]:
                # ask passphrase if any key requires it
                if any(k["has_passphrase"] for k in self.keys.values()) and ask_passphrase_fn:
                    pw = ask_passphrase_fn("Enter passphrase (or empty): ")
                    if pw:
                        dec = self.decrypt(armored_text, passphrase=pw)

            if not dec["ok"]:
                out["status"] = dec["status"]
                out["warning"] = "Cannot decrypt message."
                return out

            out["plaintext"] = dec["plaintext"]
            out["status"] = "Decryption OK"

            # Even if gnupg misreports key_id, we know we’re one of the recipients.
            out["is_recipient"] = True
            out["decrypted_with"] = dec.get("key_used") or list(self.keys.values())[0]["fpr"]
            print(f"[DEBUG] Assuming recipient because decrypt OK. Using key: {out['decrypted_with'][-8:]}")

            if dec["key_used"]:
                print(f"[DEBUG] Message decrypted with key: {dec['key_used']}")
                keyid8 = _short8(dec["key_used"])
                for meta in self.keys.values():
                    fpr = meta["fpr"]
                    if _endswith8(fpr, keyid8) or keyid8 in fpr:
                        out["is_recipient"] = True
                        break

            # Determine if it’s unsigned inside
            if "BEGIN PGP SIGNED MESSAGE" in dec["plaintext"]:
                out["type"] = "encrypted_signed"
            else:
                out["type"] = "encrypted_unsigned"

            return out

        # --- Unsigned plaintext ---
        if "BEGIN PGP" not in armored_text:
            out["type"] = "unsigned"
            out["plaintext"] = armored_text
            return out

        # --- Unknown ---
        out["type"] = "unknown"
        out["plaintext"] = armored_text
        out["warning"] = "Unknown PGP block"
        return out

    # =========================
    # Cleanup
    # =========================
    def _cleanup(self):
        try:
            if os.path.isdir(self.gpg_home):
                for root, dirs, files in os.walk(self.gpg_home, topdown=False):
                    for f in files:
                        try:
                            fp = os.path.join(root, f)
                            with open(fp, "ba+", buffering=0) as fh:
                                size = os.path.getsize(fp)
                                fh.write(b"\x00" * size)
                            os.remove(fp)
                        except Exception:
                            pass
                    for d in dirs:
                        try:
                            os.rmdir(os.path.join(root, d))
                        except Exception:
                            pass
                shutil.rmtree(self.gpg_home, ignore_errors=True)
                os.sync()
                print(f"[CLEANUP] Ephemeral GPG home wiped: {self.gpg_home}")
        except Exception as e:
            print(f"[CLEANUP ERROR] {e}")
