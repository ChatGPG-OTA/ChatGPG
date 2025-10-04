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
import subprocess
import atexit
import os
import re
from typing import Optional, Dict, List, Callable
import textwrap

DECRYPT_KEY_RE = re.compile(r'key,?\s*(?:ID|id)?\s*([A-Fa-f0-9]{8,40})')


def _short8(fp: str) -> str:
    return fp[-8:].upper() if fp else ""


def _undash_clearsign_payload(text: str) -> str:
    """
    In clearsigned text, lines starting with '- ' are dash-escaped.
    This removes the leading '- ' so that inner PGP blocks are intact.
    """
    out_lines = []
    for ln in text.splitlines():
        if ln.startswith('- '):
            out_lines.append(ln[2:])
        else:
            out_lines.append(ln)
    return "\n".join(out_lines)


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

        # Write GPG config (main)
        with open(os.path.join(self.gpg_home, "gpg.conf"), "w") as f:
            f.write(textwrap.dedent("""\
            use-agent
            no-tty
            """))

        # Write GPG agent config (loopback)
        agent_conf_path = os.path.join(self.gpg_home, "gpg-agent.conf")
        with open(agent_conf_path, "w") as f:
            f.write("allow-loopback-pinentry\n")

        # Reload agent to apply settings
        os.system(f"gpgconf --homedir {self.gpg_home} --kill gpg-agent >/dev/null 2>&1")

        # Initialize GPG engine
        self.gpg = gnupg.GPG(
            gnupghome=self.gpg_home,
            options=["--pinentry-mode", "loopback"]
        )

        self.keys: Dict[str, Dict] = {}

        if self._cleanup_on_exit:
            atexit.register(self._cleanup)



    # =========================
    # Key Management
    # =========================
    def generate_key(self, name: str, email: str, passphrase: Optional[str] = None,
                 key_type="RSA", key_length=2048, expire_date=0) -> Optional[str]:

        if passphrase:
            params = self.gpg.gen_key_input(
                name_real=name,
                name_email=email,
                passphrase=passphrase,
                key_type=key_type,
                key_length=key_length,
                expire_date=expire_date
            )
        else:
            params = self.gpg.gen_key_input(
                name_real=name,
                name_email=email,
                key_type=key_type,
                key_length=key_length,
                expire_date=expire_date,
                no_protection=True
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

    def import_public_key(self, armored: str) -> Dict:
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

    def delete_key_by_shortid(self, shortid: str) -> bool:
        """Delete keypair (public + private) by last 8 chars, tolerant to GPG quirks."""
        shortid = shortid.upper()
        target = None
        for short, meta in list(self.keys.items()):
            if short == shortid or meta["fpr"][-8:].upper() == shortid:
                target = meta["fpr"]
                del self.keys[short]
                break

        if not target:
            return False

        try:
            # Delete public key first (no passphrase required)
            self.gpg.delete_keys(target)
        except Exception as e:
            print(f"[WARN] Failed to delete public key {target}: {e}")

        try:
            # Try deleting secret key, but ignore failure due to dummy passphrase requirement
            self.gpg.delete_keys(target, secret=True)
        except Exception as e:
            if "passphrase" in str(e).lower():
                print(f"[INFO] Secret key {target} retained (GPG requires passphrase).")
            else:
                print(f"[WARN] Failed to delete secret key {target}: {e}")

        print(f"[GPG] Deleted key {target} (public, secret optional)")
        return True

    # =========================
    # Crypto Operations
    # =========================
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
        """Clearsign plaintext message."""
        key_full = signer_fpr if len(signer_fpr) > 8 else self.keys[signer_fpr]["fpr"]
        sig = self.gpg.sign(message, keyid=key_full, passphrase=passphrase, clearsign=True)
        if not getattr(sig, "data", None):
            raise RuntimeError(f"Signing failed: {getattr(sig, 'status', '')}")
        return str(sig)

    def sign_ciphertext(self, armored_ciphertext: str, signer_short8: str,
                        ask_passphrase_fn: Optional[Callable[[str], Optional[str]]] = None) -> str:
        """
        Clearsign the ORIGINAL encrypted PGP block, preserving recipients.
        """
        key_meta = self.keys.get(signer_short8)
        if not key_meta:
            raise RuntimeError("Signing key not found in ephemeral keyring.")
        key_full = key_meta["fpr"]

        pw = None
        if key_meta.get("has_passphrase") and ask_passphrase_fn:
            pw = ask_passphrase_fn("Enter passphrase for signing key: ")

        sig = self.gpg.sign(armored_ciphertext, keyid=key_full, passphrase=pw, clearsign=True)
        if not getattr(sig, "data", None):
            raise RuntimeError(f"Signing failed: {getattr(sig, 'status', '')}")
        return str(sig)

    def sign_and_encrypt_message(self, message: str, signer_fpr: str, recipients: List[str], passphrase: Optional[str] = None) -> str:
        """
        (Optional) Clearsign + re-encrypt for a given list of recipients.
        Use ONLY if you explicitly know the recipients. To preserve the original recipients
        of the message, prefer sign_ciphertext().
        """
        key_full = signer_fpr if len(signer_fpr) > 8 else self.keys[signer_fpr]["fpr"]
        signed = self.gpg.sign(message, keyid=key_full, passphrase=passphrase, clearsign=True)
        if not getattr(signed, "data", None):
            raise RuntimeError(f"Signing failed: {getattr(signed, 'status', '')}")

        encrypted = self.gpg.encrypt(str(signed), recipients, always_trust=True, armor=True)
        if not encrypted.ok:
            raise RuntimeError(f"Encrypt failed: {encrypted.status}")
        return str(encrypted)

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

        # --- Signed (clearsigned) ---
        if "BEGIN PGP SIGNED MESSAGE" in armored_text:
            out["type"] = "signed"
            v = self.verify_clearsign(armored_text)
            out["signature_valid"] = v["valid"]
            out["signer_fpr"] = v["fingerprint"]  # may be None if pubkey missing

            # Extract payload: after "Hash:..." blank line until signature block
            head, _, rest = armored_text.partition("\n\n")
            body = armored_text
            if rest:
                # everything before signature block
                body = rest.split("-----BEGIN PGP SIGNATURE-----")[0]
            # Undash-escape so inner PGP blocks remain valid
            signed_payload = _undash_clearsign_payload(body).strip()
            out["plaintext"] = signed_payload

            # If payload itself is an encrypted PGP message, try to decrypt it
            if "BEGIN PGP MESSAGE" in signed_payload and self.keys:
                pw = ask_passphrase_fn("Enter passphrase (or empty): ")
                dec = self.decrypt(signed_payload, passphrase=pw or None)
                # print(dec)

                if dec["ok"]:
                    out["is_recipient"] = True
                    out["decrypted_with"] = dec.get("key_used")
                    out["plaintext"] = dec["plaintext"]
                    out["type"] = "signed_ciphertext"
                else:
                    out["decryption_failed"] = True
                    out["decryption_status"] = dec["status"]
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
            out["is_recipient"] = True
            out["decrypted_with"] = dec.get("key_used") or list(self.keys.values())[0]["fpr"]

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

    def export_keypair_ascii(self, fpr: str, passphrase: Optional[str] = None) -> tuple[str, str]:
        """Export public + private keys in ASCII armor using python-gnupg's safe API."""
        # Public key is always easy
        pub_ascii = self.gpg.export_keys(fpr, armor=True)

        # Private key export — with or without passphrase
        try:
            if passphrase:
                priv_ascii = self.gpg.export_keys(
                    fpr,
                    secret=True,
                    armor=True,
                    passphrase=passphrase,
                    expect_passphrase=True,
                )
            else:
                priv_ascii = self.gpg.export_keys(
                    fpr,
                    secret=True,
                    armor=True,
                    expect_passphrase=False,
                )
        except Exception as e:
            raise RuntimeError(f"Secret key export failed: {e}")

        if not priv_ascii.strip():
            raise RuntimeError("Empty private key export output")

        return pub_ascii.strip(), priv_ascii.strip()

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
