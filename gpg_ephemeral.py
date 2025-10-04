"""
Ephemeral GPG manager for ChatGPG
=================================

Features:
- Ephemeral GNUPG home (in RAM /dev/shm)
- Key management (generate, import, list, export)
- Encrypt / decrypt / sign / verify
- Safe message signing rules (only author can sign)
- Detects: encrypted, signed, unsigned, encrypted+signed, key blocks
- Secure RAM wipe on exit
"""

import gnupg
import tempfile
import shutil
import atexit
import os
import re
from typing import Optional, Dict, List, Callable


# --- Regex helpers for metadata extraction ---
FINGERPRINT_RE = re.compile(r'Fingerprint:\s*([A-Fa-f0-9]+)', re.IGNORECASE)
RECIPIENTS_RE = re.compile(
    r'^Recipients?:\s*((?:[A-Fa-f0-9]{8,40})(?:\s*,\s*[A-Fa-f0-9]{8,40})*)$',
    re.IGNORECASE | re.MULTILINE
)

def _short8(fp: str) -> str:
    return fp[-8:] if fp else ""


def _endswith8(a: str, b: str) -> bool:
    """True if last 8 hex of a == last 8 hex of b."""
    if not a or not b:
        return False
    return a[-8:].upper() == b[-8:].upper()


class EphemeralGPG:
    def __init__(self, gpg_home: Optional[str] = None, use_ram: bool = True):
        """
        Create ephemeral GPG environment.
        If gpg_home is None and use_ram=True -> directory in /dev/shm
        """
        if gpg_home:
            os.makedirs(gpg_home, exist_ok=True)
            self.gpg_home = gpg_home
            self._cleanup_on_exit = False
        else:
            tmpdir_base = "/dev/shm" if use_ram and os.path.isdir("/dev/shm") else None
            self.gpg_home = tempfile.mkdtemp(prefix="gpg_", dir=tmpdir_base)
            self._cleanup_on_exit = True

        self.gpg = gnupg.GPG(gnupghome=self.gpg_home)
        # keys: map short8 -> { fpr, name, email, has_passphrase }
        self.keys: Dict[str, Dict] = {}

        if self._cleanup_on_exit:
            atexit.register(self._cleanup)

    # =========================
    # Key Management
    # =========================
    def generate_key(self, name: str, email: str, passphrase: Optional[str] = None,
                     key_type="RSA", key_length=2048, expire_date=0) -> Optional[str]:
        """Generate new ephemeral key."""
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

    def debug_list_all_keys(self):
        print("== Public keys ==")
        for k in self.gpg.list_keys():
            print(k["fingerprint"], k["uids"])
        print("== Secret keys ==")
        for k in self.gpg.list_keys(secret=True):
            print(k["fingerprint"], k["uids"])

    def import_private_key(self, armored: str, assume_has_passphrase=True) -> Dict:
        res = self.gpg.import_keys(armored)
        for r in res.results:
            fpr = r.get("fingerprint")
            if fpr:
                short = _short8(fpr)
                # preserve name/email if existed
                meta = self.keys.get(short, {})
                meta.update({
                    "fpr": fpr,
                    "name": meta.get("name", "Imported"),
                    "email": meta.get("email", ""),
                    "has_passphrase": False
                })
                self.keys[short] = meta
        print(self.gpg.list_keys(secret=True))
        self.debug_list_all_keys()
        return res

    def list_keys(self, secret: bool = True) -> Dict[str, Dict]:
        return self.keys

    # =========================
    # Crypto Operations
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
        return {"ok": ok, "status": status, "plaintext": plaintext}

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
    # Metadata parsing helpers
    # =========================
    def _parse_metadata(self, text: str) -> Dict[str, object]:
        """
        Extract author_fpr (first Fingerprint:) and recipients list (from Recipients: ...).
        Returns {author_fpr, recipients, all_fprs}
        """
        author_fpr = None
        m_auth = FINGERPRINT_RE.search(text)
        if m_auth:
            author_fpr = m_auth.group(1).strip()

        recipients: List[str] = []
        m_rec = RECIPIENTS_RE.search(text)
        if m_rec:
            recipients = [x.strip() for x in m_rec.group(1).split(",") if x.strip()]

        # all_fprs (author + recipients) for broader checks if needed
        all_fprs = []
        if author_fpr:
            all_fprs.append(author_fpr)
        all_fprs.extend(recipients)

        return {"author_fpr": author_fpr, "recipients": recipients, "all_fprs": all_fprs}

    def _our_fprs(self) -> List[str]:
        return [meta["fpr"] for meta in self.keys.values()]

    # =========================
    # Message Processing
    # =========================
    def process_scanned(self, armored_text: str, ask_passphrase_fn: Optional[Callable] = None) -> Dict:
        """
        Detect and handle encrypted/signed/unsigned content.
        Returns dict:
          type, plaintext, signature_valid, signer_fpr,
          author_fpr, recipients, expected_fprs,
          is_author(bool), is_recipient(bool),
          should_sign(bool), status, warning
        """
        out = {
            "type": None,
            "plaintext": None,
            "signature_valid": None,
            "signer_fpr": None,
            "author_fpr": None,
            "recipients": [],
            "expected_fprs": [],
            "is_author": False,
            "is_recipient": False,
            "should_sign": False,
            "status": "",
            "warning": None
        }

        print(armored_text)

        # ---- Detect and short-circuit key blocks (avoid treating as messages) ----
        if "BEGIN PGP PRIVATE KEY BLOCK" in armored_text:
            out["type"] = "private_key"
            out["status"] = "Detected private key block"
            return out
        if "BEGIN PGP PUBLIC KEY BLOCK" in armored_text:
            out["type"] = "public_key"
            out["status"] = "Detected public key block"
            return out

        # Parse any outer metadata (may be empty if metadata is inside encrypted payload)
        meta_outer = self._parse_metadata(armored_text)
        out["author_fpr"] = meta_outer["author_fpr"]
        out["recipients"] = meta_outer["recipients"]
        out["expected_fprs"] = meta_outer["all_fprs"]

        # 1) Signed (clearsigned)
        if "BEGIN PGP SIGNED MESSAGE" in armored_text:
            out["type"] = "clearsigned"
            v = self.verify_clearsign(armored_text)
            out["signature_valid"] = v["valid"]
            out["signer_fpr"] = v["fingerprint"]

            # Extract human-readable plaintext (strip armor headers)
            payload = armored_text.split("-----BEGIN PGP SIGNATURE-----")[0]
            lines = [ln for ln in payload.splitlines() if not ln.startswith(("-----", "Hash:"))]
            out["plaintext"] = "\n".join(lines).strip()

            # Determine author/recipients from plaintext metadata if available
            meta_in = self._parse_metadata(out["plaintext"])
            if meta_in["author_fpr"]:
                out["author_fpr"] = meta_in["author_fpr"]
            if meta_in["recipients"]:
                out["recipients"] = meta_in["recipients"]
            out["expected_fprs"] = meta_in["all_fprs"] or out["expected_fprs"]

            # Mark flags
            for our in self._our_fprs():
                if out["author_fpr"] and _endswith8(our, out["author_fpr"]):
                    out["is_author"] = True
                if any(_endswith8(our, r) for r in out["recipients"]):
                    out["is_recipient"] = True

            if out["signer_fpr"]:
                ok = any(_endswith8(out["signer_fpr"], fp) for fp in out["expected_fprs"]) if out["expected_fprs"] else True
                if not ok:
                    out["warning"] = "⚠️ signer not in recipients list"
            elif not v["valid"]:
                out["warning"] = "⚠️ invalid signature"
            return out

        # 2) Encrypted (possibly containing signed message)
        if "BEGIN PGP MESSAGE" in armored_text:
            out["type"] = "encrypted"

            # If no private keys loaded -> cannot decrypt (and do not ask passphrase)
            if not self.keys:
                out["status"] = "No private keys loaded; cannot decrypt message."
                out["warning"] = "⚠️ Encrypted message but no private keys present."
                return out

            # Attempt decrypt (first without passphrase)
            dec_res = self.decrypt(armored_text, passphrase=None)
            if not dec_res["ok"]:
                # Ask passphrase only if we actually have passphrase-protected keys
                if any(k["has_passphrase"] for k in self.keys.values()) and ask_passphrase_fn:
                    pw = ask_passphrase_fn("Enter passphrase for your key (or empty to cancel): ")
                    if pw:
                        dec_res = self.decrypt(armored_text, passphrase=pw)

            if not dec_res["ok"]:
                out["warning"] = "❌ Cannot decrypt message."
                out["status"] = dec_res["status"]
                return out

            plaintext = dec_res["plaintext"]
            out["plaintext"] = plaintext
            out["status"] = dec_res["status"] or "Decrypted OK"

            # Parse metadata from decrypted plaintext
            meta_in = self._parse_metadata(plaintext)
            if meta_in["author_fpr"]:
                out["author_fpr"] = meta_in["author_fpr"]
            if meta_in["recipients"]:
                out["recipients"] = meta_in["recipients"]
            out["expected_fprs"] = meta_in["all_fprs"] or out["expected_fprs"]

            # Mark flags (who are we?)
            for our in self._our_fprs():
                if out["author_fpr"] and _endswith8(our, out["author_fpr"]):
                    out["is_author"] = True
                if any(_endswith8(our, r) for r in out["recipients"]):
                    out["is_recipient"] = True

            # If decrypted contains a clearsigned message → verify
            if "BEGIN PGP SIGNED MESSAGE" in plaintext:
                v = self.verify_clearsign(plaintext)
                out["type"] = "encrypted_signed"
                out["signature_valid"] = v["valid"]
                out["signer_fpr"] = v["fingerprint"]
                if out["expected_fprs"] and out["signer_fpr"]:
                    ok = any(_endswith8(out["signer_fpr"], fp) for fp in out["expected_fprs"])
                    if not ok:
                        out["warning"] = "⚠️ signer not among recipients"
            else:
                # Decrypted unsigned payload → candidate for signing if we're the author
                out["type"] = "encrypted_unsigned"
                out["should_sign"] = bool(out["is_author"])
            return out

        # 3) Unsigned plaintext (no PGP armor)
        if "BEGIN PGP" not in armored_text:
            out["type"] = "unsigned"
            out["plaintext"] = armored_text

            meta_in = self._parse_metadata(armored_text)
            out["author_fpr"] = meta_in["author_fpr"]
            out["recipients"] = meta_in["recipients"]
            out["expected_fprs"] = meta_in["all_fprs"]

            for our in self._our_fprs():
                if out["author_fpr"] and _endswith8(our, out["author_fpr"]):
                    out["is_author"] = True
                if any(_endswith8(our, r) for r in out["recipients"]):
                    out["is_recipient"] = True

            out["should_sign"] = bool(out["is_author"])
            return out

        # 4) Unknown
        out["type"] = "unknown"
        out["plaintext"] = armored_text
        out["warning"] = "⚠️ Unknown PGP block"
        return out

    # =========================
    # Signing Unsigned Messages
    # =========================
    def sign_unsigned_message(self, plaintext: str, signer_short8: str,
                              ask_passphrase_fn: Optional[Callable] = None) -> Dict:
        """
        Sign a message (plaintext) only if:
          - signer_short8 exists in self.keys
          - signer_full_fpr == author_fpr (metadata)
        """
        res = {"ok": False, "signed_armored": None, "status": "", "warning": None}

        key_meta = self.keys.get(signer_short8)
        if not key_meta:
            res["status"] = "Key not found."
            return res

        signer_fpr = key_meta["fpr"]
        meta = self._parse_metadata(plaintext)
        author_fpr = meta["author_fpr"]
        if not author_fpr:
            res["status"] = "No author metadata found; refusing to sign."
            res["warning"] = "❌ Missing author metadata"
            return res

        # Strict rule: only author may sign (match by last-8 or full)
        if not (_endswith8(signer_fpr, author_fpr) or _endswith8(author_fpr, signer_fpr)):
            res["status"] = "Signer is not the author; refusing to sign."
            res["warning"] = "❌ Security rule: only the author may sign."
            return res

        # Optional: also ensure author is listed among recipients
        recipients = meta["recipients"]
        if recipients and not any(_endswith8(signer_fpr, r) for r in recipients):
            res["status"] = "Author not listed among recipients; refusing to sign."
            res["warning"] = "❌ Author FPR not in recipients"
            return res

        # get passphrase if required (only for signing key)
        pw = None
        if key_meta.get("has_passphrase"):
            if ask_passphrase_fn:
                pw = ask_passphrase_fn("Enter passphrase for signing key: ")
            else:
                res["status"] = "Signing key requires passphrase but no callback provided"
                return res

        try:
            signed = self.sign_message(plaintext, signer_fpr, passphrase=pw)
            res["ok"] = True
            res["signed_armored"] = signed
            res["status"] = "Signed OK"
        except Exception as e:
            res["status"] = f"Signing failed: {e}"
        return res

    # =========================
    # Cleanup / Secure Wipe
    # =========================
    def _cleanup(self):
        """Wipe all GPG data from RAM (secure cleanup)."""
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
