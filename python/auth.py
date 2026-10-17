#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Apple ID login via GrandSlam (GSA) using SRP-6a, with 2FA and Xcode app token.
# Each GSA request opens a fresh session to avoid Apple's edge returning 503.
# client_info and user_agent come from the anisette server, no fallback.

import os
import uuid
import json
import base64
import time
import hashlib
import hmac
import traceback
from datetime import datetime, timezone

import requests
import plistlib as plist
import srp._pysrp as srp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


ANISETTE_URL = "https://anisette-v3-server-sg29.onrender.com/"
ANISETTE_FALLBACK = []
COOKIE_PATH = os.path.expanduser("~/.sideload/cookies.enc")


def _safe_plist_loads(data):
    # Apple sometimes returns plists without an XML header; plistlib throws on those.
    if isinstance(data, str):
        data = data.encode("utf-8")
    stripped = data.lstrip()
    if not stripped.startswith(b"bplist") and not stripped.startswith(b"<?xml"):
        header = (
            b"<?xml version='1.0' encoding='UTF-8'?>\n"
            b"<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' "
            b"'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>\n"
            b"<plist version='1.0'>\n"
        )
        data = header + data + b"\n</plist>"
    return plist.loads(data)


def derive_key(password):
    salt = b"SideDroid-Cookie-Salt-v1"
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000, 32)


def save_cookies_encrypted(cookies_dict, password):
    try:
        key = derive_key(password)
        iv = os.urandom(12)
        aad = b"SideDroid-Cookies-v1"
        plaintext = json.dumps(cookies_dict).encode("utf-8")

        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag

        blob = iv + tag + ciphertext
        b64 = base64.b64encode(blob).decode("ascii")

        os.makedirs(os.path.dirname(COOKIE_PATH), exist_ok=True)
        with open(COOKIE_PATH, "w") as f:
            f.write(b64)

        print(f"[cookie] Saved {len(cookies_dict)} cookies")
        return True
    except Exception as e:
        print(f"[cookie] Save error: {e}")
        return False


def load_cookies_encrypted(password):
    try:
        if not os.path.exists(COOKIE_PATH):
            return None
        with open(COOKIE_PATH, "r") as f:
            b64 = f.read().strip()
        if not b64:
            return None

        blob = base64.b64decode(b64)
        if len(blob) < 28:
            return None

        iv = blob[:12]
        tag = blob[12:28]
        ciphertext = blob[28:]
        aad = b"SideDroid-Cookies-v1"
        key = derive_key(password)

        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        decryptor.authenticate_additional_data(aad)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        cookies = json.loads(plaintext.decode("utf-8"))
        print(f"[cookie] Loaded {len(cookies)} cookies")
        return cookies
    except Exception as e:
        print(f"[cookie] Load error: {e}")
        return None


class AppleAuth:
    def __init__(self, anisette_url=None, input_func=None):
        self.anisette_url = anisette_url or ANISETTE_URL
        self.input_func = input_func or input

        self.user_id = str(uuid.uuid4()).upper()
        self.device_id = str(uuid.uuid4()).upper()

        self.client_info = None
        self.user_agent = None
        self.xcode_ua = None

        self._cached_ani = None

        try:
            srp.rfc5054_enable()
            srp.no_username_in_x()
        except Exception as e:
            print(f"[SRP] Init error: {e}")

    def ensure_client_info(self):
        # No fallback. If the server can't provide identity, raise so the caller
        # can switch servers or wait for a fix.
        if self.client_info is not None and self.user_agent is not None:
            return

        url = self.anisette_url.rstrip("/") + "/v3/client_info"
        r = requests.get(url, timeout=10, verify=False)
        if r.status_code != 200:
            raise Exception(f"/v3/client_info HTTP {r.status_code}")

        data = r.json()
        client_info = data.get("client_info")
        user_agent = data.get("user_agent")

        if not client_info:
            raise Exception("/v3/client_info missing 'client_info'")
        if not user_agent:
            raise Exception("/v3/client_info missing 'user_agent'")

        self.client_info = client_info
        self.user_agent = user_agent
        self.xcode_ua = user_agent

        print(f"[identity] client_info: {self.client_info}")
        print(f"[identity] user_agent:  {self.user_agent}")

    def get_ani(self):
        servers = [self.anisette_url] + [s for s in ANISETTE_FALLBACK if s != self.anisette_url]
        for srv in servers:
            try:
                r = requests.get(srv, timeout=10, verify=False)
                if r.status_code != 200:
                    continue
                data = r.json()
                if "X-Apple-I-MD-M" in data:
                    return data
            except Exception:
                continue
        return None

    def generate_meta_headers(self):
        return {
            "X-Apple-I-Client-Time": datetime.now(timezone.utc)
                .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "X-Apple-I-TimeZone": "UTC",
            "loc": "en_US",
            "X-Apple-Locale": "en_US",
            "X-Apple-I-MD-RINFO": "17106176",
            "X-Mme-Device-Id": self.device_id,
            "X-Apple-I-SRL-NO": "0",
        }

    def generate_cpd(self):
        # cpd is required by the new GrandSlam.
        if self._cached_ani is None:
            self._cached_ani = self.get_ani()
        anisette = self._cached_ani
        if not anisette:
            return None

        if "X-Mme-Device-Id" in anisette:
            self.device_id = anisette["X-Mme-Device-Id"]

        cpd = {
            "bootstrap": True,
            "icscrec": True,
            "pbe": False,
            "prkgen": True,
            "svct": "iCloud",
            "loc": "en_US",
            "X-Apple-Locale": "en_US",
            "X-Apple-I-MD": anisette.get("X-Apple-I-MD", ""),
            "X-Apple-I-MD-M": anisette.get("X-Apple-I-MD-M", ""),
            "X-Mme-Device-Id": anisette.get("X-Mme-Device-Id", self.device_id),
            "X-Apple-I-MD-LU": anisette.get("X-Apple-I-MD-LU", ""),
            "X-Apple-I-MD-RINFO": anisette.get("X-Apple-I-MD-RINFO", "17106176"),
            "X-Apple-I-SRL-NO": anisette.get("X-Apple-I-SRL-NO", "0"),
            "X-Apple-I-Client-Time": anisette.get("X-Apple-I-Client-Time", ""),
            "X-Apple-I-TimeZone": anisette.get("X-Apple-I-TimeZone", "UTC"),
        }
        return cpd

    def encrypt_password(self, password, salt, iterations, protocol):
        p = hashlib.sha256(password.encode("utf-8")).digest()
        if protocol == "s2k_fo":
            p = p.hex().encode("utf-8")
        return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, 32)

    def create_session_key(self, usr, name):
        session_key = getattr(usr, "K", None)
        if not session_key:
            raise Exception("No session key (usr.K)")
        return hmac.new(session_key, name.encode(), hashlib.sha256).digest()

    def decrypt_cbc(self, usr, data):
        key = self.create_session_key(usr, "extra data key:")
        iv = self.create_session_key(usr, "extra data iv:")[:16]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted) + unpadder.finalize()

    def decrypt_gcm(self, sk, encrypted_data):
        # Layout: 3-byte XYZ (AAD) + 16-byte IV + ciphertext + 16-byte tag.
        if len(encrypted_data) < 35:
            raise Exception("Encrypted token too short")
        if encrypted_data[:3] != b"XYZ":
            raise Exception("Unexpected token version")

        aad = encrypted_data[:3]
        iv = encrypted_data[3:19]
        ciphertext = encrypted_data[19:-16]
        tag = encrypted_data[-16:]

        decryptor = Cipher(
            algorithms.AES(sk),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        decryptor.authenticate_additional_data(aad)
        return decryptor.update(ciphertext) + decryptor.finalize()

    def gsa_request(self, parameters, max_retries=3):
        # Fresh session per request. Apple allows only 2-3 requests per connection;
        # the 3rd onward can get 503 or a cut body.
        if parameters.get("o") == "apptokens":
            max_retries = 1

        for attempt in range(max_retries):
            self.ensure_client_info()

            cpd_data = self.generate_cpd()
            if not cpd_data:
                print("[gsa] Unable to obtain cpd")
                time.sleep(2)
                continue

            body = {
                "Header": {"Version": "1.0.1"},
                "Request": {"cpd": cpd_data},
            }
            body["Request"].update(parameters)

            headers = {
                "Content-Type": "text/x-xml-plist",
                "Accept": "text/x-xml-plist",
                "User-Agent": self.user_agent,
                "X-Mme-Client-Info": self.client_info,
                "Connection": "close",
            }

            anisette = self.get_ani()
            if anisette:
                for k in [
                    "X-Apple-I-MD",
                    "X-Apple-I-MD-M",
                    "X-Apple-I-MD-LU",
                    "X-Apple-I-MD-RINFO",
                    "X-Mme-Device-Id",
                    "X-Apple-I-Client-Time",
                ]:
                    if k in anisette:
                        headers[k] = anisette[k]

            try:
                op = parameters.get("o", "?")
                print(f"[gsa] {op} (attempt {attempt + 1}/{max_retries})")

                body_bytes = plist.dumps(body, fmt=plist.FMT_XML)

                session = requests.Session()
                session.verify = False
                session.trust_env = False
                session.headers.update(headers)

                response = session.post(
                    "https://gsa.apple.com/grandslam/GsService2",
                    data=body_bytes,
                    timeout=30,
                )
                session.close()

                print(f"[gsa] HTTP {response.status_code}")

                if response.status_code == 429:
                    print("[gsa] 429 - rate limited")
                    if attempt < max_retries - 1:
                        time.sleep(10)
                        continue
                    raise Exception("GSA 429")

                if response.status_code >= 500 or \
                   response.headers.get("Content-Type", "").startswith("text/html"):
                    wait = min(2 ** attempt + 1, 15)
                    print(f"[gsa] HTTP {response.status_code} - waiting {wait}s")
                    time.sleep(wait)
                    continue

                response.raise_for_status()
                content = response.content

                print(f"[gsa] raw response: len={len(content)}, first={content[:60]!r}")

                if not content or not content.strip():
                    print("[gsa] Empty body, treating as empty Response")
                    return {"Status": {}, "_headers": dict(response.headers)}

                if not content.lstrip().startswith(b"<?xml") and \
                   not content.startswith(b"bplist"):
                    raise Exception(f"Unexpected response format: {content[:200]!r}")

                result = plist.loads(content)
                if "Response" not in result:
                    raise Exception("Invalid response")
                result = result["Response"]

                st = result.get("Status", {})
                ec = st.get("ec", 0)
                if ec != 0:
                    print(f"[gsa] ec={ec} em={st.get('em', '?')}")
                else:
                    print("[gsa] OK")

                result["_headers"] = dict(response.headers)
                return result

            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                print(f"[gsa] Error: {e} - retrying")
                time.sleep(2)

        raise Exception("GSA request failed")

    def _build_2fa_headers(self, dsid, idms_token):
        # Don't override X-Apple-I-MD-LU if anisette already has one; otherwise
        # it desyncs from MD-M.
        self.ensure_client_info()

        identity_token = base64.b64encode(
            (str(dsid) + ":" + idms_token).encode()
        ).decode()

        headers = {
            "Content-Type": "text/x-xml-plist",
            "User-Agent": self.xcode_ua,
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-Identity-Token": identity_token,
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "14.2 (14C18)",
            "X-Mme-Client-Info": self.client_info,
            "X-MMe-Client-Info": self.client_info,
            "X-Apple-I-DSID": str(dsid),
            "Connection": "close",
        }
        headers.update(self.generate_meta_headers())

        anisette = self.get_ani()
        if anisette:
            for k in [
                "X-Apple-I-MD",
                "X-Apple-I-MD-M",
                "X-Apple-I-MD-LU",
                "X-Apple-I-MD-RINFO",
                "X-Mme-Device-Id",
                "X-Apple-I-Client-Time",
            ]:
                if k in anisette:
                    headers[k] = anisette[k]

        if "X-Apple-I-MD-LU" not in headers:
            headers["X-Apple-I-MD-LU"] = base64.b64encode(
                str(dsid).encode()
            ).decode()

        return headers

    def handle_2fa_trusted_device(self, dsid, idms_token):
        print("[2fa] Trusted device...")
        headers = self._build_2fa_headers(dsid, idms_token)

        for _ in range(3):
            try:
                s = requests.Session()
                s.verify = False
                s.trust_env = False
                r = s.get(
                    "https://gsa.apple.com/auth/verify/trusteddevice",
                    headers=headers,
                    timeout=15,
                )
                s.close()
                if r.status_code in (200, 412):
                    break
                time.sleep(1)
            except Exception:
                continue

        code = self.input_func("[2fa] Enter the 6-digit code from your device: ").strip()
        if not code:
            return False

        vh = self._build_2fa_headers(dsid, idms_token)
        vh["security-code"] = code

        s = requests.Session()
        s.verify = False
        s.trust_env = False
        r = s.post(
            "https://gsa.apple.com/grandslam/GsService2/validate",
            headers=vh,
            data=b"",
            timeout=15,
        )
        s.close()

        if r.ok:
            try:
                result = plist.loads(r.content)
                ec = result.get("Response", {}).get("Status", {}).get("ec", 0)
                if ec == 0:
                    print("[2fa] Verified!")
                    return True
                print(f"[2fa] ec={ec}")
            except Exception:
                return True
        print(f"[2fa] Failed: HTTP {r.status_code}")
        return False

    def handle_2fa_sms(self, dsid, idms_token):
        print("[2fa-sms] Starting...")
        headers = self._build_2fa_headers(dsid, idms_token)
        phone_id = 1

        try:
            s = requests.Session()
            s.verify = False
            s.trust_env = False
            r = s.get(
                "https://gsa.apple.com/auth/verify/phone",
                headers=headers,
                timeout=10,
            )
            s.close()
            if r.ok:
                phones = r.json().get("trustedPhoneNumbers", [])
                if phones:
                    phone_id = phones[0].get("id", 1)
        except Exception:
            pass

        sms_headers = self._build_2fa_headers(dsid, idms_token)
        sms_headers["Content-Type"] = "application/json"
        sms_body = {"phoneNumber": {"id": phone_id}, "mode": "sms"}

        s = requests.Session()
        s.verify = False
        s.trust_env = False
        s.put(
            "https://gsa.apple.com/auth/verify/phone",
            json=sms_body,
            headers=sms_headers,
            timeout=10,
        )
        s.close()

        code = self.input_func("[2fa-sms] Enter the OTP: ").strip()
        if not code:
            return False

        vh = self._build_2fa_headers(dsid, idms_token)
        vh["Content-Type"] = "application/json"
        body = {
            "phoneNumber": {"id": phone_id},
            "mode": "sms",
            "securityCode": {"code": code},
        }

        s = requests.Session()
        s.verify = False
        s.trust_env = False
        r = s.post(
            "https://gsa.apple.com/auth/verify/phone/securitycode",
            json=body,
            headers=vh,
            timeout=10,
        )
        s.close()

        if r.ok:
            print("[2fa-sms] Verified!")
            return True
        print(f"[2fa-sms] Failed: HTTP {r.status_code}")
        return False

    def fetch_app_token(self, adsid, c, idms_token, sk,
                        app="com.apple.gs.xcode.auth",
                        allow_2fa=True):
        # apptokens is the 3rd request after init/complete. Apple caps connections
        # at ~2 requests, so we must use a raw socket, not requests.Session.
        # c stays as bytes so plistlib serializes it as <data>; base64-encoding
        # it would make Apple return 200 with an empty body.
        print(f"[apptoken] Fetching token for '{app}'...")
        print(f"[apptoken] c type: {type(c).__name__}, idms_len: {len(idms_token)}, sk_len: {len(sk)}")

        try:
            checksum_hmac = hmac.new(sk, digestmod=hashlib.sha256)
            checksum_hmac.update(b"apptokens")
            checksum_hmac.update(adsid.encode("utf-8"))
            checksum_hmac.update(app.encode("utf-8"))
            checksum = checksum_hmac.digest()

            import http.client
            import ssl

            def _apptokens_once():
                body = {
                    "Header": {"Version": "1.0.1"},
                    "Request": {
                        "cpd": self.generate_cpd(),
                        "u": adsid,
                        "app": [app],
                        "c": c,
                        "t": idms_token,
                        "checksum": checksum,
                        "o": "apptokens",
                    },
                }
                body_bytes = plist.dumps(body, fmt=plist.FMT_XML)

                identity = base64.b64encode(
                    (str(adsid) + ":" + idms_token).encode()
                ).decode()

                headers = {
                    "Host": "gsa.apple.com",
                    "Content-Type": "text/x-xml-plist",
                    "Accept": "text/x-xml-plist",
                    "User-Agent": self.user_agent,
                    "X-Mme-Client-Info": self.client_info,
                    "X-Apple-I-Identity-Token": identity,
                    "X-Apple-App-Info": "com.apple.gs.xcode.auth",
                    "Connection": "close",
                }

                anisette = self.get_ani()
                if anisette:
                    for k in [
                        "X-Apple-I-MD",
                        "X-Apple-I-MD-M",
                        "X-Apple-I-MD-LU",
                        "X-Apple-I-MD-RINFO",
                        "X-Mme-Device-Id",
                        "X-Apple-I-Client-Time",
                    ]:
                        if k in anisette:
                            headers[k] = anisette[k]

                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(
                    "gsa.apple.com", timeout=30, context=ctx
                )
                try:
                    conn.request(
                        "POST",
                        "/grandslam/GsService2",
                        body=body_bytes,
                        headers=headers,
                    )
                    resp = conn.getresponse()
                    raw = resp.read()
                    code = resp.status
                finally:
                    conn.close()
                return code, raw

            status, raw = _apptokens_once()
            print(f"[apptoken] attempt 1: HTTP {status}, len={len(raw)}, first={raw[:60]!r}")

            if status == 503:
                time.sleep(2)
                status, raw = _apptokens_once()
                print(f"[apptoken] attempt 2: HTTP {status}, len={len(raw)}, first={raw[:60]!r}")

            if status != 200:
                print(f"[apptoken] Non-200 status {status}, giving up")
                return None

            if not raw or not raw.strip():
                print("[apptoken] 200 with empty body")
                return None

            try:
                parsed = plist.loads(raw)
            except Exception as e:
                print(f"[apptoken] plist parse error: {e}, raw={raw[:200]!r}")
                return None

            response = parsed.get("Response", {})

            ec = response.get("Status", {}).get("ec", 0)
            if ec == -22411 and allow_2fa:
                print("[apptoken] Apple requires 2FA again (-22411)")
                for attempt in range(1, 4):
                    prompt = (
                        "[2fa] Enter the 6-digit code from your device: "
                        if attempt == 1 else
                        "[2fa] Enter the code again: "
                    )
                    code = self.input_func(prompt).strip()
                    if not code:
                        return None

                    vh = self._build_2fa_headers(adsid, idms_token)
                    vh["security-code"] = code

                    s = requests.Session()
                    s.verify = False
                    s.trust_env = False
                    r = s.post(
                        "https://gsa.apple.com/grandslam/GsService2/validate",
                        headers=vh,
                        data=b"",
                        timeout=15,
                    )
                    s.close()

                    if r.ok:
                        print("[apptoken] 2FA verified, retrying token fetch...")
                        return self.fetch_app_token(
                            adsid, c, idms_token, sk, app, allow_2fa=False
                        )
                    print(f"[apptoken] 2FA failed: HTTP {r.status_code}")
                return None

            encrypted_token = response.get("et")
            if not encrypted_token:
                print("[apptoken] No 'et' in response")
                return None

            decrypted = self.decrypt_gcm(sk, encrypted_token)
            token_plist = _safe_plist_loads(decrypted)
            app_tokens = token_plist.get("t", {})
            token_info = app_tokens.get(app)

            if token_info and "token" in token_info:
                print("[apptoken] OK!")
                return token_info["token"]
            return None
        except Exception as e:
            print(f"[apptoken] Error: {e}")
            return None

    def authenticate(self, apple_id, password, _depth=0):
        # Flow: SRP init -> complete -> (2FA if required) -> retry for a fresh
        # session key -> app token.
        try:
            print(f"[auth] Starting: {apple_id}")

            usr = srp.User(
                apple_id, bytes(),
                hash_alg=srp.SHA256,
                ng_type=srp.NG_2048,
            )
            _, A = usr.start_authentication()

            response = self.gsa_request({
                "A2k": A,
                "ps": ["s2k", "s2k_fo"],
                "u": apple_id,
                "o": "init",
            })

            if "sp" not in response:
                print("[auth] Missing SP in response")
                print(f"[auth] Response: {str(response)[:300]}")
                return None

            protocol = response["sp"]
            salt = response["s"]
            B = response["B"]
            c = response["c"]
            iterations = response["i"]

            if isinstance(salt, str):
                salt = base64.b64decode(salt)
            if isinstance(B, str):
                B = base64.b64decode(B)

            usr.p = self.encrypt_password(password, salt, iterations, protocol)
            M = usr.process_challenge(salt, B)
            if M is None:
                print("[auth] M1 failed")
                return None

            response = self.gsa_request({
                "c": c,
                "M1": M,
                "u": apple_id,
                "o": "complete",
            })

            status = response.get("Status", {})

            if "M2" in response:
                try:
                    usr.verify_session(response["M2"])
                    _ = usr.authenticated()
                except Exception as e:
                    print(f"[auth] Skipping M2: {e}")

            if not getattr(usr, "K", None):
                print("[auth] Missing session key")
                return None
            print(f"[auth] Session key OK (len={len(usr.K)})")

            spd_data = {}
            if "spd" in response:
                try:
                    decrypted_spd = self.decrypt_cbc(usr, response["spd"])
                    spd_data = _safe_plist_loads(decrypted_spd)
                    print(f"[auth] spd OK ({len(spd_data)} keys)")
                except Exception as e:
                    print(f"[auth] spd error: {e}")

            # 2FA detection: hsc, status-code, au, authmode can each carry the
            # signal. authmode may be an int (1) instead of a string, so coerce.
            hsc = status.get("hsc", 200)
            if not isinstance(hsc, int):
                hsc = 200
            spd_status = spd_data.get("status-code")
            spd_authmode_raw = spd_data.get("authmode")
            spd_authmode = spd_authmode_raw if isinstance(spd_authmode_raw, str) else None

            auth_type = (
                status.get("au")
                or response.get("au")
                or spd_data.get("au")
            )
            if not auth_type and spd_authmode and spd_authmode != "password":
                auth_type = spd_authmode
            if not auth_type and (hsc == 409 or spd_status == 409):
                auth_type = spd_authmode or "trustedDeviceSecondaryAuth"

            is_already_sent = (hsc == 409 or spd_status == 409)

            print(f"[2fa] Status.hsc={hsc}, SPD.status-code={spd_status}, "
                  f"Status.au={status.get('au')}, SPD.authmode={spd_authmode}")
            print(f"[auth] auth_type = {auth_type}")

            if auth_type and (
                "SecondaryAuth" in auth_type
                or auth_type in ("secondaryAuth",
                                 "trustedDeviceSecondaryAuth",
                                 "smsSecondaryAuth")
            ):
                if not is_already_sent:
                    time.sleep(2)

                headers_dict = {
                    k.lower(): v
                    for k, v in response.get("_headers", {}).items()
                }
                dsid = (
                    spd_data.get("adsid")
                    or spd_data.get("dsid")
                    or status.get("dsid")
                    or headers_dict.get("x-apple-dsid")
                )
                idms_token = (
                    spd_data.get("GsIdmsToken")
                    or spd_data.get("idmsToken")
                    or status.get("idmsToken")
                )

                if not dsid or not idms_token:
                    print("[2fa] Missing dsid/idms")
                    return None

                print(f"[2fa] DSID: {dsid}")

                if auth_type in ("trustedDeviceSecondaryAuth", "secondaryAuth"):
                    two_fa_ok = self.handle_2fa_trusted_device(dsid, idms_token)
                    if not two_fa_ok:
                        two_fa_ok = self.handle_2fa_sms(dsid, idms_token)
                else:
                    two_fa_ok = self.handle_2fa_sms(dsid, idms_token)
                    if not two_fa_ok:
                        two_fa_ok = self.handle_2fa_trusted_device(dsid, idms_token)

                if not two_fa_ok:
                    print("[2fa] Failed")
                    return None

                # Session key is invalid after 2FA; log in again from scratch.
                if _depth >= 1:
                    print("[2fa] Already retried, continuing")
                else:
                    print("[2fa] OK, retrying login for a fresh session key...")
                    time.sleep(1)
                    return self.authenticate(apple_id, password, _depth=_depth + 1)

            dsid = (
                spd_data.get("adsid")
                or spd_data.get("dsid")
                or response.get("dsid")
            )
            app_session_token = None
            adsid = spd_data.get("adsid") or dsid
            c2 = spd_data.get("c")
            sk = spd_data.get("sk")
            idms = spd_data.get("GsIdmsToken") or spd_data.get("idmsToken")

            if adsid and c2 and sk and idms:
                app_session_token = self.fetch_app_token(
                    adsid, c2, idms, sk
                )

            return {
                "user_id": apple_id,
                "authenticated": True,
                "dsid": dsid,
                "session_token": (
                    app_session_token
                    or spd_data.get("GsIdmsToken")
                    or status.get("idmsToken")
                ),
                "m2": response.get("M2"),
                "srp_user": usr,
            }

        except Exception as e:
            print(f"[auth] Error: {e}")
            traceback.print_exc()
            return None


if __name__ == "__main__":
    import getpass

    print("=== APPLE ID AUTHENTICATION ===")
    aid = input("Apple ID: ").strip()
    pw = getpass.getpass("Password: ")
    if not aid or not pw:
        exit(1)

    auth = AppleAuth()
    result = auth.authenticate(aid, pw)

    print()
    if result and result.get("authenticated"):
        print("*** SUCCESS! ***")
        print(f"  DSID: {result.get('dsid')}")
    else:
        print("*** FAILED ***")


def fetch_official_servers(anisette_url=None):
    return [ANISETTE_URL]


def _get_auth_instance(self):
    return self


def generate_anisette_headers(self):
    return self.get_ani() or {}


def generate_meta_headers_compat(self):
    return self.generate_meta_headers()


AppleAuth.generate_anisette_headers = generate_anisette_headers
AppleAuth.generate_meta_headers_compat = generate_meta_headers_compat
