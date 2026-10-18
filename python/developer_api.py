#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Developer Portal client matching fortiva's transport. Uses QH65B2 plist API
# for teams/devices/appids/profiles and v1 JSON API for certificates.
# Auth: X-Apple-I-Identity-Id (dsid) + X-Apple-GS-Token (app token).

import json
import logging
import plistlib
import time
import uuid
from typing import Any, Dict, Iterable, List, Mapping, Optional, Union

import requests


_LOG = logging.getLogger(__name__)

BASE_URL_QH65B2 = "https://developerservices2.apple.com/services/QH65B2"
BASE_URL_V1 = "https://developerservices2.apple.com/services/v1"
CLIENT_ID = "XABBG36SBA"
PROTOCOL_VERSION = "QH65B2"
XCODE_VERSION = "14.2 (14C18)"

JsonDict = Dict[str, Any]


class DeveloperAPIError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        response: Optional[Any] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response = response
        self.payload = dict(payload or {})


class DeveloperAPI:
    def __init__(
        self,
        auth: Any,
        dsid: Union[str, int],
        session_token: str,
        *,
        team_id: Optional[str] = None,
        timeout: int = 30,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.auth = auth
        self.dsid = str(dsid)
        self.session_token = session_token
        self.team_id = team_id
        self.timeout = timeout

        self.session = session or requests.Session()
        self.session.verify = False
        self.session.trust_env = False

    # Headers and transport
    def _build_headers(self, content_type: str = "text/x-xml-plist") -> Dict[str, str]:
        headers = {
            "Content-Type": content_type,
            "Accept": content_type,
            "User-Agent": "Xcode",
            "Accept-Language": "en-us",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": XCODE_VERSION,
            "X-Apple-I-Identity-Id": self.dsid,
            "X-Apple-GS-Token": self.session_token,
            "Connection": "close",
        }

        anisette = self.auth.get_ani() or {}
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

        client_info = getattr(self.auth, "client_info", None) or anisette.get("X-MMe-Client-Info")
        if client_info:
            headers["X-Mme-Client-Info"] = client_info

        return headers

    def _request_plist(
        self,
        action: str,
        extra_params: Optional[Mapping[str, Any]] = None,
        *,
        require_team: bool = False,
    ) -> JsonDict:
        params: JsonDict = {
            "clientId": CLIENT_ID,
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": str(uuid.uuid4()).upper(),
            "userLocale": ["en_US"],
        }
        if require_team:
            if not self.team_id:
                raise DeveloperAPIError("No team selected. Call set_team() first.")
            params["teamId"] = self.team_id
        if extra_params:
            params.update(extra_params)

        url = f"{BASE_URL_QH65B2}/{action}?clientId={CLIENT_ID}"
        body = plistlib.dumps(params, fmt=plistlib.FMT_XML)

        last_error: Optional[Exception] = None
        for attempt in range(2):
            headers = self._build_headers("text/x-xml-plist")
            try:
                resp = self.session.post(url, data=body, headers=headers, timeout=self.timeout)
            except requests.RequestException as exc:
                last_error = exc
                if attempt == 0:
                    time.sleep(2)
                    continue
                raise DeveloperAPIError(f"Request failed: {exc}") from exc

            if resp.status_code >= 500 and attempt == 0:
                time.sleep(2)
                continue

            if not resp.ok:
                raise DeveloperAPIError(
                    f"HTTP {resp.status_code}: {resp.text[:300]}",
                    status_code=resp.status_code,
                    response=resp,
                )

            try:
                result = plistlib.loads(resp.content)
            except Exception as exc:
                raise DeveloperAPIError(
                    f"Invalid plist response: {resp.content[:200]!r}",
                    status_code=resp.status_code,
                    response=resp,
                ) from exc

            if not isinstance(result, dict):
                raise DeveloperAPIError("Response is not a dictionary", payload=result)

            result_code = result.get("resultCode", 0)
            try:
                result_code_int = int(result_code) if result_code is not None else 0
            except (TypeError, ValueError):
                result_code_int = 0

            if result_code_int == 1100 and attempt == 0:
                # Anisette expired. Clear cache and retry once.
                self.auth._cached_ani = None
                continue

            if result_code_int != 0:
                user_string = result.get("userString", "") or result.get("resultString", "")
                raise DeveloperAPIError(
                    user_string or f"resultCode={result_code_int}",
                    payload=result,
                )

            return result

        raise DeveloperAPIError("Request failed after retries") from last_error

    def _request_json(
        self,
        method_override: str,
        url: str,
        query: str,
        body: Optional[JsonDict] = None,
    ) -> Optional[JsonDict]:
        headers = self._build_headers("application/vnd.api+json")
        headers["X-HTTP-Method-Override"] = method_override

        if body is not None:
            payload = body
        else:
            payload = {"urlEncodedQueryParams": query}

        try:
            resp = self.session.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise DeveloperAPIError(f"JSON request failed: {exc}") from exc

        if not resp.ok:
            raise DeveloperAPIError(
                f"JSON API HTTP {resp.status_code}: {resp.text[:300]}",
                status_code=resp.status_code,
                response=resp,
            )

        if not resp.content:
            return None

        try:
            return json.loads(resp.content)
        except Exception as exc:
            raise DeveloperAPIError(
                f"JSON parse error: {exc}, raw={resp.content[:200]!r}",
                status_code=resp.status_code,
                response=resp,
            ) from exc

    @staticmethod
    def _items(data: Mapping[str, Any], *keys: str) -> List[JsonDict]:
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
        return []

     # Teams
    def list_teams(self) -> List[JsonDict]:
        data = self._request_plist("listTeams.action")
        return self._items(data, "teams", "teamList")

    def set_team(self, team_id: str) -> str:
        if not team_id or not str(team_id).strip():
            raise ValueError("team_id cannot be empty")
        self.team_id = str(team_id).strip()
        return self.team_id

   # Devices
    def list_devices(self) -> List[JsonDict]:
        if not self.team_id:
            raise DeveloperAPIError("No team selected. Call set_team() first.")
        url = f"{BASE_URL_V1}/devices"
        query = f"teamId={self.team_id}"
        resp = self._request_json("GET", url, query)
        if not resp:
            return []
        data = resp.get("data", [])
        return [x for x in data if isinstance(x, dict)]

    def register_device(self, name: str, udid: str) -> JsonDict:
        import urllib.parse
        if not self.team_id:
            raise DeveloperAPIError("No team selected. Call set_team() first.")
        name = str(name).strip()
        udid = str(udid).strip().upper()
        if not name or not udid:
            raise ValueError("name and udid are required")

        url = f"{BASE_URL_V1}/devices"
        query = urllib.parse.urlencode({
            "teamId": self.team_id,
            "name": name,
            "udid": udid,
            "platform": "IOS",
        })
        return self._request_json("POST", url, query) or {}

    # Certificates (JSON v1 API with plist fallback)
    def list_certificates(self) -> List[JsonDict]:
        if not self.team_id:
            raise DeveloperAPIError("No team selected. Call set_team() first.")

        url = f"{BASE_URL_V1}/certificates"
        query = f"teamId={self.team_id}"
        resp = self._request_json("GET", url, query)
        if not resp:
            return []
        data = resp.get("data", [])
        return [x for x in data if isinstance(x, dict)]

    def revoke_certificate(self, certificate_id: str) -> bool:
        import urllib.parse
        if not self.team_id:
            raise DeveloperAPIError("No team selected. Call set_team() first.")
        if not certificate_id:
            raise ValueError("certificate_id cannot be empty")

        url = f"{BASE_URL_V1}/certificates/{certificate_id}"
        query = urllib.parse.urlencode({"teamId": self.team_id})
        try:
            self._request_json("DELETE", url, query)
            return True
        except DeveloperAPIError as e:
            print(f"[devapi] revoke failed: {e}")
            return False

    def create_certificate(
        self,
        name: str,
        csr_pem: Union[str, bytes],
        certificate_type: str = "IOS_DEVELOPMENT",
    ) -> JsonDict:
        import urllib.parse
        if not self.team_id:
            raise DeveloperAPIError("No team selected. Call set_team() first.")
        if isinstance(csr_pem, bytes):
            csr_text = csr_pem.decode("utf-8", errors="strict")
        else:
            csr_text = str(csr_pem)
        csr_text = csr_text.strip()
        if "BEGIN CERTIFICATE REQUEST" not in csr_text:
            raise ValueError("csr_pem must contain a PEM CERTIFICATE REQUEST")

        url = f"{BASE_URL_V1}/certificates"
        query = urllib.parse.urlencode({
            "teamId": self.team_id,
            "csrContent": csr_text,
            "certificateType": certificate_type,
            "name": str(name).strip(),
        })
        return self._request_json("POST", url, query) or {}

    # App IDs
    def list_app_ids(self) -> List[JsonDict]:
        if not self.team_id:
            raise DeveloperAPIError("No team selected. Call set_team() first.")
        url = f"{BASE_URL_V1}/bundleIds"
        query = f"teamId={self.team_id}"
        resp = self._request_json("GET", url, query)
        if not resp:
            return []
        data = resp.get("data", [])
        return [x for x in data if isinstance(x, dict)]

    def create_app_id(self, bundle_id: str, app_name: str) -> JsonDict:
        import urllib.parse
        if not self.team_id:
            raise DeveloperAPIError("No team selected. Call set_team() first.")
        if "." not in bundle_id:
            raise ValueError("bundle_id must be reverse-DNS")

        url = f"{BASE_URL_V1}/bundleIds"
        query = urllib.parse.urlencode({
            "teamId": self.team_id,
            "identifier": str(bundle_id).strip(),
            "name": str(app_name).strip(),
            "platform": "IOS",
        })
        return self._request_json("POST", url, query) or {}

    # Provisioning profiles

    def create_provisioning_profile(
        self,
        bundle_id: str,
        *,
        certificate_ids: Optional[Iterable[str]] = None,
        device_ids: Optional[Iterable[str]] = None,
        profile_name: Optional[str] = None,
        profile_type: str = "IOS_APP_DEVELOPMENT",
    ) -> JsonDict:
        import urllib.parse
        if not self.team_id:
            raise DeveloperAPIError("No team selected. Call set_team() first.")

        url = f"{BASE_URL_V1}/profiles"
        params = {
            "teamId": self.team_id,
            "bundleId": str(bundle_id).strip(),
            "name": profile_name or f"Sidle {bundle_id}",
            "profileType": profile_type,
        }
        certs = list(certificate_ids or [])
        devices = list(device_ids or [])
        if certs:
            params["certificateIds"] = ",".join(certs)
        if devices:
            params["deviceIds"] = ",".join(devices)

        query = urllib.parse.urlencode(params)
        return self._request_json("POST", url, query) or {}

    def download_profile_content(self, profile_id: str) -> bytes:
        import base64
        if not self.team_id:
            raise DeveloperAPIError("No team selected. Call set_team() first.")
        url = f"{BASE_URL_V1}/profiles/{profile_id}"
        query = f"teamId={self.team_id}"
        resp = self._request_json("GET", url, query)
        if not resp:
            raise DeveloperAPIError("Empty profile response")

        attrs = resp.get("data", {}).get("attributes", {})
        content = attrs.get("profileContent")
        if not content:
            raise DeveloperAPIError("No profileContent in response", payload=resp)
        try:
            return base64.b64decode(content)
        except Exception:
            return content.encode("utf-8")

    def list_profiles(self) -> List[JsonDict]:
        if not self.team_id:
            raise DeveloperAPIError("No team selected. Call set_team() first.")
        url = f"{BASE_URL_V1}/profiles"
        query = f"teamId={self.team_id}"
        resp = self._request_json("GET", url, query)
        if not resp:
            return []
        return [x for x in resp.get("data", []) if isinstance(x, dict)]

       # Utilities
    @staticmethod
    def generate_csr(common_name: str = "Sidle") -> bytes:
        """Generate an RSA-2048 CSR in PEM format."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]))
            .sign(key, hashes.SHA256())
        )
        return csr.public_bytes(serialization.Encoding.PEM)

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "DeveloperAPI":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


if __name__ == "__main__":
    # Quick self-test: authenticate, list teams, set first team, list devices.
    import getpass
    from auth import AppleAuth

    print("=== DEVELOPER API TEST ===")
    aid = input("Apple ID: ").strip()
    pw = getpass.getpass("Password: ")

    auth = AppleAuth()
    res = auth.authenticate(aid, pw)
    if not res or not res.get("authenticated"):
        print("Login failed")
        raise SystemExit(1)

    token = res.get("session_token")
    if not token:
        print("No app token in login result, cannot test Developer API")
        raise SystemExit(1)

    api = DeveloperAPI(auth, dsid=res["dsid"], session_token=token)

    teams = api.list_teams()
    print(f"Teams: {len(teams)}")
    for t in teams:
        print(f"  {t.get('teamId')}  {t.get('name')}")

    if teams:
        api.set_team(teams[0]["teamId"])
        devices = api.list_devices()
        print(f"Devices: {len(devices)}")
        certs = api.list_certificates()
        print(f"Certificates: {len(certs)}")
