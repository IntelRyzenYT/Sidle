import base64
import plistlib
import time
from typing import Any, Dict, List, Optional, Union

from developer_api import DeveloperAPI, DeveloperAPIError

class EntitlementsManager:
    """
    Strictly focuses on communicating with the Apple Developer API 
    to manage App Groups and fetch provisioning profiles.
    """
    def __init__(self, dev_api: DeveloperAPI, team_id: str):
        self.api = dev_api
        self.api.set_team(team_id)
        self.team_id = team_id

    # App Groups (QH65B2 plist)

    def list_app_groups(self) -> List[Dict[str, Any]]:
        data = self.api._request_plist(
            "ios/listApplicationGroups.action", {}, require_team=True
        )
        return data.get("applicationGroupList", [])

    def create_app_group(self, identifier: str, name: str) -> Dict[str, Any]:
        return self.api._request_plist(
            "ios/addApplicationGroup.action",
            {"identifier": identifier, "name": name},
            require_team=True,
        )

    def ensure_app_group(self, identifier: str, name: str) -> Dict[str, Any]:
        """
        Idempotent lookup and create. 
        Caller must explicitly provide the full identifier.
        """
        for g in self.list_app_groups():
            if g.get("identifier") == identifier:
                print(f"[entmgr] App Group exists: {identifier}")
                return g
        
        print(f"[entmgr] Creating App Group: {identifier
        
}")
        return self.create_app_group(identifier, name)

    def enable_app_group_feature(self, app_id_id: str) -> Dict[str, Any]:
        # Enables the APG3427HIY (App Groups) capability on the App ID.
        return self.api._request_plist(
            "ios/updateAppId.action",
            {"appIdId": app_id_id, "APG3427HIY": True},
            require_team=True,
        )

    def assign_app_group(self, app_id_id: str, group: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Assigns the App Group to the App ID. 
        Accepts either the group dictionary or its internal ID string.
        """
        group_id = group.get("applicationGroup") if isinstance(group, dict) else group        # If the caller mistakenly passed the identifier (group.xxx), resolve it to the internal ID.
        if isinstance(group_id, str) and group_id.startswith("group."):
            for g in self.list_app_groups():
                if g.get("identifier") == group_id:
                    group_id = g.get("applicationGroup")
                    break

        if not group_id:
            raise DeveloperAPIError("Cannot resolve App Group ID")

        return self.api._request_plist(
            "ios/assignApplicationGroupToAppId.action",
            {"appIdId": app_id_id, "applicationGroups": group_id},
            require_team=True,
        )

    # Profile Download with Polling

    def download_profile(self, app_id_id: str, max_retries: int = 5, delay: int = 3) -> bytes:
        """
        Polls Apple for the updated provisioning profile.
        Replaces hardcoded sleep to handle Apple's inconsistent propagation times.
        """
        last_err = None
        
        for attempt in range(max_retries):
            try:
                resp = self.api._request_plist(
                    "ios/downloadTeamProvisioningProfile.action",
                    {"appIdId": app_id_id},
                    require_team=True,
                )
                profile = resp.get("provisioningProfile")
                
                if isinstance(profile, dict):
                    encoded = (
                        profile.get("encodedProfile")
                        or profile.get("content")
                        or profile.get("profileContent")
                    )
                    if encoded:
                        return base64.b64decode(encoded) if isinstance(encoded, str) else encoded
                
                raise DeveloperAPIError("Response missing encoded profile data")
                
            except DeveloperAPIError as e:
                last_err = e
                if attempt < max_retries - 1:
                    print(f"[entmgr] Profile not ready (attempt {attempt + 1}/{max_retries}). Waiting {delay}s...")
                    time.sleep(delay)
                    # Force anisette refresh to ensure the next request isn't using a stale session
                    self.api.auth._cached_ani = None

        raise DeveloperAPIError(f"Failed to download profile after {max_retries} attempts: {last_err}")

    # Entitlements Parsing

    @staticmethod
    def extract_entitlements(profile_bytes: bytes) -> Dict[str, Any]:
        """
        Extracts the raw Entitlements dictionary from the CMS profile.
        Does NOT inject app specific logic or keychain groups.
        """
        start = profile_bytes.find(b"<plist")
        end = profile_bytes.rfind(b"</plist>")
        
        if start == -1 or end == -1:
            raise DeveloperAPIError("Profile has no plist section")

        try:
            parsed = plistlib.loads(profile_bytes[start:end + 8])
        except Exception as e:
            raise DeveloperAPIError(f"Failed to parse profile plist: {e}")

        entitlements = parsed.get("Entitlements")
        if not entitlements:
            raise DeveloperAPIError("Profile has no Entitlements section")
        
        return entitlements


# PATCHER LAYER (Decoupled from API Wrapper)

def patch_entitlements(
    entitlements: Dict[str, Any], 
    team_id: str, 
    bundle_id: str, 
    is_livecontainer: bool = False
) -> Dict[str, Any]:
    """
    Mutates the raw entitlements dict in memory to match the sideloaded app identity.
    This handles the app specific hacks outside of the EntitlementsManager class.
    """
    new_app_id = f"{team_id}.{bundle_id}"
    
    # 1. Override application identifier to match the new signing identity
    entitlements["application-identifier"] = new_app_id

    # 2. Override keychain access groups
    if is_livecontainer:
        # LiveContainer specific hack: inject 128 sub groups
        groups = [
            new_app_id,
            f"{team_id}.com.kdt.livecontainer.shared",
            f"{team_id}.com.kdt.livecontainer",
        ]
        for i in range(1, 129):
            groups.append(f"{team_id}.com.kdt.livecontainer.shared.{i}")
        entitlements["keychain-access-groups"] = groups
    else:
        # Standard app: enforce new_app_id unless wildcard exists
        existing = entitlements.get("keychain-access-groups", [])
        should_override = True
        if existing and isinstance(existing, list):
            first = existing[0] if existing else ""
            if isinstance(first, str) and (first == "*" or first.endswith(".*")):
                should_override = False
                
        if should_override:
            entitlements["keychain-access-groups"] = [new_app_id]

    return entitlements
