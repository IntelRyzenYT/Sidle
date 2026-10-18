#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Entitlements manager: wraps DeveloperAPI to handle App Groups, profile
# download, and entitlements extraction. Kept separate from developer_api.py
# so the core client stays stable while we iterate on this layer.

import base64
import plistlib
import time
from typing import Any, Dict, List, Optional

from developer_api import DeveloperAPI, DeveloperAPIError


class EntitlementsManager:
    def __init__(self, dev_api: DeveloperAPI, team_id: str):
        self.api = dev_api
        self.api.set_team(team_id)
        self.team_id = team_id

        # App Groups (QH65B2 plist)

    def list_app_groups(self):
        # QH65B2 returns key "applicationGroupList", not applicationGroups.
        data = self.api._request_plist(
            "ios/listApplicationGroups.action", {}, require_team=True
        )
        raw = (
            data.get("applicationGroupList")
            or data.get("applicationGroups")
            or data.get("appGroups")
            or []
        )
        return [g for g in raw if isinstance(g, dict)]

    def ensure_app_group(self, identifier=None, name=None, bundle_id=None, is_sidestore_lc=False):
        if not identifier:
            if is_sidestore_lc:
                identifier = "group.com.SideStore.SideStore." + self.team_id
            elif bundle_id:
                identifier = "group." + bundle_id
            else:
                identifier = "group.com.sidedroid." + self.team_id
        if not name:
            name = "App Group for " + self.team_id
        for g in self.list_app_groups():
            gid = g.get("identifier") or g.get("applicationGroup")
            if gid == identifier:
                print("[entmgr] App Group exists: " + identifier)
                return g
        print("[entmgr] Creating App Group: " + identifier)
        return self.create_app_group(identifier, name)

    def create_app_group(self, identifier: str, name: str) -> Dict[str, Any]:
        return self.api._request_plist(
            "ios/addApplicationGroup.action",
            {"identifier": identifier, "name": name},
            require_team=True,
        )

    def enable_app_group_feature(self, app_id_id: str) -> Dict[str, Any]:
        # APG3427HIY is Apple's internal feature code for App Groups.
        return self.api._request_plist(
            "ios/updateAppId.action",
            {"appIdId": app_id_id, "APG3427HIY": True},
            require_team=True,
        )

    def assign_app_group(self, app_id_id, group):
        # Apple wants the internal applicationGroup ID (R272AQMN48),
        # not the identifier (group.com.xxx). Accept both.
        if isinstance(group, dict):
            group_id = group.get("applicationGroup")
            if not group_id:
                group_id = group.get("identifier")
        else:
            group_id = group
            if isinstance(group_id, str) and group_id.startswith("group."):
                for g in self.list_app_groups():
                    if g.get("identifier") == group_id:
                        group_id = g.get("applicationGroup") or group_id
                        break

        if not group_id or group_id.startswith("group."):
            raise DeveloperAPIError("Cannot resolve App Group ID: " + str(group_id))

        print("[entmgr] assign_app_group using ID: " + str(group_id))
        return self.api._request_plist(
            "ios/assignApplicationGroupToAppId.action",
            {
                "appIdId": app_id_id,
                "applicationGroups": group_id,
            },
            require_team=True,
        )

    def add_increased_memory_limit(self, app_id_id: str) -> Dict[str, Any]:
        return self.api._request_plist(
            "ios/enableAppIdFeature.action",
            {"appIdId": app_id_id, "features": ["INCREASED_MEMORY_LIMIT"]},
            require_team=True,
        )

    # Provisioning profile download (QH65B2 plist, with retries)

    def download_profile(self, app_id_id: str) -> bytes:
        delays = [3, 5, 7]
        last_err: Optional[Exception] = None

        for i, delay in enumerate(delays):
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
                        if isinstance(encoded, bytes):
                            return encoded
                        return base64.b64decode(encoded)
                last_err = DeveloperAPIError(
                    "Missing provisioningProfile, resultCode="
                    + str(resp.get("resultCode"))
                )
            except DeveloperAPIError as e:
                last_err = e

            if i < len(delays) - 1:
                print(
                    "[entmgr] Profile attempt "
                    + str(i + 1)
                    + "/"
                    + str(len(delays))
                    + " failed, retry in "
                    + str(delay)
                    + "s"
                )
                time.sleep(delay)

        raise last_err or DeveloperAPIError("Profile download failed")
    # Full flow: enable + assign + wait + download + extract
    def prepare_app_with_group(
        self,
        app_id_id: str,
        bundle_id: str,
        group: Union[str, Dict[str, Any]],
    ) -> bytes:
        """Enable App Group feature on App ID, assign group, wait, download
        profile, and return raw profile bytes.

        group can be either:
          - dict returned by ensure_app_group/create_app_group
          - str with the internal 'applicationGroup' ID (PD23MQPPXW)
          - str with the identifier (group.com.xxx) - will be resolved
        """
        if isinstance(group, dict):
            gid = group.get("applicationGroup") or group.get("identifier")
            label = str(gid)
        else:
            label = str(group)

        print("[entmgr] Step 1: enable App Group feature")
        self.enable_app_group_feature(app_id_id)

        print("[entmgr] Step 2: assign group " + label)
        self.assign_app_group(app_id_id, group)

        print("[entmgr] Step 3: wait 5s for Apple to propagate")
        time.sleep(5)

        print("[entmgr] Step 4: download profile")
        return self.download_profile(app_id_id)

    # Entitlements extraction

    @staticmethod
    def extract_entitlements(
        profile_bytes: bytes,
        team_id: str,
        bundle_id: str,
    ) -> Dict[str, Any]:
        s = profile_bytes.find(b"<plist")
        e = profile_bytes.rfind(b"</plist>")
        if s < 0 or e < 0:
            raise DeveloperAPIError("Profile has no plist section")

        parsed = plistlib.loads(profile_bytes[s:e + 8])
        entitlements = dict(parsed.get("Entitlements", {}))
        if not entitlements:
            raise DeveloperAPIError("Profile has no Entitlements section")

        new_app_id = team_id + "." + bundle_id
        entitlements["application-identifier"] = new_app_id

        is_lc = "livecontainer" in bundle_id.lower()
        if is_lc:
            groups = [
                new_app_id,
                team_id + ".com.kdt.livecontainer.shared",
                team_id + ".com.kdt.livecontainer",
            ]
            for i in range(1, 129):
                groups.append(
                    team_id + ".com.kdt.livecontainer.shared." + str(i)
                )
            entitlements["keychain-access-groups"] = groups
        else:
            existing = entitlements.get("keychain-access-groups") or []
            should_override = True
            if existing and isinstance(existing, list):
                first = existing[0] if existing else ""
                if isinstance(first, str) and (
                    first == "*" or first.endswith(".*")
                ):
                    should_override = False
            if should_override:
                entitlements["keychain-access-groups"] = [new_app_id]

        return entitlements


if __name__ == "__main__":
    print("Run test_entitlements.py to exercise this module.")
