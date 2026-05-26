from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass

import httpx

from .config import Config

logger = logging.getLogger(__name__)

DEVICE_TYPE_SDK = 22

LOGIN_TYPE = 1
MCP_URI = "mcp-secret://"


class VaultwardenError(Exception):
    pass


class NotFoundError(VaultwardenError):
    pass


class ForbiddenError(VaultwardenError):
    pass


class DuplicateError(VaultwardenError):
    pass


class InternalError(VaultwardenError):
    pass


class ConflictError(VaultwardenError):
    pass


@dataclass(slots=True)
class _Folder:
    id: str
    name: str


@dataclass(slots=True)
class _SecretItem:
    name: str
    password: str


class VaultwardenClient:
    def __init__(self, config: Config):
        self._url = config.vaultwarden_url
        self._client_id = config.client_id
        self._client_secret = config.client_secret
        self._allowed: list[str] | None = config.allowed_folders
        self._device_id = str(uuid.uuid4())

        self._http: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._token_expiry: float = 0

        self._folders: dict[str, _Folder] = {}
        self._folder_loaded = False

        self._retry_lock = asyncio.Lock()

    async def _get_http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        return self._http

    # -- auth ----------------------------------------------------------------

    async def _exchange_token(self) -> None:
        logger.info("Exchanging client credentials for access token")
        http = await self._get_http()
        try:
            resp = await http.post(
                f"{self._url}/identity/connect/token",
                content=(
                    f"grant_type=client_credentials"
                    f"&client_id={self._client_id}"
                    f"&client_secret={self._client_secret}"
                    f"&scope=api"
                    f"&device_identifier={self._device_id}"
                    f"&device_name=vaultwarden-mcp"
                    f"&device_type={DEVICE_TYPE_SDK}"
                ),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as e:
            raise InternalError(f"Token exchange failed: {e}") from e

        self._token = data["access_token"]
        expires_in = data.get("expires_in", 7200)
        self._token_expiry = time.time() + expires_in
        logger.info("Token obtained, expires in %d seconds", expires_in)

    async def _access_token(self) -> str:
        if self._token is not None and time.time() < self._token_expiry - 300:
            return self._token

        async with self._retry_lock:
            if self._token is not None and time.time() < self._token_expiry - 300:
                return self._token

            for attempt in range(3):
                try:
                    await self._exchange_token()
                    return self._token
                except InternalError:
                    if attempt == 2:
                        raise
                    wait = 5 * (2 ** attempt)
                    logger.warning("Token exchange attempt %d failed, retrying in %ds", attempt + 1, wait)
                    await asyncio.sleep(wait)
            raise InternalError("Token exchange failed after 3 attempts")

    def _auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    # -- folders -------------------------------------------------------------

    async def _load_folders(self) -> None:
        token = await self._access_token()
        http = await self._get_http()
        try:
            resp = await http.get(
                f"{self._url}/api/folders",
                headers=self._auth_headers(token),
            )
            resp.raise_for_status()
            body = resp.json()
            folder_list = body.get("data") or body.get("Data") or []
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to load folders: {e}") from e

        self._folders = {}
        for f in folder_list:
            fid = f.get("id") or f.get("Id")
            name = f.get("name") or f.get("Name") or ""
            if not name or not fid:
                continue
            if name not in self._folders:
                self._folders[name] = _Folder(id=fid, name=name)
        self._folder_loaded = True
        logger.info("Loaded %d folders", len(self._folders))

    async def _ensure_folders(self) -> None:
        if not self._folder_loaded:
            await self._load_folders()

    def _resolve_folder(self, folder_name: str) -> _Folder | None:
        return self._folders.get(folder_name)

    # -- ciphers / secrets ---------------------------------------------------

    async def _fetch_all_ciphers(self) -> list[dict]:
        token = await self._access_token()
        http = await self._get_http()
        all_items: list[dict] = []
        url = f"{self._url}/api/ciphers"

        while url:
            try:
                resp = await http.get(url, headers=self._auth_headers(token))
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPError as e:
                raise InternalError(f"Failed to fetch ciphers: {e}") from e

            all_items.extend(data.get("data") or data.get("Data") or [])
            url = data.get("continuationToken") or data.get("ContinuationToken")
            if url:
                if not url.startswith("http"):
                    url = f"{self._url}{url}"

        return all_items

    @staticmethod
    def _is_mcp_secret(item: dict) -> bool:
        if item.get("type") != LOGIN_TYPE:
            return False
        if not item.get("folderId"):
            return False
        login = item.get("login") or {}
        uris = login.get("uris") or []
        for u in uris:
            if u.get("uri") == MCP_URI:
                return True
        return False

    @staticmethod
    def _item_password(item: dict) -> str:
        login = item.get("login") or {}
        return login.get("password") or ""

    # -- tool operations -----------------------------------------------------

    async def _all_secrets(self) -> dict[str, list[_SecretItem]]:
        await self._ensure_folders()
        ciphers = await self._fetch_all_ciphers()

        folder_id_to_name: dict[str, str] = {}
        for f in self._folders.values():
            folder_id_to_name[f.id] = f.name

        result: dict[str, list[_SecretItem]] = {}
        for item in ciphers:
            if not self._is_mcp_secret(item):
                continue
            folder_id = item["folderId"]
            folder_name = folder_id_to_name.get(folder_id)
            if folder_name is None:
                continue
            if folder_name not in result:
                result[folder_name] = []
            result[folder_name].append(
                _SecretItem(name=item["name"], password=self._item_password(item))
            )

        return result

    async def get_secret(self, folder: str, item_name: str) -> str:
        if self._allowed is not None and folder not in self._allowed:
            raise ForbiddenError(f"Folder not in allowed_folders: {folder}")

        await self._ensure_folders()
        f = self._resolve_folder(folder)
        if f is None:
            raise NotFoundError(f"Folder not found: {folder}")

        ciphers = await self._fetch_all_ciphers()
        matches: list[dict] = []
        for item in ciphers:
            if not self._is_mcp_secret(item):
                continue
            if item.get("folderId") != f.id:
                continue
            if item["name"] == item_name:
                matches.append(item)

        if len(matches) == 0:
            raise NotFoundError(f"Item not found: {item_name}")
        if len(matches) > 1:
            raise DuplicateError(f"Multiple items named '{item_name}' in folder '{folder}'")

        return self._item_password(matches[0])

    async def list_secrets(self, folder: str | None = None) -> list[dict]:
        if folder is not None:
            if self._allowed is not None and folder not in self._allowed:
                return []

            await self._ensure_folders()
            f = self._resolve_folder(folder)
            if f is None:
                return []

            ciphers = await self._fetch_all_ciphers()
            item_names: list[str] = []
            for item in ciphers:
                if not self._is_mcp_secret(item):
                    continue
                if item.get("folderId") == f.id:
                    item_names.append(item["name"])
            return [] if not item_names else [{"folder": folder, "items": item_names}]

        secrets = await self._all_secrets()
        result: list[dict] = []
        for folder_name, items in sorted(secrets.items()):
            if self._allowed is not None and folder_name not in self._allowed:
                continue
            if not items:
                continue
            result.append({"folder": folder_name, "items": sorted(i.name for i in items)})
        return result

    # -- mutations (write tools) ---------------------------------------------

    def _check_allowed(self, folder: str) -> None:
        if self._allowed is not None and folder not in self._allowed:
            raise ForbiddenError(f"Folder not in allowed_folders: {folder}")

    async def _require_folder(self, folder: str) -> _Folder:
        self._check_allowed(folder)
        await self._ensure_folders()
        f = self._resolve_folder(folder)
        if f is None:
            raise NotFoundError(f"Folder not found: {folder}")
        return f

    async def _find_item(self, folder_id: str, item_name: str) -> dict:
        ciphers = await self._fetch_all_ciphers()
        matches = [
            c for c in ciphers
            if c.get("folderId") == folder_id
            and c["name"] == item_name
            and not c.get("deletedDate")
        ]
        if len(matches) == 0:
            raise NotFoundError(f"Item not found: {item_name}")
        if len(matches) > 1:
            raise DuplicateError(f"Multiple items named '{item_name}'")
        return matches[0]

    async def add_secret(self, folder: str, item_name: str, value: str) -> None:
        f = await self._require_folder(folder)
        try:
            await self._find_item(f.id, item_name)
            raise ConflictError(f"Item already exists: {item_name}")
        except NotFoundError:
            pass

        token = await self._access_token()
        http = await self._get_http()
        payload = {
            "type": LOGIN_TYPE,
            "folderId": f.id,
            "name": item_name,
            "login": {
                "username": item_name.lower(),
                "password": value,
                "uris": [{"uri": MCP_URI, "match": None}],
            },
        }
        try:
            resp = await http.post(
                f"{self._url}/api/ciphers",
                headers=self._auth_headers(token),
                json=payload,
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to create secret: {e}") from e

    async def edit_secret(self, folder: str, item_name: str, value: str) -> None:
        f = await self._require_folder(folder)
        item = await self._find_item(f.id, item_name)
        if not self._is_mcp_secret(item):
            raise NotFoundError(f"Item not an MCP secret: {item_name}")

        token = await self._access_token()
        http = await self._get_http()
        login = item.get("login") or {}
        login["password"] = value
        payload = {
            "type": item["type"],
            "folderId": item["folderId"],
            "name": item["name"],
            "login": login,
        }
        try:
            resp = await http.put(
                f"{self._url}/api/ciphers/{item['id']}",
                headers=self._auth_headers(token),
                json=payload,
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to update secret: {e}") from e

    async def delete_secret(self, folder: str, item_name: str) -> None:
        f = await self._require_folder(folder)
        item = await self._find_item(f.id, item_name)
        token = await self._access_token()
        http = await self._get_http()
        try:
            resp = await http.put(
                f"{self._url}/api/ciphers/{item['id']}/delete",
                headers=self._auth_headers(token),
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to delete secret: {e}") from e

    async def recover_secret(self, folder: str, item_name: str) -> None:
        self._check_allowed(folder)
        await self._ensure_folders()
        f = self._resolve_folder(folder)
        if f is None:
            raise NotFoundError(f"Folder not found: {folder}")

        ciphers = await self._fetch_all_ciphers()
        matches = [
            c for c in ciphers
            if c.get("folderId") == f.id and c["name"] == item_name
        ]
        if len(matches) == 0:
            raise NotFoundError(f"Item not found in trash: {item_name}")

        token = await self._access_token()
        http = await self._get_http()
        try:
            resp = await http.put(
                f"{self._url}/api/ciphers/{matches[0]['id']}/restore",
                headers=self._auth_headers(token),
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to recover secret: {e}") from e

    async def add_folder(self, folder: str) -> None:
        self._check_allowed(folder)
        await self._ensure_folders()
        if folder in self._folders:
            raise ConflictError(f"Folder already exists: {folder}")

        token = await self._access_token()
        http = await self._get_http()
        try:
            resp = await http.post(
                f"{self._url}/api/folders",
                headers=self._auth_headers(token),
                json={"name": folder},
            )
            resp.raise_for_status()
            data = resp.json()
            fid = data.get("id") or data.get("Id")
            self._folders[folder] = _Folder(id=fid, name=folder)
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to create folder: {e}") from e

    async def delete_folder(self, folder: str) -> None:
        self._check_allowed(folder)
        await self._ensure_folders()
        f = self._resolve_folder(folder)
        if f is None:
            raise NotFoundError(f"Folder not found: {folder}")

        ciphers = await self._fetch_all_ciphers()
        for c in ciphers:
            if c.get("folderId") == f.id:
                raise ConflictError(f"Folder not empty: {folder}")

        token = await self._access_token()
        http = await self._get_http()
        try:
            resp = await http.delete(
                f"{self._url}/api/folders/{f.id}",
                headers=self._auth_headers(token),
            )
            resp.raise_for_status()
            del self._folders[folder]
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to delete folder: {e}") from e

    async def list_trash(self) -> list[dict]:
        await self._ensure_folders()
        ciphers = await self._fetch_all_ciphers()
        folder_id_to_name = {f.id: f.name for f in self._folders.values()}
        result = []
        for item in ciphers:
            if not item.get("deletedDate"):
                continue
            if not self._is_mcp_secret(item):
                continue
            fid = item.get("folderId")
            fname = folder_id_to_name.get(fid, "(no folder)")
            if self._allowed is not None and fname not in self._allowed:
                continue
            result.append({
                "folder": fname,
                "name": item["name"],
                "deletedDate": item["deletedDate"],
            })
        return result

    # -- startup -------------------------------------------------------------

    async def validate(self) -> None:
        token = await self._access_token()
        http = await self._get_http()
        try:
            resp = await http.get(
                f"{self._url}/api/accounts/revision-date",
                headers=self._auth_headers(token),
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise InternalError(f"Vaultwarden unreachable: {e}") from e

        await self._load_folders()

        for folder_name in (self._allowed or []):
            if folder_name not in self._folders:
                logger.warning("Folder %r in allowed_folders not found in Vaultwarden", folder_name)

    async def close(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None
