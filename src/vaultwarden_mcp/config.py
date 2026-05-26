from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class Config:
    vaultwarden_url: str
    client_id: str
    client_secret: str
    allowed_folders: list[str] | None = None

    @classmethod
    def from_path(cls, path: str) -> Config:
        expanded = Path(os.path.expanduser(os.path.expandvars(path)))
        data: dict = {}
        if expanded.exists():
            try:
                data = json.loads(expanded.read_text())
            except (OSError, json.JSONDecodeError) as e:
                raise SystemExit(f"Cannot read config: {e}")

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> Config:
        url = os.environ.get("VAULTWARDEN_URL", str(data.get("vaultwarden_url", ""))).rstrip("/")
        if not url:
            raise SystemExit("Missing vaultwarden_url (set VAULTWARDEN_URL or config.json)")

        client_id = os.environ.get("VAULTWARDEN_CLIENT_ID") or str(data.get("client_id", ""))
        client_secret = os.environ.get("VAULTWARDEN_CLIENT_SECRET") or str(data.get("client_secret", ""))
        if not client_id or not client_secret:
            raise SystemExit("Missing client_id/client_secret (set VAULTWARDEN_CLIENT_ID/_SECRET or config.json)")

        allowed = data.get("allowed_folders")
        if allowed is not None:
            if not isinstance(allowed, list) or not all(isinstance(f, str) for f in allowed):
                raise SystemExit("allowed_folders must be a list of strings")

        return cls(
            vaultwarden_url=url,
            client_id=client_id,
            client_secret=client_secret,
            allowed_folders=allowed,
        )
