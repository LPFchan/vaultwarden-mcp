from __future__ import annotations

import argparse
import contextlib
import fnmatch
import logging
import os
import sys
from collections.abc import AsyncIterator
from urllib.parse import parse_qs

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
import uvicorn

from .config import Config
from .vaultwarden import (
    ConflictError,
    DuplicateError,
    ForbiddenError,
    InternalError,
    NotFoundError,
    VaultwardenClient,
)

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"

_client: VaultwardenClient | None = None


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format=LOG_FORMAT,
        stream=sys.stderr,
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("mcp").setLevel(logging.WARNING)
    logging.getLogger("uvicorn").setLevel(logging.WARNING)


def _require_client() -> VaultwardenClient:
    if _client is None:
        raise InternalError("Server not initialized")
    return _client


# -- CORS middleware -------------------------------------------------------


class _CORSMiddleware:
    def __init__(self, app):
        self.app = app
        raw = os.environ.get("ALLOWED_ORIGINS", "https://*.lost.plus")
        self._allowed = [o.strip() for o in raw.split(",") if o.strip()]

    def _echo_origin(self, origin: str | None) -> str | None:
        if not origin:
            return None
        for pattern in self._allowed:
            if fnmatch.fnmatch(origin, pattern):
                return origin
        return None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        origin_raw = headers.get(b"origin")
        origin = origin_raw.decode() if origin_raw else None
        matched = self._echo_origin(origin)

        if scope["method"] == "OPTIONS":
            resp_headers = [
                (b"access-control-allow-methods", b"GET, POST, DELETE, OPTIONS"),
                (b"access-control-allow-headers", b"authorization, content-type, accept, mcp-session-id, mcp-protocol-version, last-event-id, x-api-key"),
                (b"access-control-expose-headers", b"mcp-session-id, mcp-protocol-version, content-type"),
            ]
            if matched:
                resp_headers.insert(0, (b"access-control-allow-origin", matched.encode()))
            elif origin:
                resp_headers.insert(0, (b"access-control-allow-origin", origin.encode()))
            await send({"type": "http.response.start", "status": 204, "headers": resp_headers})
            await send({"type": "http.response.body", "body": b""})
            return

        async def send_with_cors(message):
            if message["type"] == "http.response.start":
                hlist = list(message.get("headers", []))
                if matched:
                    hlist.append((b"access-control-allow-origin", matched.encode()))
                elif origin:
                    hlist.append((b"access-control-allow-origin", origin.encode()))
                hlist.append((b"access-control-expose-headers", b"mcp-session-id, mcp-protocol-version, content-type"))
                hlist.append((b"vary", b"Origin"))
                message["headers"] = hlist
            await send(message)

        await self.app(scope, receive, send_with_cors)


# -- auth middleware -------------------------------------------------------


class _AuthMiddleware:
    def __init__(self, app, tokens: list[str] | None):
        self.app = app
        self._tokens = set(tokens) if tokens else None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self._tokens is None:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path == "/healthz":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode()
        if auth_header.startswith("Bearer ") and auth_header[7:] in self._tokens:
            await self.app(scope, receive, send)
            return

        token_values = parse_qs(scope.get("query_string", b"").decode()).get("token", [])
        if self._tokens & set(token_values):
            await self.app(scope, receive, send)
            return

        first_segment = path.strip("/").split("/")[0] if path.strip("/") else ""
        if first_segment in self._tokens:
            scope["path"] = "/" + "/".join(path.strip("/").split("/")[1:])
            await self.app(scope, receive, send)
            return

        await send({"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b'{"error":"Unauthorized"}'})


# -- lifespan --------------------------------------------------------------


def _build_lifespan(config_path: str):
    @contextlib.asynccontextmanager
    async def lifespan(_server: FastMCP) -> AsyncIterator[None]:
        global _client
        logger = logging.getLogger(__name__)
        logger.info("Loading config from %s", config_path)

        config = Config.from_path(config_path)
        logger.info(
            "Configured for %s (allowed_folders=%s)",
            config.vaultwarden_url,
            config.allowed_folders if config.allowed_folders is not None else "all",
        )

        _client = VaultwardenClient(config)
        await _client.validate()
        logger.info("Startup validation passed")

        try:
            yield
        finally:
            if _client is not None:
                await _client.close()
                _client = None

    return lifespan


# -- tools ----------------------------------------------------------------


def _register_tools(mcp_server: FastMCP) -> None:
    @mcp_server.tool()
    async def get_secret(folder: str, item_name: str) -> str:
        """Retrieve a secret value from Vaultwarden."""
        try:
            return await _require_client().get_secret(folder, item_name)
        except (NotFoundError, ForbiddenError, DuplicateError, InternalError):
            raise
        except Exception as e:
            raise InternalError(str(e)) from e

    @mcp_server.tool()
    async def get_login(folder: str, item_name: str) -> dict:
        """Retrieve a full login entry (username and password) from Vaultwarden."""
        try:
            return await _require_client().get_login(folder, item_name)
        except (NotFoundError, ForbiddenError, DuplicateError, InternalError):
            raise
        except Exception as e:
            raise InternalError(str(e)) from e

    @mcp_server.tool()
    async def list_secrets(folder: str | None = None) -> list[dict]:
        """List available secret names (never the values themselves)."""
        try:
            return await _require_client().list_secrets(folder)
        except InternalError:
            raise
        except Exception as e:
            raise InternalError(str(e)) from e

    @mcp_server.tool()
    async def add_secret(folder: str, item_name: str, value: str) -> dict:
        """Add a new secret to a folder. Auto-tags with mcp-secret:// URI."""
        try:
            await _require_client().add_secret(folder, item_name, value)
            return {"ok": True}
        except (NotFoundError, ForbiddenError, ConflictError, InternalError):
            raise
        except Exception as e:
            raise InternalError(str(e)) from e

    @mcp_server.tool()
    async def add_login(folder: str, item_name: str, username: str, password: str) -> dict:
        """Add a new login entry (username + password) to a folder."""
        try:
            await _require_client().add_login(folder, item_name, username, password)
            return {"ok": True}
        except (NotFoundError, ForbiddenError, ConflictError, InternalError):
            raise
        except Exception as e:
            raise InternalError(str(e)) from e

    @mcp_server.tool()
    async def edit_secret(folder: str, item_name: str, value: str) -> dict:
        """Update an existing secret's value."""
        try:
            await _require_client().edit_secret(folder, item_name, value)
            return {"ok": True}
        except (NotFoundError, ForbiddenError, InternalError):
            raise
        except Exception as e:
            raise InternalError(str(e)) from e

    @mcp_server.tool()
    async def delete_secret(folder: str, item_name: str) -> dict:
        """Soft-delete a secret (moves to trash, recoverable for 30 days)."""
        try:
            await _require_client().delete_secret(folder, item_name)
            return {"ok": True}
        except (NotFoundError, ForbiddenError, InternalError):
            raise
        except Exception as e:
            raise InternalError(str(e)) from e

    @mcp_server.tool()
    async def recover_secret(folder: str, item_name: str) -> dict:
        """Recover a soft-deleted secret from trash."""
        try:
            await _require_client().recover_secret(folder, item_name)
            return {"ok": True}
        except (NotFoundError, ForbiddenError, InternalError):
            raise
        except Exception as e:
            raise InternalError(str(e)) from e

    @mcp_server.tool()
    async def add_folder(folder: str) -> dict:
        """Create a new folder for organizing secrets."""
        try:
            await _require_client().add_folder(folder)
            return {"ok": True}
        except (ConflictError, InternalError):
            raise
        except Exception as e:
            raise InternalError(str(e)) from e

    @mcp_server.tool()
    async def delete_folder(folder: str) -> dict:
        """Delete an empty folder."""
        try:
            await _require_client().delete_folder(folder)
            return {"ok": True}
        except (NotFoundError, ConflictError, InternalError):
            raise
        except Exception as e:
            raise InternalError(str(e)) from e

    @mcp_server.tool()
    async def list_trash() -> list[dict]:
        """List soft-deleted secrets currently in trash."""
        try:
            return await _require_client().list_trash()
        except InternalError:
            raise
        except Exception as e:
            raise InternalError(str(e)) from e

    @mcp_server.tool()
    async def move_secret(folder: str, item_name: str, target_folder: str) -> dict:
        """Move a secret to a different folder."""
        try:
            await _require_client().move_secret(folder, item_name, target_folder)
            return {"ok": True}
        except (NotFoundError, ForbiddenError, InternalError):
            raise
        except Exception as e:
            raise InternalError(str(e)) from e

    @mcp_server.tool()
    async def rename_secret(folder: str, item_name: str, new_name: str) -> dict:
        """Rename a secret (keeps the same value and folder)."""
        try:
            await _require_client().rename_secret(folder, item_name, new_name)
            return {"ok": True}
        except (NotFoundError, ForbiddenError, ConflictError, InternalError):
            raise
        except Exception as e:
            raise InternalError(str(e)) from e

    @mcp_server.tool()
    async def rename_folder(folder: str, new_name: str) -> dict:
        """Rename a folder."""
        try:
            await _require_client().rename_folder(folder, new_name)
            return {"ok": True}
        except (NotFoundError, ConflictError, InternalError):
            raise
        except Exception as e:
            raise InternalError(str(e)) from e

    @mcp_server.tool()
    async def empty_trash() -> dict:
        """Permanently delete all soft-deleted items in trash."""
        try:
            await _require_client().empty_trash()
            return {"ok": True}
        except InternalError:
            raise
        except Exception as e:
            raise InternalError(str(e)) from e

    @mcp_server.tool()
    async def search_secrets(query: str) -> list[dict]:
        """Search secrets by name across all folders. Returns folder + item_name for each match."""
        try:
            return await _require_client().search_secrets(query)
        except InternalError:
            raise
        except Exception as e:
            raise InternalError(str(e)) from e


# -- routes ----------------------------------------------------------------


def _register_routes(mcp_server: FastMCP) -> None:
    @mcp_server.custom_route("/", methods=["GET"], include_in_schema=False)
    async def root_route(request):
        del request
        return JSONResponse({"name": "vaultwarden-mcp", "mcp_path": "/mcp", "healthz": "/healthz"})

    @mcp_server.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def health_route(request):
        del request
        return JSONResponse({"ok": True})


# -- transport security ----------------------------------------------------


def _build_transport_security() -> TransportSecuritySettings:
    return TransportSecuritySettings(enable_dns_rebinding_protection=False)


# -- main -----------------------------------------------------------------


def _build_app(mcp_server: FastMCP) -> object:
    raw_tokens = os.environ.get("VAULTWARDEN_MCP_AUTH_TOKEN")
    auth_tokens: list[str] | None = None
    if raw_tokens:
        auth_tokens = [t.strip() for t in raw_tokens.split(",") if t.strip()]
        logging.getLogger(__name__).info("Auth enabled (%d token(s))", len(auth_tokens))

    inner = _AuthMiddleware(mcp_server.streamable_http_app(), auth_tokens)
    return _CORSMiddleware(inner)


def main() -> None:
    global _auth_app

    parser = argparse.ArgumentParser(prog="vaultwarden-mcp-server")
    parser.add_argument("--config", required=True, help="Path to config.json")
    parser.add_argument("--stdio", action="store_true", help="Run in stdio mode (default: HTTP+SSE)")
    args = parser.parse_args()

    _setup_logging()

    mcp = FastMCP(
        "vaultwarden-secrets",
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8000")),
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        lifespan=_build_lifespan(args.config),
        transport_security=_build_transport_security(),
    )

    _register_tools(mcp)
    _register_routes(mcp)

    if args.stdio:
        try:
            mcp.run(transport="stdio")
        except SystemExit:
            raise
        except Exception as e:
            logging.getLogger(__name__).error("Server failed: %s", e)
            sys.exit(1)
        return

    app = _build_app(mcp)

    uvicorn.run(
        app,
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8000")),
        forwarded_allow_ips="*",
        proxy_headers=True,
    )


if __name__ == "__main__":
    main()
