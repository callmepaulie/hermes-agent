"""Frame.io V4 tools for Hermes Agent.

Phase 1 focuses on OAuth setup/status and read-only discovery. The toolset is
API/OAuth based; it never tries to drive a browser session or use cookies.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from hermes_constants import get_hermes_home
from tools.registry import registry

API_BASE = "https://api.frame.io/v4"
AUTHORIZE_URL = "https://ims-na1.adobelogin.com/ims/authorize/v2"
TOKEN_URL = "https://ims-na1.adobelogin.com/ims/token/v3"
DEFAULT_REDIRECT_URI = "http://127.0.0.1:43828/frameio/callback"
SCOPES = "openid email profile offline_access additional_info.roles"
AUTH_FILENAME = "frameio_auth.json"
CACHE_FILENAME = "frameio_cache.json"


# ---------------------------------------------------------------------------
# Paths and config
# ---------------------------------------------------------------------------


def _auth_file() -> Path:
    return get_hermes_home() / AUTH_FILENAME


def _cache_file() -> Path:
    return get_hermes_home() / CACHE_FILENAME


def _client_id() -> str:
    return os.getenv("FRAMEIO_CLIENT_ID", "").strip()


def _client_secret() -> str:
    return os.getenv("FRAMEIO_CLIENT_SECRET", "").strip()


def _redirect_uri() -> str:
    return os.getenv("FRAMEIO_REDIRECT_URI", DEFAULT_REDIRECT_URI).strip() or DEFAULT_REDIRECT_URI


def _missing_config() -> list[str]:
    missing = []
    if not _client_id():
        missing.append("FRAMEIO_CLIENT_ID")
    return missing


def _check_frameio_available() -> bool:
    """Show the toolset only when the OAuth app client id is configured.

    Individual tools still return structured auth_required results when token
    state is missing/expired, so no browser-login workaround is attempted.
    """
    return bool(_client_id())


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------


def _json(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True)


def _load_json_file(path: Path) -> dict[str, Any]:
    try:
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_json_file(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _load_auth_state() -> dict[str, Any]:
    return _load_json_file(_auth_file())


def _save_auth_state(state: dict[str, Any]) -> None:
    _write_json_file(_auth_file(), state)


def _load_cache() -> dict[str, Any]:
    return _load_json_file(_cache_file())


def _save_cache(cache: dict[str, Any]) -> None:
    _write_json_file(_cache_file(), cache)


def _auth_required(error: str = "not_authenticated", **extra: Any) -> str:
    payload = {
        "success": False,
        "auth_required": True,
        "error": error,
        "next_step": "Run frameio_login and complete Adobe IMS OAuth before calling Frame.io discovery tools.",
    }
    payload.update(extra)
    return _json(payload)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _http_json(method: str, url: str, *, headers: dict[str, str] | None = None, data: dict[str, Any] | None = None) -> Any:
    encoded_data = None
    request_headers = dict(headers or {})
    if data is not None:
        encoded_data = urllib.parse.urlencode(data).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=encoded_data, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:  # noqa: S310 - user-configured API endpoint constants
            body = response.read().decode("utf-8")
            if not body:
                return {}
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {"body": body}
        raise RuntimeError(f"HTTP {exc.code}: {parsed}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error: {exc.reason}") from exc


def _api_get(path: str, params: dict[str, Any] | None = None) -> Any:
    state = _load_auth_state()
    access_token = state.get("access_token")
    if not access_token:
        raise PermissionError("not_authenticated")
    normalized = path if path.startswith("/") else f"/{path}"
    url = f"{API_BASE}{normalized}"
    if params:
        url = f"{url}?{urllib.parse.urlencode({k: v for k, v in params.items() if v not in (None, '')})}"
    return _http_json("GET", url, headers={"Authorization": f"Bearer {access_token}"})


def _exchange_code_for_token(code: str) -> dict[str, Any]:
    if not _client_secret():
        raise RuntimeError("FRAMEIO_CLIENT_SECRET is required to exchange an OAuth code")
    token = _http_json(
        "POST",
        TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "client_id": _client_id(),
            "client_secret": _client_secret(),
            "code": code,
            "redirect_uri": _redirect_uri(),
        },
    )
    if not isinstance(token, dict) or not token.get("access_token"):
        raise RuntimeError("Adobe IMS token response did not include an access_token")
    if token.get("expires_in") and not token.get("expires_at"):
        token["expires_at"] = int(time.time()) + int(token["expires_in"])
    _save_auth_state(token)
    return token


def _safe_api_get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        return {"success": True, "data": _api_get(path, params=params)}
    except PermissionError:
        return json.loads(_auth_required())
    except Exception as exc:
        return {"success": False, "auth_required": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Public tool handlers
# ---------------------------------------------------------------------------


def frameio_status() -> str:
    state = _load_auth_state()
    has_access = bool(state.get("access_token"))
    expires_at = state.get("expires_at")
    expired = bool(expires_at and int(expires_at) <= int(time.time()))
    return _json(
        {
            "success": True,
            "configured": not _missing_config(),
            "authenticated": has_access and not expired,
            "auth_required": not (has_access and not expired),
            "api_base": API_BASE,
            "authorize_endpoint": AUTHORIZE_URL,
            "token_endpoint": TOKEN_URL,
            "scopes": SCOPES,
            "redirect_uri": _redirect_uri(),
            "auth_file": str(_auth_file()),
            "cache_file": str(_cache_file()),
            "expires_at": expires_at,
            "expired": expired,
            "missing_env": _missing_config(),
        }
    )


def frameio_login(code: str = "", state: str = "") -> str:
    missing = _missing_config()
    if missing:
        return _auth_required("missing_config", missing_env=missing)

    code = (code or "").strip()
    if code:
        try:
            token = _exchange_code_for_token(code)
        except Exception as exc:
            return _json({"success": False, "auth_required": True, "error": str(exc)})
        return _json(
            {
                "success": True,
                "auth_required": False,
                "authenticated": True,
                "auth_file": str(_auth_file()),
                "expires_at": token.get("expires_at"),
            }
        )

    params = {
        "client_id": _client_id(),
        "redirect_uri": _redirect_uri(),
        "response_type": "code",
        "scope": SCOPES,
    }
    if state:
        params["state"] = state
    authorize_url = f"{AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"
    return _json(
        {
            "success": True,
            "auth_required": True,
            "authorize_url": authorize_url,
            "redirect_uri": _redirect_uri(),
            "scopes": SCOPES,
            "next_step": "Open authorize_url, approve Adobe IMS access, then pass the returned code to frameio_login(code=...).",
        }
    )


def frameio_list_accounts() -> str:
    return _json(_safe_api_get("/accounts"))


def frameio_list_workspaces(account_id: str) -> str:
    if not account_id:
        return _json({"success": False, "error": "account_id is required"})
    return _json(_safe_api_get(f"/accounts/{urllib.parse.quote(account_id)}/workspaces"))


def frameio_list_projects(workspace_id: str) -> str:
    if not workspace_id:
        return _json({"success": False, "error": "workspace_id is required"})
    return _json(_safe_api_get(f"/workspaces/{urllib.parse.quote(workspace_id)}/projects"))


def frameio_list_folder_children(project_id: str, folder_id: str = "") -> str:
    if not project_id:
        return _json({"success": False, "error": "project_id is required"})
    safe_project = urllib.parse.quote(project_id)
    if folder_id:
        path = f"/projects/{safe_project}/folders/{urllib.parse.quote(folder_id)}/children"
    else:
        path = f"/projects/{safe_project}/folders/root/children"
    return _json(_safe_api_get(path))


def _iter_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("data", "items", "children"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def frameio_find_folder(project_id: str, folder_name: str, parent_folder_id: str = "", max_depth: int = 4) -> str:
    if not project_id:
        return _json({"success": False, "error": "project_id is required"})
    if not folder_name:
        return _json({"success": False, "error": "folder_name is required"})

    target = folder_name.strip().casefold()
    visited: set[str] = set()

    def search(folder_id: str, depth: int) -> dict[str, Any] | None:
        if depth > max_depth:
            return None
        cache_key = folder_id or "root"
        if cache_key in visited:
            return None
        visited.add(cache_key)
        safe_project = urllib.parse.quote(project_id)
        if folder_id:
            path = f"/projects/{safe_project}/folders/{urllib.parse.quote(folder_id)}/children"
        else:
            path = f"/projects/{safe_project}/folders/root/children"
        children = _api_get(path)
        for item in _iter_items(children):
            name = str(item.get("name") or item.get("display_name") or "")
            item_id = str(item.get("id") or item.get("folder_id") or "")
            item_type = str(item.get("type") or item.get("asset_type") or "").casefold()
            if name.casefold() == target:
                return item
            if item_id and ("folder" in item_type or item.get("children") is not None):
                found = search(item_id, depth + 1)
                if found:
                    return found
        return None

    try:
        found = search(parent_folder_id, 0)
    except PermissionError:
        return _auth_required()
    except Exception as exc:
        return _json({"success": False, "auth_required": False, "error": str(exc)})

    if found:
        cache = _load_cache()
        cache.setdefault("folders", {})[folder_name] = found.get("id") or found.get("folder_id")
        _save_cache(cache)
        return _json({"success": True, "found": True, "folder": found, "cache_file": str(_cache_file())})
    return _json({"success": True, "found": False, "folder": None})


# ---------------------------------------------------------------------------
# Schemas and registry
# ---------------------------------------------------------------------------


FRAMEIO_LOGIN_SCHEMA = {
    "name": "frameio_login",
    "description": "Start or complete Adobe IMS OAuth for Frame.io V4. With no code, returns an authorization URL; with code, stores tokens under HERMES_HOME.",
    "parameters": {
        "type": "object",
        "properties": {
            "code": {"type": "string", "description": "OAuth authorization code from Adobe IMS callback."},
            "state": {"type": "string", "description": "Optional opaque OAuth state value to include in the authorization URL."},
        },
    },
}

FRAMEIO_STATUS_SCHEMA = {
    "name": "frameio_status",
    "description": "Show Frame.io OAuth configuration and token status without printing secrets or tokens.",
    "parameters": {"type": "object", "properties": {}},
}

FRAMEIO_LIST_ACCOUNTS_SCHEMA = {
    "name": "frameio_list_accounts",
    "description": "List Frame.io V4 accounts for the authenticated user.",
    "parameters": {"type": "object", "properties": {}},
}

FRAMEIO_LIST_WORKSPACES_SCHEMA = {
    "name": "frameio_list_workspaces",
    "description": "List workspaces under a Frame.io account.",
    "parameters": {
        "type": "object",
        "properties": {"account_id": {"type": "string", "description": "Frame.io account ID."}},
        "required": ["account_id"],
    },
}

FRAMEIO_LIST_PROJECTS_SCHEMA = {
    "name": "frameio_list_projects",
    "description": "List projects under a Frame.io workspace.",
    "parameters": {
        "type": "object",
        "properties": {"workspace_id": {"type": "string", "description": "Frame.io workspace ID."}},
        "required": ["workspace_id"],
    },
}

FRAMEIO_LIST_FOLDER_CHILDREN_SCHEMA = {
    "name": "frameio_list_folder_children",
    "description": "List children of a Frame.io project folder. If folder_id is omitted, tries the project root folder.",
    "parameters": {
        "type": "object",
        "properties": {
            "project_id": {"type": "string", "description": "Frame.io project ID."},
            "folder_id": {"type": "string", "description": "Optional Frame.io folder ID."},
        },
        "required": ["project_id"],
    },
}

FRAMEIO_FIND_FOLDER_SCHEMA = {
    "name": "frameio_find_folder",
    "description": "Find a Frame.io folder by friendly name within a project and cache its ID locally.",
    "parameters": {
        "type": "object",
        "properties": {
            "project_id": {"type": "string", "description": "Frame.io project ID."},
            "folder_name": {"type": "string", "description": "Folder friendly name to find."},
            "parent_folder_id": {"type": "string", "description": "Optional parent folder ID to start from."},
            "max_depth": {"type": "integer", "description": "Maximum recursive search depth.", "default": 4},
        },
        "required": ["project_id", "folder_name"],
    },
}


registry.register(
    name="frameio_login",
    toolset="frameio",
    schema=FRAMEIO_LOGIN_SCHEMA,
    handler=lambda args, **kw: frameio_login(code=args.get("code", ""), state=args.get("state", "")),
    check_fn=_check_frameio_available,
    requires_env=["FRAMEIO_CLIENT_ID"],
    description="Start or complete Frame.io OAuth.",
    emoji="🎞️",
)
registry.register(
    name="frameio_status",
    toolset="frameio",
    schema=FRAMEIO_STATUS_SCHEMA,
    handler=lambda args, **kw: frameio_status(),
    check_fn=_check_frameio_available,
    requires_env=["FRAMEIO_CLIENT_ID"],
    description="Show Frame.io auth status.",
    emoji="🎞️",
)
registry.register(
    name="frameio_list_accounts",
    toolset="frameio",
    schema=FRAMEIO_LIST_ACCOUNTS_SCHEMA,
    handler=lambda args, **kw: frameio_list_accounts(),
    check_fn=_check_frameio_available,
    requires_env=["FRAMEIO_CLIENT_ID"],
    description="List Frame.io accounts.",
    emoji="🎞️",
)
registry.register(
    name="frameio_list_workspaces",
    toolset="frameio",
    schema=FRAMEIO_LIST_WORKSPACES_SCHEMA,
    handler=lambda args, **kw: frameio_list_workspaces(account_id=args.get("account_id", "")),
    check_fn=_check_frameio_available,
    requires_env=["FRAMEIO_CLIENT_ID"],
    description="List Frame.io workspaces.",
    emoji="🎞️",
)
registry.register(
    name="frameio_list_projects",
    toolset="frameio",
    schema=FRAMEIO_LIST_PROJECTS_SCHEMA,
    handler=lambda args, **kw: frameio_list_projects(workspace_id=args.get("workspace_id", "")),
    check_fn=_check_frameio_available,
    requires_env=["FRAMEIO_CLIENT_ID"],
    description="List Frame.io projects.",
    emoji="🎞️",
)
registry.register(
    name="frameio_list_folder_children",
    toolset="frameio",
    schema=FRAMEIO_LIST_FOLDER_CHILDREN_SCHEMA,
    handler=lambda args, **kw: frameio_list_folder_children(project_id=args.get("project_id", ""), folder_id=args.get("folder_id", "")),
    check_fn=_check_frameio_available,
    requires_env=["FRAMEIO_CLIENT_ID"],
    description="List Frame.io folder children.",
    emoji="🎞️",
)
registry.register(
    name="frameio_find_folder",
    toolset="frameio",
    schema=FRAMEIO_FIND_FOLDER_SCHEMA,
    handler=lambda args, **kw: frameio_find_folder(
        project_id=args.get("project_id", ""),
        folder_name=args.get("folder_name", ""),
        parent_folder_id=args.get("parent_folder_id", ""),
        max_depth=int(args.get("max_depth", 4) or 4),
    ),
    check_fn=_check_frameio_available,
    requires_env=["FRAMEIO_CLIENT_ID"],
    description="Find a Frame.io folder by name.",
    emoji="🎞️",
)
