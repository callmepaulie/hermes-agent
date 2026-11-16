"""Frame.io V4 tools for Hermes Agent.

The toolset is API/OAuth based; it never drives a browser session or uses
cookies. It supports Adobe IMS user OAuth and the Frame.io V4 transitional
legacy developer-token path (`x-frameio-legacy-token-auth: true`).
"""

from __future__ import annotations

import fnmatch
import json
import mimetypes
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


def _legacy_token() -> str:
    return os.getenv("FRAMEIO_LEGACY_TOKEN", "").strip()


def _config_setting(key: str) -> str:
    """Return a string from the ``frameio`` section of config.yaml ("" if unset).

    Never raises: if config cannot be loaded the caller falls back to defaults.
    """
    try:
        from hermes_cli.config import load_config

        section = load_config().get("frameio")
        value = section.get(key) if isinstance(section, dict) else None
        return value.strip() if isinstance(value, str) else ""
    except Exception:
        return ""


def _redirect_uri() -> str:
    """FRAMEIO_REDIRECT_URI env overrides ``frameio.redirect_uri`` in config.yaml."""
    return (
        os.getenv("FRAMEIO_REDIRECT_URI", "").strip()
        or _config_setting("redirect_uri")
        or DEFAULT_REDIRECT_URI
    )


def _auth_mode() -> str:
    """Return configured auth mode.

    Defaults to legacy when FRAMEIO_LEGACY_TOKEN is present so users can add the
    token without also editing another env key. Otherwise defaults to OAuth.
    """

    # FRAMEIO_AUTH_MODE env overrides ``frameio.auth_mode`` in config.yaml.
    for raw in (os.getenv("FRAMEIO_AUTH_MODE", ""), _config_setting("auth_mode")):
        raw = raw.strip().lower()
        if raw in {"legacy", "oauth", "s2s"}:
            return raw
    if _legacy_token():
        return "legacy"
    return "oauth"


def _missing_config() -> list[str]:
    mode = _auth_mode()
    missing: list[str] = []
    if mode == "legacy":
        if not _legacy_token():
            missing.append("FRAMEIO_LEGACY_TOKEN")
        return missing
    if not _client_id():
        missing.append("FRAMEIO_CLIENT_ID")
    if mode == "s2s" and not _client_secret():
        missing.append("FRAMEIO_CLIENT_SECRET")
    return missing


def _check_frameio_available() -> bool:
    """Show the toolset when OAuth or legacy-token config is present."""

    return bool(_client_id() or _legacy_token())


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
    mode = _auth_mode()
    next_step = (
        "Set FRAMEIO_LEGACY_TOKEN in ~/.hermes/.env, or switch FRAMEIO_AUTH_MODE to oauth and run frameio_login."
        if mode == "legacy"
        else "Run frameio_login and complete Adobe IMS OAuth before calling Frame.io tools."
    )
    payload = {
        "success": False,
        "auth_required": True,
        "auth_mode": mode,
        "error": error,
        "next_step": next_step,
    }
    payload.update(extra)
    return _json(payload)


def _require(value: str, name: str) -> str | None:
    if not value:
        return f"{name} is required"
    return None


_ID_FORBIDDEN = ("/", "\\", "..", "?", "#")


def _seg(value: Any, name: str = "id") -> str:
    """Validate and percent-encode a caller-supplied id for use as one URL path segment."""
    text = str(value) if value is not None else ""
    if not text:
        raise ValueError(f"{name} is required")
    if any(ch.isspace() for ch in text) or any(bad in text for bad in _ID_FORBIDDEN):
        raise ValueError(f"{name} contains characters not allowed in an id (/, \\, .., ?, #, whitespace)")
    return urllib.parse.quote(text, safe="")


def _id_error(**ids: Any) -> str | None:
    for name, value in ids.items():
        try:
            _seg(value, name)
        except ValueError as exc:
            return _json({"success": False, "error": str(exc)})
    return None


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _http_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    data: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> Any:
    encoded_data = None
    request_headers = dict(headers or {})
    request_headers.setdefault("Accept", "application/json")
    request_headers.setdefault("User-Agent", "HermesFrameio/1.0")
    if json_body is not None:
        encoded_data = json.dumps(json_body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    elif data is not None:
        encoded_data = urllib.parse.urlencode(data).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=encoded_data, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:  # noqa: S310 - fixed API endpoints / signed URLs
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


def _http_put_bytes(url: str, payload: bytes, headers: dict[str, str] | None = None) -> None:
    req = urllib.request.Request(url, data=payload, headers=dict(headers or {}), method="PUT")
    try:
        with urllib.request.urlopen(req, timeout=120) as response:  # noqa: S310 - Frame.io returns pre-signed upload URLs
            response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Upload HTTP {exc.code}: {body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Upload network error: {exc.reason}") from exc


def _auth_headers() -> dict[str, str]:
    mode = _auth_mode()
    if mode == "legacy":
        token = _legacy_token()
        if not token:
            raise PermissionError("not_authenticated")
        return {"Authorization": f"Bearer {token}", "x-frameio-legacy-token-auth": "true"}

    state = _load_auth_state()
    access_token = state.get("access_token")
    if not access_token:
        raise PermissionError("not_authenticated")
    expires_at = state.get("expires_at")
    if expires_at and int(expires_at) <= int(time.time()):
        raise PermissionError("Frame.io OAuth token has expired; run frameio_login again (tokens are not refreshed automatically).")
    return {"Authorization": f"Bearer {access_token}"}


def _api_request(method: str, path: str, params: dict[str, Any] | None = None, json_body: dict[str, Any] | None = None) -> Any:
    normalized = path if path.startswith("/") else f"/{path}"
    url = f"{API_BASE}{normalized}"
    if params:
        clean = {k: v for k, v in params.items() if v not in (None, "")}
        if clean:
            url = f"{url}?{urllib.parse.urlencode(clean)}"
    return _http_json(method, url, headers=_auth_headers(), json_body=json_body)


def _api_get(path: str, params: dict[str, Any] | None = None) -> Any:
    return _api_request("GET", path, params=params)


def _api_post(path: str, body: dict[str, Any]) -> Any:
    return _api_request("POST", path, json_body=body)


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


def _safe_api_call(fn: Any) -> dict[str, Any]:
    try:
        return {"success": True, "data": fn()}
    except PermissionError as exc:
        return json.loads(_auth_required(str(exc) or "not_authenticated"))
    except Exception as exc:
        return {"success": False, "auth_required": False, "auth_mode": _auth_mode(), "error": str(exc)}


# ---------------------------------------------------------------------------
# Public tool handlers
# ---------------------------------------------------------------------------


def frameio_status() -> str:
    mode = _auth_mode()
    state = _load_auth_state()
    has_access = bool(state.get("access_token"))
    expires_at = state.get("expires_at")
    expired = bool(expires_at and int(expires_at) <= int(time.time()))
    legacy_configured = bool(_legacy_token())
    authenticated = legacy_configured if mode == "legacy" else has_access and not expired
    return _json(
        {
            "success": True,
            "configured": not _missing_config(),
            "authenticated": authenticated,
            "auth_required": not authenticated,
            "auth_mode": mode,
            "api_base": API_BASE,
            "authorize_endpoint": AUTHORIZE_URL,
            "token_endpoint": TOKEN_URL,
            "scopes": SCOPES,
            "redirect_uri": _redirect_uri(),
            "auth_file": str(_auth_file()),
            "cache_file": str(_cache_file()),
            "expires_at": expires_at,
            "expired": expired,
            "legacy_configured": legacy_configured,
            "missing_env": _missing_config(),
        }
    )


def frameio_login(code: str = "", state: str = "") -> str:
    missing = _missing_config()
    if missing:
        return _auth_required("missing_config", missing_env=missing)

    if _auth_mode() == "legacy":
        return _json(
            {
                "success": True,
                "auth_required": False,
                "authenticated": True,
                "auth_mode": "legacy",
                "next_step": "Legacy developer token mode is configured; call frameio_me or frameio_list_accounts to smoke-test API access.",
            }
        )

    code = (code or "").strip()
    if code:
        try:
            token = _exchange_code_for_token(code)
        except Exception as exc:
            return _json({"success": False, "auth_required": True, "auth_mode": _auth_mode(), "error": str(exc)})
        return _json(
            {
                "success": True,
                "auth_required": False,
                "authenticated": True,
                "auth_mode": _auth_mode(),
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
            "auth_mode": _auth_mode(),
            "authorize_url": authorize_url,
            "redirect_uri": _redirect_uri(),
            "scopes": SCOPES,
            "next_step": "Open authorize_url, approve Adobe IMS access, then pass the returned code to frameio_login(code=...).",
        }
    )


def _after_error(after: Any) -> str | None:
    """Reject an ``after`` cursor that is not a plain string without whitespace/control chars."""
    if after in (None, ""):
        return None
    if not isinstance(after, str) or any(ch.isspace() or not ch.isprintable() for ch in after):
        return _json({"success": False, "error": "after must be a string without whitespace or control characters"})
    return None


def _list_page(path: str, after: Any = "", params: dict[str, Any] | None = None) -> dict[str, Any]:
    """GET one page of a paged collection and add a top-level ``next_after`` cursor."""
    query = dict(params or {})
    if after:
        query["after"] = after

    def fetch() -> Any:
        return _api_get(path, params=query or None)

    result = _safe_api_call(fetch)
    if result.get("success"):
        result["next_after"] = _next_page_cursor(result.get("data"))[0]
    return result


def frameio_me() -> str:
    return _json(_safe_api_call(lambda: _api_get("/me")))


def frameio_list_accounts(after: str = "") -> str:
    if error := _after_error(after):
        return error
    return _json(_list_page("/accounts", after))


def frameio_list_workspaces(account_id: str, after: str = "") -> str:
    if error := _require(account_id, "account_id"):
        return _json({"success": False, "error": error})
    if error := _id_error(account_id=account_id):
        return error
    if error := _after_error(after):
        return error
    safe_account = _seg(account_id, "account_id")
    return _json(_list_page(f"/accounts/{safe_account}/workspaces", after))


def frameio_list_projects(account_id: str, workspace_id: str, after: str = "") -> str:
    if error := _require(account_id, "account_id"):
        return _json({"success": False, "error": error})
    if error := _require(workspace_id, "workspace_id"):
        return _json({"success": False, "error": error})
    if error := _id_error(account_id=account_id, workspace_id=workspace_id):
        return error
    if error := _after_error(after):
        return error
    safe_account = _seg(account_id, "account_id")
    safe_workspace = _seg(workspace_id, "workspace_id")
    return _json(_list_page(f"/accounts/{safe_account}/workspaces/{safe_workspace}/projects", after))


def frameio_list_folder_children(account_id: str, folder_id: str, include: str = "", after: str = "") -> str:
    if error := _require(account_id, "account_id"):
        return _json({"success": False, "error": error})
    if error := _require(folder_id, "folder_id"):
        return _json({"success": False, "error": error})
    if error := _id_error(account_id=account_id, folder_id=folder_id):
        return error
    if error := _after_error(after):
        return error
    safe_account = _seg(account_id, "account_id")
    safe_folder = _seg(folder_id, "folder_id")
    params = {"include": include} if include else None
    return _json(_list_page(f"/accounts/{safe_account}/folders/{safe_folder}/children", after, params))


def _iter_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("data", "items", "children"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


MAX_CHILD_PAGES = 200


def _next_page_cursor(data: Any) -> tuple[str | None, bool]:
    """Return (cursor, more_pages) from a paged list response.

    Frame.io V4 list responses carry ``links.next`` with an ``after`` cursor.
    ``more_pages`` is True when the response says another page exists, even
    if no usable cursor could be read from it.
    """
    if not isinstance(data, dict):
        return None, False
    links = data.get("links")
    nxt = links.get("next") if isinstance(links, dict) else None
    if not nxt or not isinstance(nxt, str):
        return None, False
    query = urllib.parse.urlparse(nxt).query
    after = urllib.parse.parse_qs(query).get("after", [None])[0]
    return (after or None), True


def _iter_all_children(path: str) -> list[dict[str, Any]]:
    """Fetch every page of a children listing.

    Raises RuntimeError rather than returning a partial list, so a caller
    never reports "not found" after looking at only some of the children.
    """
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    params: dict[str, Any] | None = None
    for _ in range(MAX_CHILD_PAGES):
        data = _api_get(path, params=params)
        items.extend(_iter_items(data))
        cursor, more = _next_page_cursor(data)
        if not more:
            return items
        if not cursor or cursor in seen:
            raise RuntimeError("Frame.io listing has more pages but no usable next-page cursor; search is incomplete")
        seen.add(cursor)
        params = {"after": cursor}
    raise RuntimeError(f"Frame.io listing exceeded {MAX_CHILD_PAGES} pages; search is incomplete")


def frameio_find_folder(account_id: str, folder_name: str, parent_folder_id: str, max_depth: int = 4) -> str:
    if error := _require(account_id, "account_id"):
        return _json({"success": False, "error": error})
    if error := _require(parent_folder_id, "parent_folder_id"):
        return _json({"success": False, "error": error})
    if error := _require(folder_name, "folder_name"):
        return _json({"success": False, "error": error})

    target = folder_name.strip().casefold()
    visited: set[str] = set()
    if error := _id_error(account_id=account_id, parent_folder_id=parent_folder_id):
        return error
    safe_account = _seg(account_id, "account_id")

    def search(folder_id: str, depth: int) -> dict[str, Any] | None:
        if depth > max_depth:
            return None
        if folder_id in visited:
            return None
        visited.add(folder_id)
        safe_folder = _seg(folder_id, "folder_id")
        path = f"/accounts/{safe_account}/folders/{safe_folder}/children"
        for item in _iter_all_children(path):
            name = str(item.get("name") or item.get("display_name") or "")
            item_id = str(item.get("id") or item.get("folder_id") or "")
            item_type = str(item.get("type") or item.get("asset_type") or "").casefold()
            is_folder = "folder" in item_type
            if is_folder and name.casefold() == target:
                return item
            if item_id and is_folder:
                found = search(item_id, depth + 1)
                if found:
                    return found
        return None

    try:
        found = search(parent_folder_id, 0)
    except PermissionError as exc:
        return _auth_required(str(exc) or "not_authenticated")
    except Exception as exc:
        return _json({"success": False, "auth_required": False, "auth_mode": _auth_mode(), "error": str(exc)})

    if found:
        cache = _load_cache()
        cache.setdefault("folders", {})[folder_name] = found.get("id") or found.get("folder_id")
        _save_cache(cache)
        return _json({"success": True, "found": True, "folder": found, "cache_file": str(_cache_file())})
    return _json({"success": True, "found": False, "folder": None})


def frameio_create_folder(account_id: str, parent_folder_id: str, name: str) -> str:
    for value, label in [(account_id, "account_id"), (parent_folder_id, "parent_folder_id"), (name, "name")]:
        if error := _require(value, label):
            return _json({"success": False, "error": error})
    if error := _id_error(account_id=account_id, parent_folder_id=parent_folder_id):
        return error
    safe_account = _seg(account_id, "account_id")
    safe_folder = _seg(parent_folder_id, "parent_folder_id")
    body = {"data": {"name": name}}
    return _json(_safe_api_call(lambda: _api_post(f"/accounts/{safe_account}/folders/{safe_folder}/folders", body)))


def frameio_create_remote_upload(account_id: str, folder_id: str, name: str, source_url: str) -> str:
    for value, label in [(account_id, "account_id"), (folder_id, "folder_id"), (name, "name"), (source_url, "source_url")]:
        if error := _require(value, label):
            return _json({"success": False, "error": error})
    if error := _id_error(account_id=account_id, folder_id=folder_id):
        return error
    safe_account = _seg(account_id, "account_id")
    safe_folder = _seg(folder_id, "folder_id")
    body = {"data": {"name": name, "source_url": source_url}}
    return _json(_safe_api_call(lambda: _api_post(f"/accounts/{safe_account}/folders/{safe_folder}/files/remote_upload", body)))


def _upload_urls_from_response(response: Any) -> list[dict[str, Any]]:
    if not isinstance(response, dict):
        return []
    data = response.get("data") if isinstance(response.get("data"), dict) else response
    urls = data.get("upload_urls") if isinstance(data, dict) else None
    return [item for item in urls if isinstance(item, dict)] if isinstance(urls, list) else []


def _file_id_from_response(response: Any) -> str:
    if not isinstance(response, dict):
        return ""
    data = response.get("data") if isinstance(response.get("data"), dict) else response
    return str(data.get("id") or "") if isinstance(data, dict) else ""


_BLOCKED_UPLOAD_DIRS = (".ssh", ".aws", ".gnupg", ".config")
_BLOCKED_UPLOAD_NAMES = (".env", "*.pem", "*.key", "id_rsa*", "id_ed25519*", AUTH_FILENAME)


def _upload_path_violation(path: Path) -> str | None:
    """Return the rule a local upload path violates, or None if it may be uploaded."""
    expanded = path.expanduser()
    try:
        resolved = expanded.resolve()
        hermes_home = get_hermes_home().resolve()
        user_home = Path.home().resolve()
    except (OSError, RuntimeError) as exc:
        return f"path could not be resolved ({exc})"

    def _within(base: Path) -> bool:
        return resolved == base or base in resolved.parents

    if _within(hermes_home):
        return "path is inside the Hermes home directory"
    for dirname in _BLOCKED_UPLOAD_DIRS:
        if _within(user_home / dirname):
            return f"path is inside ~/{dirname}"
    for candidate in (expanded, resolved):
        if any(part.startswith(".") and part not in (".", "..") for part in candidate.parts):
            return "path has a component starting with a dot (hidden file or directory)"
    for candidate in (expanded, resolved):
        lowered = candidate.name.casefold()
        if any(fnmatch.fnmatch(lowered, pattern.casefold()) for pattern in _BLOCKED_UPLOAD_NAMES):
            return "file name looks like a credential file (.env, *.pem, *.key, id_rsa*, id_ed25519*, frameio_auth.json)"
    return None


def frameio_upload_file(account_id: str, folder_id: str, file_path: str, name: str = "") -> str:
    for value, label in [(account_id, "account_id"), (folder_id, "folder_id"), (file_path, "file_path")]:
        if error := _require(value, label):
            return _json({"success": False, "error": error})
    path = Path(file_path).expanduser()
    if violation := _upload_path_violation(path):
        return _json({"success": False, "error": f"file_path refused: {violation}"})
    if not path.exists() or not path.is_file():
        return _json({"success": False, "error": f"file_path does not exist or is not a file: {path}"})
    upload_name = name or path.name
    file_size = path.stat().st_size
    content_type = mimetypes.guess_type(upload_name)[0] or "application/octet-stream"
    if error := _id_error(account_id=account_id, folder_id=folder_id):
        return error
    safe_account = _seg(account_id, "account_id")
    safe_folder = _seg(folder_id, "folder_id")

    def do_upload() -> dict[str, Any]:
        create_response = _api_post(
            f"/accounts/{safe_account}/folders/{safe_folder}/files/local_upload",
            {"data": {"name": upload_name, "file_size": file_size}},
        )
        upload_urls = _upload_urls_from_response(create_response)
        if not upload_urls:
            raise RuntimeError("Frame.io create response contained no upload URLs; nothing was uploaded")
        for index, part in enumerate(upload_urls, start=1):
            parsed = urllib.parse.urlparse(str(part.get("url") or ""))
            if parsed.scheme != "https" or not parsed.netloc:
                raise RuntimeError(f"Upload URL at index {index} is not an https URL; refusing to upload")
        bytes_uploaded = 0
        with path.open("rb") as handle:
            for index, part in enumerate(upload_urls, start=1):
                part_size = int(part.get("size") or 0)
                upload_url = str(part.get("url") or "")
                if not part_size or not upload_url:
                    raise RuntimeError(f"Invalid upload_urls entry at index {index}")
                chunk = handle.read(part_size)
                if len(chunk) != part_size:
                    raise RuntimeError(f"Unexpected EOF while reading upload chunk {index}")
                _http_put_bytes(upload_url, chunk, headers={"x-amz-acl": "private", "Content-Type": content_type})
                bytes_uploaded += len(chunk)
        if bytes_uploaded != file_size:
            raise RuntimeError(f"Uploaded {bytes_uploaded} bytes but file size is {file_size}; upload is incomplete")
        return {
            "file": create_response,
            "file_id": _file_id_from_response(create_response),
            "chunks_uploaded": len(upload_urls),
            "bytes_uploaded": bytes_uploaded,
            "file_size": file_size,
        }

    return _json(_safe_api_call(do_upload))


def frameio_upload_status(account_id: str, file_id: str) -> str:
    for value, label in [(account_id, "account_id"), (file_id, "file_id")]:
        if error := _require(value, label):
            return _json({"success": False, "error": error})
    if error := _id_error(account_id=account_id, file_id=file_id):
        return error
    safe_account = _seg(account_id, "account_id")
    safe_file = _seg(file_id, "file_id")
    return _json(_safe_api_call(lambda: _api_get(f"/accounts/{safe_account}/files/{safe_file}/status")))


def frameio_get_media_links(account_id: str, file_id: str, include: str = "media_links.thumbnail,media_links.original") -> str:
    for value, label in [(account_id, "account_id"), (file_id, "file_id")]:
        if error := _require(value, label):
            return _json({"success": False, "error": error})
    if error := _id_error(account_id=account_id, file_id=file_id):
        return error
    safe_account = _seg(account_id, "account_id")
    safe_file = _seg(file_id, "file_id")
    return _json(_safe_api_call(lambda: _api_get(f"/accounts/{safe_account}/files/{safe_file}", params={"include": include})))


def frameio_create_share(
    account_id: str,
    project_id: str,
    name: str,
    asset_ids: list[str] | None = None,
    access: str = "secure",
    downloading_enabled: bool = True,
    description: str = "",
) -> str:
    for value, label in [(account_id, "account_id"), (project_id, "project_id"), (name, "name")]:
        if error := _require(value, label):
            return _json({"success": False, "error": error})
    if access not in {"public", "secure"}:
        return _json({"success": False, "error": "access must be public or secure"})
    data: dict[str, Any] = {"type": "asset", "access": access, "name": name, "downloading_enabled": downloading_enabled}
    if asset_ids:
        data["asset_ids"] = asset_ids
    if description:
        data["description"] = description
    if error := _id_error(account_id=account_id, project_id=project_id):
        return error
    safe_account = _seg(account_id, "account_id")
    safe_project = _seg(project_id, "project_id")
    return _json(_safe_api_call(lambda: _api_post(f"/accounts/{safe_account}/projects/{safe_project}/shares", {"data": data})))


def frameio_list_shares(account_id: str, project_id: str, after: str = "") -> str:
    for value, label in [(account_id, "account_id"), (project_id, "project_id")]:
        if error := _require(value, label):
            return _json({"success": False, "error": error})
    if error := _id_error(account_id=account_id, project_id=project_id):
        return error
    if error := _after_error(after):
        return error
    safe_account = _seg(account_id, "account_id")
    safe_project = _seg(project_id, "project_id")
    return _json(_list_page(f"/accounts/{safe_account}/projects/{safe_project}/shares", after))


def frameio_list_comments(account_id: str, file_id: str, after: str = "") -> str:
    for value, label in [(account_id, "account_id"), (file_id, "file_id")]:
        if error := _require(value, label):
            return _json({"success": False, "error": error})
    if error := _id_error(account_id=account_id, file_id=file_id):
        return error
    if error := _after_error(after):
        return error
    safe_account = _seg(account_id, "account_id")
    safe_file = _seg(file_id, "file_id")
    return _json(_list_page(f"/accounts/{safe_account}/files/{safe_file}/comments", after))


def frameio_create_comment(account_id: str, file_id: str, text: str, timestamp: str = "") -> str:
    for value, label in [(account_id, "account_id"), (file_id, "file_id"), (text, "text")]:
        if error := _require(value, label):
            return _json({"success": False, "error": error})
    data: dict[str, Any] = {"text": text}
    if timestamp:
        data["timestamp"] = timestamp
    if error := _id_error(account_id=account_id, file_id=file_id):
        return error
    safe_account = _seg(account_id, "account_id")
    safe_file = _seg(file_id, "file_id")
    return _json(_safe_api_call(lambda: _api_post(f"/accounts/{safe_account}/files/{safe_file}/comments", {"data": data})))


# ---------------------------------------------------------------------------
# Schemas and registry
# ---------------------------------------------------------------------------


def _schema(name: str, description: str, properties: dict[str, Any] | None = None, required: list[str] | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {"type": "object", "properties": properties or {}}
    if required:
        params["required"] = required
    return {"name": name, "description": description, "parameters": params}


UUID_PROP = {"type": "string", "description": "Frame.io UUID."}
AFTER_PROP = {
    "type": "string",
    "description": "Optional pagination cursor: pass the previous response's next_after to fetch the next page.",
}

FRAMEIO_LOGIN_SCHEMA = _schema(
    "frameio_login",
    "Start or complete Adobe IMS OAuth for Frame.io V4. In legacy-token mode, reports that legacy auth is configured.",
    {
        "code": {"type": "string", "description": "OAuth authorization code from Adobe IMS callback."},
        "state": {"type": "string", "description": "Optional opaque OAuth state value to include in the authorization URL."},
    },
)
FRAMEIO_STATUS_SCHEMA = _schema("frameio_status", "Show Frame.io auth/config status without printing secrets or tokens.")
FRAMEIO_ME_SCHEMA = _schema("frameio_me", "Show Frame.io V4 current user details.")
FRAMEIO_LIST_ACCOUNTS_SCHEMA = _schema(
    "frameio_list_accounts",
    "List Frame.io V4 accounts for the authenticated user.",
    {"after": AFTER_PROP},
)
FRAMEIO_LIST_WORKSPACES_SCHEMA = _schema(
    "frameio_list_workspaces",
    "List workspaces under a Frame.io account.",
    {"account_id": UUID_PROP, "after": AFTER_PROP},
    ["account_id"],
)
FRAMEIO_LIST_PROJECTS_SCHEMA = _schema(
    "frameio_list_projects",
    "List projects under a Frame.io account/workspace.",
    {"account_id": UUID_PROP, "workspace_id": UUID_PROP, "after": AFTER_PROP},
    ["account_id", "workspace_id"],
)
FRAMEIO_LIST_FOLDER_CHILDREN_SCHEMA = _schema(
    "frameio_list_folder_children",
    "List children of a Frame.io folder. Use a project's root_folder_id for top-level project contents.",
    {"account_id": UUID_PROP, "folder_id": UUID_PROP, "include": {"type": "string", "description": "Optional include query, e.g. media_links.thumbnail."}, "after": AFTER_PROP},
    ["account_id", "folder_id"],
)
FRAMEIO_FIND_FOLDER_SCHEMA = _schema(
    "frameio_find_folder",
    "Find a Frame.io folder by friendly name below a parent folder and cache its ID locally.",
    {
        "account_id": UUID_PROP,
        "folder_name": {"type": "string", "description": "Folder friendly name to find."},
        "parent_folder_id": UUID_PROP,
        "max_depth": {"type": "integer", "description": "Maximum recursive search depth.", "default": 4},
    },
    ["account_id", "folder_name", "parent_folder_id"],
)
FRAMEIO_CREATE_FOLDER_SCHEMA = _schema(
    "frameio_create_folder",
    "Create a folder inside a parent Frame.io folder.",
    {"account_id": UUID_PROP, "parent_folder_id": UUID_PROP, "name": {"type": "string", "description": "New folder name."}},
    ["account_id", "parent_folder_id", "name"],
)
FRAMEIO_UPLOAD_FILE_SCHEMA = _schema(
    "frameio_upload_file",
    "Upload a local file to Frame.io using V4 local-upload pre-signed URLs.",
    {
        "account_id": UUID_PROP,
        "folder_id": UUID_PROP,
        "file_path": {"type": "string", "description": "Local path to upload."},
        "name": {"type": "string", "description": "Optional destination file name."},
    },
    ["account_id", "folder_id", "file_path"],
)
FRAMEIO_CREATE_REMOTE_UPLOAD_SCHEMA = _schema(
    "frameio_create_remote_upload",
    "Create a Frame.io remote upload from a source URL.",
    {
        "account_id": UUID_PROP,
        "folder_id": UUID_PROP,
        "name": {"type": "string", "description": "Destination file name."},
        "source_url": {"type": "string", "description": "Source URL for Frame.io to fetch."},
    },
    ["account_id", "folder_id", "name", "source_url"],
)
FRAMEIO_UPLOAD_STATUS_SCHEMA = _schema(
    "frameio_upload_status",
    "Show Frame.io file upload/processing status.",
    {"account_id": UUID_PROP, "file_id": UUID_PROP},
    ["account_id", "file_id"],
)
FRAMEIO_GET_MEDIA_LINKS_SCHEMA = _schema(
    "frameio_get_media_links",
    "Fetch fresh temporary media links for a Frame.io file.",
    {"account_id": UUID_PROP, "file_id": UUID_PROP, "include": {"type": "string", "description": "Include query for media_links."}},
    ["account_id", "file_id"],
)
FRAMEIO_CREATE_SHARE_SCHEMA = _schema(
    "frameio_create_share",
    "Create a Frame.io share/review link for asset IDs.",
    {
        "account_id": UUID_PROP,
        "project_id": UUID_PROP,
        "name": {"type": "string", "description": "Share name."},
        "asset_ids": {"type": "array", "items": {"type": "string"}, "description": "File/folder/version stack IDs to share."},
        "access": {"type": "string", "enum": ["public", "secure"], "default": "secure", "description": "Defaults to secure; use public only when explicitly requested."},
        "downloading_enabled": {"type": "boolean", "default": True},
        "description": {"type": "string", "description": "Optional share description."},
    },
    ["account_id", "project_id", "name"],
)
FRAMEIO_LIST_SHARES_SCHEMA = _schema(
    "frameio_list_shares",
    "List shares under a Frame.io project.",
    {"account_id": UUID_PROP, "project_id": UUID_PROP, "after": AFTER_PROP},
    ["account_id", "project_id"],
)
FRAMEIO_LIST_COMMENTS_SCHEMA = _schema(
    "frameio_list_comments",
    "List comments on a Frame.io file.",
    {"account_id": UUID_PROP, "file_id": UUID_PROP, "after": AFTER_PROP},
    ["account_id", "file_id"],
)
FRAMEIO_CREATE_COMMENT_SCHEMA = _schema(
    "frameio_create_comment",
    "Create a text comment on a Frame.io file.",
    {
        "account_id": UUID_PROP,
        "file_id": UUID_PROP,
        "text": {"type": "string", "description": "Comment text."},
        "timestamp": {"type": "string", "description": "Optional Frame.io timestamp value."},
    },
    ["account_id", "file_id", "text"],
)


def _register(name: str, schema: dict[str, Any], handler: Any, description: str) -> None:
    registry.register(
        name=name,
        toolset="frameio",
        schema=schema,
        handler=handler,
        check_fn=_check_frameio_available,
        requires_env=["FRAMEIO_CLIENT_ID or FRAMEIO_LEGACY_TOKEN"],
        description=description,
        emoji="🎞️",
    )


_register("frameio_login", FRAMEIO_LOGIN_SCHEMA, lambda args, **kw: frameio_login(code=args.get("code", ""), state=args.get("state", "")), "Start or complete Frame.io OAuth.")
_register("frameio_status", FRAMEIO_STATUS_SCHEMA, lambda args, **kw: frameio_status(), "Show Frame.io auth status.")
_register("frameio_me", FRAMEIO_ME_SCHEMA, lambda args, **kw: frameio_me(), "Show Frame.io current user.")
_register("frameio_list_accounts", FRAMEIO_LIST_ACCOUNTS_SCHEMA, lambda args, **kw: frameio_list_accounts(after=args.get("after", "")), "List Frame.io accounts.")
_register("frameio_list_workspaces", FRAMEIO_LIST_WORKSPACES_SCHEMA, lambda args, **kw: frameio_list_workspaces(account_id=args.get("account_id", ""), after=args.get("after", "")), "List Frame.io workspaces.")
_register("frameio_list_projects", FRAMEIO_LIST_PROJECTS_SCHEMA, lambda args, **kw: frameio_list_projects(account_id=args.get("account_id", ""), workspace_id=args.get("workspace_id", ""), after=args.get("after", "")), "List Frame.io projects.")
_register("frameio_list_folder_children", FRAMEIO_LIST_FOLDER_CHILDREN_SCHEMA, lambda args, **kw: frameio_list_folder_children(account_id=args.get("account_id", ""), folder_id=args.get("folder_id", ""), include=args.get("include", ""), after=args.get("after", "")), "List Frame.io folder children.")
_register(
    "frameio_find_folder",
    FRAMEIO_FIND_FOLDER_SCHEMA,
    lambda args, **kw: frameio_find_folder(
        account_id=args.get("account_id", ""),
        folder_name=args.get("folder_name", ""),
        parent_folder_id=args.get("parent_folder_id", ""),
        max_depth=int(args.get("max_depth", 4) or 4),
    ),
    "Find a Frame.io folder by name.",
)
_register("frameio_create_folder", FRAMEIO_CREATE_FOLDER_SCHEMA, lambda args, **kw: frameio_create_folder(account_id=args.get("account_id", ""), parent_folder_id=args.get("parent_folder_id", ""), name=args.get("name", "")), "Create Frame.io folder.")
_register("frameio_upload_file", FRAMEIO_UPLOAD_FILE_SCHEMA, lambda args, **kw: frameio_upload_file(account_id=args.get("account_id", ""), folder_id=args.get("folder_id", ""), file_path=args.get("file_path", ""), name=args.get("name", "")), "Upload local file to Frame.io.")
_register("frameio_create_remote_upload", FRAMEIO_CREATE_REMOTE_UPLOAD_SCHEMA, lambda args, **kw: frameio_create_remote_upload(account_id=args.get("account_id", ""), folder_id=args.get("folder_id", ""), name=args.get("name", ""), source_url=args.get("source_url", "")), "Create Frame.io remote upload.")
_register("frameio_upload_status", FRAMEIO_UPLOAD_STATUS_SCHEMA, lambda args, **kw: frameio_upload_status(account_id=args.get("account_id", ""), file_id=args.get("file_id", "")), "Show Frame.io upload status.")
_register("frameio_get_media_links", FRAMEIO_GET_MEDIA_LINKS_SCHEMA, lambda args, **kw: frameio_get_media_links(account_id=args.get("account_id", ""), file_id=args.get("file_id", ""), include=args.get("include", "media_links.thumbnail,media_links.original")), "Fetch Frame.io media links.")
_register(
    "frameio_create_share",
    FRAMEIO_CREATE_SHARE_SCHEMA,
    lambda args, **kw: frameio_create_share(
        account_id=args.get("account_id", ""),
        project_id=args.get("project_id", ""),
        name=args.get("name", ""),
        asset_ids=args.get("asset_ids") or [],
        access=args.get("access", "secure"),
        downloading_enabled=bool(args.get("downloading_enabled", True)),
        description=args.get("description", ""),
    ),
    "Create Frame.io share/review link.",
)
_register("frameio_list_shares", FRAMEIO_LIST_SHARES_SCHEMA, lambda args, **kw: frameio_list_shares(account_id=args.get("account_id", ""), project_id=args.get("project_id", ""), after=args.get("after", "")), "List Frame.io shares.")
_register("frameio_list_comments", FRAMEIO_LIST_COMMENTS_SCHEMA, lambda args, **kw: frameio_list_comments(account_id=args.get("account_id", ""), file_id=args.get("file_id", ""), after=args.get("after", "")), "List Frame.io comments.")
_register("frameio_create_comment", FRAMEIO_CREATE_COMMENT_SCHEMA, lambda args, **kw: frameio_create_comment(account_id=args.get("account_id", ""), file_id=args.get("file_id", ""), text=args.get("text", ""), timestamp=args.get("timestamp", "")), "Create Frame.io comment.")
