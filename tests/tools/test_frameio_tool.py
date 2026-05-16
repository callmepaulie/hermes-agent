"""Tests for the Frame.io V4 Hermes toolset.

Covers OAuth setup/status, legacy-token mode, safe discovery behavior, request
routing, and secret-safe tool discovery. Tests avoid live network calls.
"""

import json
import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def clean_frameio_env(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    for name in [
        "FRAMEIO_AUTH_MODE",
        "FRAMEIO_CLIENT_ID",
        "FRAMEIO_CLIENT_SECRET",
        "FRAMEIO_REDIRECT_URI",
        "FRAMEIO_LEGACY_TOKEN",
    ]:
        monkeypatch.delenv(name, raising=False)
    yield tmp_path


def test_status_reports_unconfigured_without_token():
    from tools import frameio_tool

    result = json.loads(frameio_tool.frameio_status())

    assert result["success"] is True
    assert result["configured"] is False
    assert result["authenticated"] is False
    assert result["auth_required"] is True
    assert result["auth_mode"] == "oauth"
    assert result["api_base"] == "https://api.frame.io/v4"
    assert result["auth_file"].endswith("frameio_auth.json")


def test_status_reports_legacy_mode_without_printing_token(monkeypatch):
    from tools import frameio_tool

    monkeypatch.setenv("FRAMEIO_LEGACY_TOKEN", "fio_legacy_secret")

    result = json.loads(frameio_tool.frameio_status())

    assert result["success"] is True
    assert result["configured"] is True
    assert result["authenticated"] is True
    assert result["auth_required"] is False
    assert result["auth_mode"] == "legacy"
    assert result["legacy_configured"] is True
    assert "fio_legacy_secret" not in json.dumps(result)


def test_login_returns_adobe_authorization_url_without_secret(monkeypatch):
    from tools import frameio_tool

    monkeypatch.setenv("FRAMEIO_CLIENT_ID", "client_123")
    monkeypatch.setenv("FRAMEIO_CLIENT_SECRET", "super-secret-value")

    result = json.loads(frameio_tool.frameio_login())

    assert result["success"] is True
    assert result["auth_required"] is True
    assert result["auth_mode"] == "oauth"
    assert result["authorize_url"].startswith("https://ims-na1.adobelogin.com/ims/authorize/v2?")
    assert "client_id=client_123" in result["authorize_url"]
    assert "redirect_uri=http%3A%2F%2F127.0.0.1%3A43828%2Fframeio%2Fcallback" in result["authorize_url"]
    assert "offline_access" in result["authorize_url"]
    serialized = json.dumps(result)
    assert "super-secret-value" not in serialized
    assert "client_secret" not in serialized


def test_login_short_circuits_in_legacy_mode(monkeypatch):
    from tools import frameio_tool

    monkeypatch.setenv("FRAMEIO_LEGACY_TOKEN", "fio_legacy_secret")

    result = json.loads(frameio_tool.frameio_login())

    assert result["success"] is True
    assert result["auth_required"] is False
    assert result["authenticated"] is True
    assert result["auth_mode"] == "legacy"
    assert "fio_legacy_secret" not in json.dumps(result)


def test_login_reports_missing_client_id_before_browser_flow():
    from tools import frameio_tool

    result = json.loads(frameio_tool.frameio_login())

    assert result["success"] is False
    assert result["auth_required"] is True
    assert result["error"] == "missing_config"
    assert "FRAMEIO_CLIENT_ID" in result["missing_env"]


def test_discovery_tools_return_auth_required_without_token():
    from tools import frameio_tool

    for payload in [
        frameio_tool.frameio_me(),
        frameio_tool.frameio_list_accounts(),
        frameio_tool.frameio_list_workspaces("acct_1"),
        frameio_tool.frameio_list_projects("acct_1", "workspace_1"),
        frameio_tool.frameio_list_folder_children("acct_1", "folder_1"),
        frameio_tool.frameio_find_folder("acct_1", "Review Exports", "folder_1"),
        frameio_tool.frameio_upload_status("acct_1", "file_1"),
        frameio_tool.frameio_get_media_links("acct_1", "file_1"),
        frameio_tool.frameio_list_shares("acct_1", "project_1"),
        frameio_tool.frameio_list_comments("acct_1", "file_1"),
    ]:
        result = json.loads(payload)
        assert result["success"] is False
        assert result["auth_required"] is True
        assert result["error"] == "not_authenticated"


def test_api_get_uses_bearer_token_and_frameio_v4_base(monkeypatch):
    from tools import frameio_tool

    frameio_tool._auth_file().write_text(
        json.dumps({"access_token": "access-123", "refresh_token": "refresh-456"}),
        encoding="utf-8",
    )
    observed = {}

    def fake_request(method, url, *, headers=None, data=None, json_body=None):
        observed["method"] = method
        observed["url"] = url
        observed["headers"] = headers or {}
        observed["json_body"] = json_body
        return {"ok": True}

    monkeypatch.setattr(frameio_tool, "_http_json", fake_request)

    result = frameio_tool._api_get("/accounts")

    assert result == {"ok": True}
    assert observed["method"] == "GET"
    assert observed["url"] == "https://api.frame.io/v4/accounts"
    assert observed["headers"]["Authorization"] == "Bearer access-123"
    assert "x-frameio-legacy-token-auth" not in observed["headers"]


def test_api_get_uses_legacy_header_when_legacy_token_present(monkeypatch):
    from tools import frameio_tool

    monkeypatch.setenv("FRAMEIO_LEGACY_TOKEN", "legacy-123")
    observed = {}

    def fake_request(method, url, *, headers=None, data=None, json_body=None):
        observed["method"] = method
        observed["url"] = url
        observed["headers"] = headers or {}
        return {"ok": True}

    monkeypatch.setattr(frameio_tool, "_http_json", fake_request)

    result = frameio_tool._api_get("/me")

    assert result == {"ok": True}
    assert observed["url"] == "https://api.frame.io/v4/me"
    assert observed["headers"]["Authorization"] == "Bearer legacy-123"
    assert observed["headers"]["x-frameio-legacy-token-auth"] == "true"


def test_projects_use_account_workspace_endpoint(monkeypatch):
    from tools import frameio_tool

    frameio_tool._auth_file().write_text(json.dumps({"access_token": "access-123"}), encoding="utf-8")
    observed = {}

    def fake_request(method, url, *, headers=None, data=None, json_body=None):
        observed["url"] = url
        return {"data": []}

    monkeypatch.setattr(frameio_tool, "_http_json", fake_request)

    result = json.loads(frameio_tool.frameio_list_projects("acct 1", "workspace 1"))

    assert result["success"] is True
    assert observed["url"] == "https://api.frame.io/v4/accounts/acct%201/workspaces/workspace%201/projects"


def test_create_share_builds_expected_v4_payload(monkeypatch):
    from tools import frameio_tool

    frameio_tool._auth_file().write_text(json.dumps({"access_token": "access-123"}), encoding="utf-8")
    observed = {}

    def fake_request(method, url, *, headers=None, data=None, json_body=None):
        observed["method"] = method
        observed["url"] = url
        observed["json_body"] = json_body
        return {"data": {"id": "share_1"}}

    monkeypatch.setattr(frameio_tool, "_http_json", fake_request)

    result = json.loads(
        frameio_tool.frameio_create_share(
            "acct_1",
            "project_1",
            "Review Link",
            asset_ids=["file_1"],
            access="public",
            downloading_enabled=False,
        )
    )

    assert result["success"] is True
    assert observed["method"] == "POST"
    assert observed["url"] == "https://api.frame.io/v4/accounts/acct_1/projects/project_1/shares"
    assert observed["json_body"] == {
        "data": {
            "type": "asset",
            "access": "public",
            "name": "Review Link",
            "downloading_enabled": False,
            "asset_ids": ["file_1"],
        }
    }


def test_upload_file_creates_local_upload_and_puts_chunks(monkeypatch, tmp_path):
    from tools import frameio_tool

    frameio_tool._auth_file().write_text(json.dumps({"access_token": "access-123"}), encoding="utf-8")
    media = tmp_path / "clip.txt"
    media.write_bytes(b"abcdef")
    api_calls = []
    put_calls = []

    def fake_request(method, url, *, headers=None, data=None, json_body=None):
        api_calls.append((method, url, json_body))
        return {
            "data": {
                "id": "file_1",
                "upload_urls": [
                    {"size": 3, "url": "https://upload.example/part1"},
                    {"size": 3, "url": "https://upload.example/part2"},
                ],
            }
        }

    def fake_put(url, payload, headers=None):
        put_calls.append((url, payload, headers or {}))

    monkeypatch.setattr(frameio_tool, "_http_json", fake_request)
    monkeypatch.setattr(frameio_tool, "_http_put_bytes", fake_put)

    result = json.loads(frameio_tool.frameio_upload_file("acct_1", "folder_1", str(media)))

    assert result["success"] is True
    assert result["data"]["file_id"] == "file_1"
    assert result["data"]["bytes_uploaded"] == 6
    assert api_calls[0] == (
        "POST",
        "https://api.frame.io/v4/accounts/acct_1/folders/folder_1/files/local_upload",
        {"data": {"name": "clip.txt", "file_size": 6}},
    )
    assert put_calls[0][0] == "https://upload.example/part1"
    assert put_calls[0][1] == b"abc"
    assert put_calls[0][2]["x-amz-acl"] == "private"
    assert put_calls[0][2]["Content-Type"] == "text/plain"
    assert put_calls[1][1] == b"def"
    assert put_calls[1][2]["Content-Type"] == "text/plain"


def test_upload_file_uses_destination_name_for_signed_content_type(monkeypatch, tmp_path):
    """Regression for Frame.io/S3 SignatureDoesNotMatch on signed content-type.

    Live UAT showed Frame.io signs content-type in local-upload URLs. A local
    source path without a useful extension must still PUT with the MIME type
    implied by the Frame.io destination name, or S3 rejects the upload.
    """

    from tools import frameio_tool

    frameio_tool._auth_file().write_text(json.dumps({"access_token": "access-123"}), encoding="utf-8")
    media = tmp_path / "payload"
    media.write_bytes(b"hello")
    put_calls = []

    def fake_request(method, url, *, headers=None, data=None, json_body=None):
        return {
            "data": {
                "id": "file_1",
                "upload_urls": [{"size": 5, "url": "https://upload.example/part1"}],
            }
        }

    def fake_put(url, payload, headers=None):
        put_calls.append((url, payload, headers or {}))

    monkeypatch.setattr(frameio_tool, "_http_json", fake_request)
    monkeypatch.setattr(frameio_tool, "_http_put_bytes", fake_put)

    result = json.loads(frameio_tool.frameio_upload_file("acct_1", "folder_1", str(media), name="review-notes.txt"))

    assert result["success"] is True
    assert put_calls[0][2]["Content-Type"] == "text/plain"


def test_http_json_sets_frameio_api_headers_by_default(monkeypatch):
    """Regression for Frame.io HTML 403s when Accept/User-Agent are absent."""

    from tools import frameio_tool

    observed = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b'{"ok": true}'

    def fake_urlopen(req, timeout=30):
        observed["timeout"] = timeout
        observed["headers"] = dict(req.header_items())
        return FakeResponse()

    monkeypatch.setattr(frameio_tool.urllib.request, "urlopen", fake_urlopen)

    result = frameio_tool._http_json("GET", "https://api.frame.io/v4/me")

    assert result == {"ok": True}
    assert observed["headers"]["Accept"] == "application/json"
    assert observed["headers"]["User-agent"] == "HermesFrameio/1.0"


def test_save_auth_state_writes_under_hermes_home(tmp_path):
    from tools import frameio_tool

    frameio_tool._save_auth_state({"access_token": "token", "refresh_token": "refresh"})

    auth_file = tmp_path / "frameio_auth.json"
    assert auth_file.exists()
    saved = json.loads(auth_file.read_text(encoding="utf-8"))
    assert saved["access_token"] == "token"
    default_auth = Path.home().joinpath(".hermes", "frameio_auth.json")
    assert not default_auth.exists() or not default_auth.samefile(auth_file)


def test_model_tools_discovers_frameio_toolset_in_fresh_process(tmp_path):
    import subprocess
    import sys

    code = """
import json
from model_tools import TOOL_TO_TOOLSET_MAP, get_tool_definitions
names = sorted(k for k, v in TOOL_TO_TOOLSET_MAP.items() if v == 'frameio')
defs = sorted(d['function']['name'] for d in get_tool_definitions(enabled_toolsets=['frameio'], quiet_mode=True))
print(json.dumps({'names': names, 'defs': defs}))
"""
    env = os.environ.copy()
    env["HERMES_HOME"] = str(tmp_path)
    env["FRAMEIO_LEGACY_TOKEN"] = "legacy_123"
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    for expected in [
        "frameio_status",
        "frameio_login",
        "frameio_me",
        "frameio_list_accounts",
        "frameio_upload_file",
        "frameio_create_share",
        "frameio_create_comment",
    ]:
        assert expected in payload["names"]
        assert expected in payload["defs"]
