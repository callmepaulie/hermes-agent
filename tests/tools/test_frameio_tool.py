"""Tests for the Frame.io V4 Hermes toolset.

Phase 1 covers OAuth setup/status and safe discovery behavior. Tests avoid live
network calls and verify secrets are not emitted in tool responses.
"""

import json
import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def clean_frameio_env(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    for name in [
        "FRAMEIO_CLIENT_ID",
        "FRAMEIO_CLIENT_SECRET",
        "FRAMEIO_REDIRECT_URI",
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
    assert result["api_base"] == "https://api.frame.io/v4"
    assert result["auth_file"].endswith("frameio_auth.json")


def test_login_returns_adobe_authorization_url_without_secret(monkeypatch):
    from tools import frameio_tool

    monkeypatch.setenv("FRAMEIO_CLIENT_ID", "client_123")
    monkeypatch.setenv("FRAMEIO_CLIENT_SECRET", "super-secret-value")

    result = json.loads(frameio_tool.frameio_login())

    assert result["success"] is True
    assert result["auth_required"] is True
    assert result["authorize_url"].startswith("https://ims-na1.adobelogin.com/ims/authorize/v2?")
    assert "client_id=client_123" in result["authorize_url"]
    assert "redirect_uri=http%3A%2F%2F127.0.0.1%3A43828%2Fframeio%2Fcallback" in result["authorize_url"]
    assert "offline_access" in result["authorize_url"]
    serialized = json.dumps(result)
    assert "super-secret-value" not in serialized
    assert "client_secret" not in serialized


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
        frameio_tool.frameio_list_accounts(),
        frameio_tool.frameio_list_workspaces("acct_1"),
        frameio_tool.frameio_list_projects("workspace_1"),
        frameio_tool.frameio_list_folder_children("project_1", "folder_1"),
        frameio_tool.frameio_find_folder("project_1", "Review Exports"),
    ]:
        result = json.loads(payload)
        assert result["success"] is False
        assert result["auth_required"] is True
        assert result["error"] == "not_authenticated"


def test_api_get_uses_bearer_token_and_frameio_v4_base(monkeypatch, tmp_path):
    from tools import frameio_tool

    frameio_tool._auth_file().write_text(
        json.dumps({"access_token": "access-123", "refresh_token": "refresh-456"}),
        encoding="utf-8",
    )
    observed = {}

    def fake_request(method, url, *, headers=None, data=None):
        observed["method"] = method
        observed["url"] = url
        observed["headers"] = headers or {}
        return {"ok": True}

    monkeypatch.setattr(frameio_tool, "_http_json", fake_request)

    result = frameio_tool._api_get("/accounts")

    assert result == {"ok": True}
    assert observed["method"] == "GET"
    assert observed["url"] == "https://api.frame.io/v4/accounts"
    assert observed["headers"]["Authorization"] == "Bearer access-123"


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
    env["FRAMEIO_CLIENT_ID"] = "client_123"
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert "frameio_status" in payload["names"]
    assert "frameio_login" in payload["defs"]
    assert "frameio_list_accounts" in payload["defs"]
