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

    result = json.loads(frameio_tool.frameio_list_projects("acct_1", "workspace_1"))

    assert result["success"] is True
    assert observed["url"] == "https://api.frame.io/v4/accounts/acct_1/workspaces/workspace_1/projects"


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


def test_upload_file_creates_local_upload_and_puts_chunks(monkeypatch, tmp_path, tmp_path_factory):
    from tools import frameio_tool

    frameio_tool._auth_file().write_text(json.dumps({"access_token": "access-123"}), encoding="utf-8")
    media = tmp_path_factory.mktemp("media") / "clip.txt"
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


def test_upload_file_uses_destination_name_for_signed_content_type(monkeypatch, tmp_path, tmp_path_factory):
    """Regression for Frame.io/S3 SignatureDoesNotMatch on signed content-type.

    Live UAT showed Frame.io signs content-type in local-upload URLs. A local
    source path without a useful extension must still PUT with the MIME type
    implied by the Frame.io destination name, or S3 rejects the upload.
    """

    from tools import frameio_tool

    frameio_tool._auth_file().write_text(json.dumps({"access_token": "access-123"}), encoding="utf-8")
    media = tmp_path_factory.mktemp("media") / "payload"
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


# ---------------------------------------------------------------------------
# Hardening regressions
# ---------------------------------------------------------------------------


def _write_token(frameio_tool, **extra):
    frameio_tool._auth_file().write_text(json.dumps({"access_token": "access-123", **extra}), encoding="utf-8")


@pytest.mark.parametrize("bad", ["a/b", "..", "a..b", "a\\b", "a?x=1", "a#f", "a b", "a\tb", "../x"])
def test_ids_with_path_or_query_characters_are_rejected_before_any_request(monkeypatch, bad):
    from tools import frameio_tool

    _write_token(frameio_tool)
    calls = []
    monkeypatch.setattr(frameio_tool, "_http_json", lambda *a, **k: calls.append(a) or {})

    results = [
        frameio_tool.frameio_list_workspaces(bad),
        frameio_tool.frameio_list_projects("acct_1", bad),
        frameio_tool.frameio_list_folder_children("acct_1", bad),
        frameio_tool.frameio_find_folder("acct_1", "x", bad),
        frameio_tool.frameio_create_folder(bad, "folder_1", "n"),
        frameio_tool.frameio_create_remote_upload("acct_1", bad, "n", "https://x.example/f"),
        frameio_tool.frameio_upload_status("acct_1", bad),
        frameio_tool.frameio_get_media_links("acct_1", bad),
        frameio_tool.frameio_create_share("acct_1", bad, "n"),
        frameio_tool.frameio_list_shares(bad, "project_1"),
        frameio_tool.frameio_list_comments("acct_1", bad),
        frameio_tool.frameio_create_comment("acct_1", bad, "hi"),
    ]
    for raw in results:
        parsed = json.loads(raw)
        assert parsed["success"] is False
        assert "not allowed in an id" in parsed["error"]
    assert calls == []


def test_find_folder_rejects_unsafe_ids_returned_by_the_api(monkeypatch):
    from tools import frameio_tool

    _write_token(frameio_tool)
    urls = []

    def fake_request(method, url, *, headers=None, data=None, json_body=None):
        urls.append(url)
        return {"data": [{"id": "../../admin", "name": "sub", "type": "folder"}]}

    monkeypatch.setattr(frameio_tool, "_http_json", fake_request)

    result = json.loads(frameio_tool.frameio_find_folder("acct_1", "missing", "root_1"))

    assert result["success"] is False
    assert len(urls) == 1


def test_find_folder_follows_next_page_links(monkeypatch):
    from tools import frameio_tool

    _write_token(frameio_tool)
    urls = []

    def fake_request(method, url, *, headers=None, data=None, json_body=None):
        urls.append(url)
        if "after=" not in url:
            return {
                "data": [{"id": "f_1", "name": "Dailies", "type": "file"}],
                "links": {"next": "/v4/accounts/acct_1/folders/root_1/children?after=cur_2"},
            }
        return {"data": [{"id": "f_2", "name": "Review Exports", "type": "folder"}], "links": {"next": None}}

    monkeypatch.setattr(frameio_tool, "_http_json", fake_request)

    result = json.loads(frameio_tool.frameio_find_folder("acct_1", "Review Exports", "root_1"))

    assert result["success"] is True
    assert result["found"] is True
    assert result["folder"]["id"] == "f_2"
    assert len(urls) == 2
    assert urls[1].endswith("after=cur_2")


def test_find_folder_fails_when_more_pages_cannot_be_followed(monkeypatch):
    from tools import frameio_tool

    _write_token(frameio_tool)

    def fake_request(method, url, *, headers=None, data=None, json_body=None):
        return {"data": [], "links": {"next": "/v4/accounts/acct_1/folders/root_1/children?page=2"}}

    monkeypatch.setattr(frameio_tool, "_http_json", fake_request)

    result = json.loads(frameio_tool.frameio_find_folder("acct_1", "missing", "root_1"))

    assert result["success"] is False
    assert "incomplete" in result["error"]


def test_find_folder_ignores_a_file_with_the_requested_name(monkeypatch):
    from tools import frameio_tool

    _write_token(frameio_tool)

    def fake_request(method, url, *, headers=None, data=None, json_body=None):
        return {
            "data": [
                {"id": "file_1", "name": "Review", "type": "file"},
                {"id": "folder_9", "name": "Review", "type": "folder"},
            ]
        }

    monkeypatch.setattr(frameio_tool, "_http_json", fake_request)

    result = json.loads(frameio_tool.frameio_find_folder("acct_1", "Review", "root_1"))

    assert result["found"] is True
    assert result["folder"]["id"] == "folder_9"


def test_frameio_credentials_are_in_the_env_var_catalog():
    from hermes_cli.config import OPTIONAL_ENV_VARS

    for name in ("FRAMEIO_CLIENT_ID", "FRAMEIO_CLIENT_SECRET", "FRAMEIO_LEGACY_TOKEN"):
        assert OPTIONAL_ENV_VARS[name]["category"] == "tool"
    assert OPTIONAL_ENV_VARS["FRAMEIO_CLIENT_SECRET"]["password"] is True
    assert OPTIONAL_ENV_VARS["FRAMEIO_LEGACY_TOKEN"]["password"] is True


def test_seg_encodes_everything_unsafe_in_one_segment():
    from tools import frameio_tool

    assert frameio_tool._seg("abc-123_X") == "abc-123_X"
    assert frameio_tool._seg("a%b") == "a%25b"


def test_create_share_defaults_to_secure_access(monkeypatch):
    from tools import frameio_tool

    _write_token(frameio_tool)
    bodies = []

    def fake_request(method, url, *, headers=None, data=None, json_body=None):
        bodies.append(json_body)
        return {"data": {}}

    monkeypatch.setattr(frameio_tool, "_http_json", fake_request)

    frameio_tool.frameio_create_share("acct_1", "project_1", "Review")
    assert bodies[-1]["data"]["access"] == "secure"

    from tools.registry import registry

    registry.get_entry("frameio_create_share").handler({"account_id": "acct_1", "project_id": "project_1", "name": "n"})
    assert bodies[-1]["data"]["access"] == "secure"
    assert frameio_tool.FRAMEIO_CREATE_SHARE_SCHEMA["parameters"]["properties"]["access"]["default"] == "secure"

    frameio_tool.frameio_create_share("acct_1", "project_1", "Review", access="public")
    assert bodies[-1]["data"]["access"] == "public"


def _upload_stubs(monkeypatch, frameio_tool, create_response):
    _write_token(frameio_tool)
    puts = []
    monkeypatch.setattr(frameio_tool, "_http_json", lambda *a, **k: create_response)
    monkeypatch.setattr(frameio_tool, "_http_put_bytes", lambda url, payload, headers=None: puts.append(url))
    return puts


def test_upload_fails_when_create_response_has_no_upload_urls(monkeypatch, tmp_path_factory):
    from tools import frameio_tool

    media = tmp_path_factory.mktemp("media") / "clip.mp4"
    media.write_bytes(b"abcdef")
    _upload_stubs(monkeypatch, frameio_tool, {"data": {"id": "file_1"}})

    result = json.loads(frameio_tool.frameio_upload_file("acct_1", "folder_1", str(media)))

    assert result["success"] is False
    assert "no upload URLs" in result["error"]


def test_upload_fails_when_uploaded_bytes_differ_from_file_size(monkeypatch, tmp_path_factory):
    from tools import frameio_tool

    media = tmp_path_factory.mktemp("media") / "clip.mp4"
    media.write_bytes(b"abcdef")
    _upload_stubs(monkeypatch, frameio_tool, {"data": {"id": "f", "upload_urls": [{"size": 3, "url": "https://u.example/p1"}]}})

    result = json.loads(frameio_tool.frameio_upload_file("acct_1", "folder_1", str(media)))

    assert result["success"] is False
    assert "incomplete" in result["error"]


def test_upload_refuses_non_https_upload_urls_without_sending_bytes(monkeypatch, tmp_path_factory):
    from tools import frameio_tool

    media = tmp_path_factory.mktemp("media") / "clip.mp4"
    media.write_bytes(b"abcdef")
    puts = _upload_stubs(
        monkeypatch,
        frameio_tool,
        {"data": {"id": "f", "upload_urls": [{"size": 3, "url": "https://u.example/p1"}, {"size": 3, "url": "http://evil.example/p2"}]}},
    )

    result = json.loads(frameio_tool.frameio_upload_file("acct_1", "folder_1", str(media)))

    assert result["success"] is False
    assert "https" in result["error"]
    assert puts == []


def test_upload_refuses_sensitive_paths(monkeypatch, tmp_path, tmp_path_factory):
    from tools import frameio_tool

    fake_home = tmp_path_factory.mktemp("userhome")
    monkeypatch.setattr(frameio_tool.Path, "home", classmethod(lambda cls: fake_home))
    puts = _upload_stubs(monkeypatch, frameio_tool, {"data": {"id": "f", "upload_urls": [{"size": 1, "url": "https://u.example/p"}]}})
    media_dir = tmp_path_factory.mktemp("media")

    blocked = []
    (tmp_path / "frameio_auth.json").write_text("x")  # inside the Hermes home
    blocked.append(tmp_path / "frameio_auth.json")
    for d in (".ssh", ".aws", ".gnupg", ".config"):
        (fake_home / d).mkdir()
        (fake_home / d / "file.bin").write_text("x")
        blocked.append(fake_home / d / "file.bin")
    (media_dir / ".hidden").mkdir()
    (media_dir / ".hidden" / "clip.mp4").write_text("x")
    blocked.append(media_dir / ".hidden" / "clip.mp4")
    for name in [".env", "server.pem", "tls.key", "id_rsa", "id_rsa.pub", "id_ed25519", "frameio_auth.json"]:
        (media_dir / name).write_text("x")
        blocked.append(media_dir / name)
    (media_dir / "innocent.mp4").symlink_to(tmp_path / "frameio_auth.json")
    blocked.append(media_dir / "innocent.mp4")

    for path in blocked:
        result = json.loads(frameio_tool.frameio_upload_file("acct_1", "folder_1", str(path)))
        assert result["success"] is False, path
        assert "refused" in result["error"], path
    assert puts == []


def test_upload_still_accepts_ordinary_media_paths(monkeypatch, tmp_path_factory):
    from tools import frameio_tool

    media = tmp_path_factory.mktemp("media") / "final-cut.mov"
    media.write_bytes(b"abc")
    _upload_stubs(monkeypatch, frameio_tool, {"data": {"id": "f", "upload_urls": [{"size": 3, "url": "https://u.example/p"}]}})

    result = json.loads(frameio_tool.frameio_upload_file("acct_1", "folder_1", str(media)))

    assert result["success"] is True


def test_expired_oauth_token_is_not_sent_and_tells_user_to_log_in_again(monkeypatch):
    import time

    from tools import frameio_tool

    _write_token(frameio_tool, expires_at=int(time.time()) - 10, refresh_token="r")
    calls = []
    monkeypatch.setattr(frameio_tool, "_http_json", lambda *a, **k: calls.append(a) or {})

    result = json.loads(frameio_tool.frameio_me())

    assert result["success"] is False
    assert result["auth_required"] is True
    assert "frameio_login" in result["error"]
    assert calls == []


def test_unexpired_oauth_token_is_still_sent(monkeypatch):
    import time

    from tools import frameio_tool

    _write_token(frameio_tool, expires_at=int(time.time()) + 3600)
    monkeypatch.setattr(frameio_tool, "_http_json", lambda *a, **k: {"ok": True})

    assert json.loads(frameio_tool.frameio_me())["success"] is True


def test_registry_only_treats_underscore_register_helper_as_self_registration():
    import ast

    from tools.registry import _is_registry_register_call

    def parse(src):
        return ast.parse(src).body[0]

    assert _is_registry_register_call(parse("registry.register(name='x')"))
    assert _is_registry_register_call(parse("_register('x')"))
    assert not _is_registry_register_call(parse("my_register('x')"))
    assert not _is_registry_register_call(parse("deregister('x')"))
    assert not _is_registry_register_call(parse("register('x')"))


# ---------------------------------------------------------------------------
# config.yaml settings (env overrides config, config overrides default)
# ---------------------------------------------------------------------------


def _write_frameio_config(tmp_path, body: str) -> None:
    (tmp_path / "config.yaml").write_text(body, encoding="utf-8")


def test_frameio_config_defaults_are_declared():
    from hermes_cli.config import DEFAULT_CONFIG
    from tools import frameio_tool

    assert DEFAULT_CONFIG["frameio"]["redirect_uri"] == frameio_tool.DEFAULT_REDIRECT_URI
    assert DEFAULT_CONFIG["frameio"]["auth_mode"] == ""


def test_redirect_uri_default_when_env_and_config_unset():
    from tools import frameio_tool

    assert frameio_tool._redirect_uri() == frameio_tool.DEFAULT_REDIRECT_URI


def test_redirect_uri_read_from_config_when_env_unset(clean_frameio_env):
    from tools import frameio_tool

    _write_frameio_config(clean_frameio_env, "frameio:\n  redirect_uri: http://127.0.0.1:9999/cb\n")

    assert frameio_tool._redirect_uri() == "http://127.0.0.1:9999/cb"


def test_redirect_uri_env_overrides_config(monkeypatch, clean_frameio_env):
    from tools import frameio_tool

    _write_frameio_config(clean_frameio_env, "frameio:\n  redirect_uri: http://127.0.0.1:9999/cb\n")
    monkeypatch.setenv("FRAMEIO_REDIRECT_URI", "http://127.0.0.1:1111/env")

    assert frameio_tool._redirect_uri() == "http://127.0.0.1:1111/env"


def test_auth_mode_read_from_config_when_env_unset(clean_frameio_env):
    from tools import frameio_tool

    _write_frameio_config(clean_frameio_env, "frameio:\n  auth_mode: s2s\n")

    assert frameio_tool._auth_mode() == "s2s"


def test_auth_mode_env_overrides_config(monkeypatch, clean_frameio_env):
    from tools import frameio_tool

    _write_frameio_config(clean_frameio_env, "frameio:\n  auth_mode: s2s\n")
    monkeypatch.setenv("FRAMEIO_AUTH_MODE", "legacy")

    assert frameio_tool._auth_mode() == "legacy"


def test_auth_mode_defaults_when_neither_set(monkeypatch):
    from tools import frameio_tool

    assert frameio_tool._auth_mode() == "oauth"
    monkeypatch.setenv("FRAMEIO_LEGACY_TOKEN", "tok")
    assert frameio_tool._auth_mode() == "legacy"


def test_invalid_config_auth_mode_falls_through_to_default(clean_frameio_env):
    from tools import frameio_tool

    _write_frameio_config(clean_frameio_env, "frameio:\n  auth_mode: bogus\n")

    assert frameio_tool._auth_mode() == "oauth"


def test_config_load_failure_falls_back_to_defaults(monkeypatch):
    from tools import frameio_tool

    def boom():
        raise RuntimeError("config unreadable")

    monkeypatch.setattr("hermes_cli.config.load_config", boom)

    assert frameio_tool._redirect_uri() == frameio_tool.DEFAULT_REDIRECT_URI
    assert frameio_tool._auth_mode() == "oauth"


# ---------------------------------------------------------------------------
# Pagination: `after` in, `next_after` out
# ---------------------------------------------------------------------------


def _paged_calls():
    from tools import frameio_tool

    return [
        ("frameio_list_accounts", (), "/v4/accounts"),
        ("frameio_list_workspaces", ("acct_1",), "/v4/accounts/acct_1/workspaces"),
        ("frameio_list_projects", ("acct_1", "ws_1"), "/v4/accounts/acct_1/workspaces/ws_1/projects"),
        ("frameio_list_folder_children", ("acct_1", "fold_1"), "/v4/accounts/acct_1/folders/fold_1/children"),
        ("frameio_list_shares", ("acct_1", "proj_1"), "/v4/accounts/acct_1/projects/proj_1/shares"),
        ("frameio_list_comments", ("acct_1", "file_1"), "/v4/accounts/acct_1/files/file_1/comments"),
    ]


@pytest.mark.parametrize("fn_name,args,path", _paged_calls())
def test_list_tools_send_after_and_return_next_after(monkeypatch, fn_name, args, path):
    from tools import frameio_tool

    _write_token(frameio_tool)
    urls = []

    def fake_request(method, url, *, headers=None, data=None, json_body=None):
        urls.append(url)
        return {"data": [{"id": "x"}], "links": {"next": f"{path}?after=cur_next"}}

    monkeypatch.setattr(frameio_tool, "_http_json", fake_request)

    result = json.loads(getattr(frameio_tool, fn_name)(*args, after="cur_1"))

    assert result["success"] is True
    assert result["data"]["data"] == [{"id": "x"}]
    assert result["next_after"] == "cur_next"
    assert urls[0].endswith("?after=cur_1") or "&after=cur_1" in urls[0]
    assert "after=" not in urls[0].split("?")[0]


@pytest.mark.parametrize("fn_name,args,path", _paged_calls())
def test_list_tools_next_after_is_null_without_links(monkeypatch, fn_name, args, path):
    from tools import frameio_tool

    _write_token(frameio_tool)
    urls = []

    def fake_request(method, url, *, headers=None, data=None, json_body=None):
        urls.append(url)
        return {"data": []}

    monkeypatch.setattr(frameio_tool, "_http_json", fake_request)

    result = json.loads(getattr(frameio_tool, fn_name)(*args))

    assert result["success"] is True
    assert result["next_after"] is None
    assert urls[0] == f"https://api.frame.io{path}"


def test_folder_children_keeps_include_alongside_after(monkeypatch):
    from tools import frameio_tool

    _write_token(frameio_tool)
    urls = []
    monkeypatch.setattr(frameio_tool, "_http_json", lambda m, url, **kw: urls.append(url) or {"data": []})

    frameio_tool.frameio_list_folder_children("acct_1", "fold_1", include="media_links.thumbnail", after="c1")

    assert "include=media_links.thumbnail" in urls[0]
    assert "after=c1" in urls[0]


@pytest.mark.parametrize("bad", ["a b", "a\nb", "a\tb", "a\x00b", 123])
def test_list_tools_reject_malformed_after_before_any_request(monkeypatch, bad):
    from tools import frameio_tool

    _write_token(frameio_tool)
    called = []
    monkeypatch.setattr(frameio_tool, "_http_json", lambda *a, **k: called.append(1) or {})

    result = json.loads(frameio_tool.frameio_list_projects("acct_1", "ws_1", after=bad))

    assert result["success"] is False
    assert "after" in result["error"]
    assert called == []


def test_after_is_query_encoded_not_path_injected(monkeypatch):
    from tools import frameio_tool

    _write_token(frameio_tool)
    urls = []
    monkeypatch.setattr(frameio_tool, "_http_json", lambda m, url, **kw: urls.append(url) or {"data": []})

    frameio_tool.frameio_list_projects("acct_1", "ws_1", after="a/b&c=d")

    assert urls[0] == "https://api.frame.io/v4/accounts/acct_1/workspaces/ws_1/projects?after=a%2Fb%26c%3Dd"


@pytest.mark.parametrize("tool", [
    "frameio_list_accounts", "frameio_list_workspaces", "frameio_list_projects",
    "frameio_list_folder_children", "frameio_list_shares", "frameio_list_comments",
])
def test_registered_list_tools_expose_and_dispatch_after(monkeypatch, tool):
    from tools import frameio_tool
    from tools.registry import registry

    entry = registry.get_entry(tool) if hasattr(registry, "get_entry") else registry._tools[tool]
    assert "after" in entry.schema["parameters"]["properties"]
    assert "after" not in entry.schema["parameters"].get("required", [])

    seen = {}
    monkeypatch.setattr(frameio_tool, "_list_page", lambda path, after="", params=None: seen.update(after=after) or {"success": True})
    entry.handler({"account_id": "a", "workspace_id": "w", "folder_id": "f", "project_id": "p", "file_id": "i", "after": "cur"})

    assert seen["after"] == "cur"
