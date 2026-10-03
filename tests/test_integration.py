"""Exercise package consumers, token storage and the real HTTPS listener."""
import datetime
import importlib.util
import os
from pathlib import Path
import shutil
import socket
import sys
import threading
from urllib.parse import parse_qs, urlparse
from unittest.mock import Mock

import dotenv
import pytest
import requests


@pytest.fixture
def helper(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    package_path = tmp_path / "auth_helper"
    package_path.mkdir()
    for filename in ("__init__.py", "auth_server.py", "oauth_attempt.py"):
        shutil.copyfile(root / filename, package_path / filename)
    env_path = tmp_path / ".env"
    env_path.write_text(
        "APP_ID=fixture-app\nAPP_SECRET=fixture-secret\n"
        "GRAPH_SCOPE=instagram_basic,pages_show_list\nCLIENT_IP_ADDRESS=127.0.0.1\n"
        "ACCESS_TOKEN=previous-token\nACCESS_TOKEN_EXPIRY=2099-01-01 00:00:00.000000\n",
        encoding="utf-8",
    )
    # Track changes made by dotenv as well as monkeypatch for proper isolation.
    environment = os.environ.copy()
    for key in ("APP_ID", "APP_SECRET", "GRAPH_SCOPE", "CLIENT_IP_ADDRESS", "GRAPH_API_VERSION", "TOKEN_ENV_PATH", "ACCESS_TOKEN", "ACCESS_TOKEN_EXPIRY"):
        os.environ.pop(key, None)
    name = "auth_helper"
    spec = importlib.util.spec_from_file_location(name, package_path / "__init__.py", submodule_search_locations=[str(package_path)])
    package = importlib.util.module_from_spec(spec)
    for module in (name, name + ".auth_server", name + ".oauth_attempt"):
        monkeypatch.delitem(sys.modules, module, raising=False)
    monkeypatch.setitem(sys.modules, name, package)
    spec.loader.exec_module(package)
    server = sys.modules[name + ".auth_server"]
    try:
        yield package, server, env_path
    finally:
        server.stop_server()
        monkeypatch.undo()
        os.environ.clear()
        os.environ.update(environment)


@pytest.mark.parametrize("configured", [None, "", "v25.0"])
def test_legacy_package_configuration_and_standalone_exchange(helper, monkeypatch, configured):
    package, server, env_path = helper
    assert os.environ["ACCESS_TOKEN"] == "previous-token"
    assert package.get_env_path() == str(env_path)
    if configured is not None:
        monkeypatch.setenv("GRAPH_API_VERSION", configured)
    version = configured or "v26.0"
    url = package.get_auth_url()
    assert package.get_auth_url() == url
    assert urlparse(url).path == f"/{version}/dialog/oauth"
    assert package.get_graph_api_version() == version
    assert server.pending_auth_url == url
    assert server.pending_oauth_state == parse_qs(urlparse(url).query)["state"][0]
    payload = {"access_token": "new-token", "expires_in": 3600, "token_type": "bearer"}
    post = Mock(return_value=Mock(status_code=200, json=lambda: payload))
    monkeypatch.setattr(server.requests, "post", post)
    assert package.exchange_code_for_token("fixture-code") == payload
    assert post.call_args.args[0] == f"https://graph.facebook.com/{version}/oauth/access_token"
    assert post.call_args.kwargs["data"]["redirect_uri"] == parse_qs(urlparse(url).query)["redirect_uri"][0]
    values = dotenv.dotenv_values(env_path)
    assert values["ACCESS_TOKEN"] == os.environ["ACCESS_TOKEN"] == "new-token"
    assert values["APP_SECRET"] == "fixture-secret"
    assert values["ACCESS_TOKEN_EXPIRY"] == os.environ["ACCESS_TOKEN_EXPIRY"]
    assert datetime.datetime.strptime(values["ACCESS_TOKEN_EXPIRY"], "%Y-%m-%d %H:%M:%S.%f") > datetime.datetime.now()
    assert env_path.stat().st_mode & 0o777 == 0o600
    assert not list(env_path.parent.glob(".oauth-*"))


def test_invalid_version_fails_before_network_and_explicit_token_file(helper, monkeypatch, tmp_path):
    package, server, original_path = helper
    path = tmp_path / "tokens" / ".env"
    monkeypatch.setenv("TOKEN_ENV_PATH", str(path))
    assert package.get_env_path() == str(path)
    monkeypatch.setenv("GRAPH_API_VERSION", "invalid")
    with pytest.raises(RuntimeError, match="GRAPH_API_VERSION"):
        package.get_auth_url()
    monkeypatch.setenv("GRAPH_API_VERSION", "v26.0")
    package.get_auth_url()
    monkeypatch.setattr(server.requests, "post", Mock(return_value=Mock(status_code=200, json=lambda: {"access_token": "explicit-token", "expires_in": 3600})))
    assert package.exchange_code_for_token("fixture-code")["access_token"] == "explicit-token"
    assert dotenv.dotenv_values(path)["ACCESS_TOKEN"] == "explicit-token"
    assert dotenv.dotenv_values(original_path)["ACCESS_TOKEN"] == "previous-token"


def test_debug_token_expiry_and_callback_replay(helper, monkeypatch):
    package, server, env_path = helper
    url = package.get_auth_url()
    state = parse_qs(urlparse(url).query)["state"][0]
    monkeypatch.setattr(server.requests, "post", Mock(return_value=Mock(status_code=200, json=lambda: {"access_token": "debug-token"})))
    expires_at = int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp())
    debug = Mock(return_value=Mock(json=lambda: {"data": {"is_valid": True, "expires_at": expires_at}}))
    monkeypatch.setattr(server.requests, "get", debug)
    client = server.app.test_client()
    params = {"state": state, "code": "fixture-code"}
    assert client.get("/callback", query_string=params).status_code == 200
    assert client.get("/callback", query_string=params).status_code == 400
    assert package.token_acquired.is_set()
    assert debug.call_args.args[0] == "https://graph.facebook.com/v26.0/debug_token"
    expiry = datetime.datetime.strptime(dotenv.dotenv_values(env_path)["ACCESS_TOKEN_EXPIRY"], "%Y-%m-%d %H:%M:%S.%f")
    assert int(expiry.timestamp()) == expires_at


@pytest.mark.parametrize("late_result", ["failure", "success"])
def test_late_callback_does_not_signal_or_clear_a_new_attempt(helper, monkeypatch, late_result):
    package, server, env_path = helper
    first_url = package.get_auth_url()
    state = parse_qs(urlparse(first_url).query)["state"][0]
    fetching = threading.Event()
    release = threading.Event()
    def blocked_fetch(code):
        fetching.set()
        assert release.wait(3)
        return None
    if late_result == "failure":
        monkeypatch.setattr(server, "_fetch_token", blocked_fetch)
    else:
        monkeypatch.setattr(server, "_fetch_token", lambda code: ({"access_token": "first-token"}, datetime.datetime(2099, 1, 1)))
        complete = server._attempt.complete
        def delayed_success(persist):
            result = complete(persist)
            fetching.set()
            assert release.wait(3)
            return result
        monkeypatch.setattr(server._attempt, "complete", delayed_success)
    responses = []
    def callback():
        with server.app.test_client() as client:
            responses.append(client.get("/callback", query_string={"state": state, "code": "fixture-code"}))
    worker = threading.Thread(target=callback)
    worker.start()
    try:
        assert fetching.wait(2)
        package.stop_server()
        second_url = package.get_auth_url(force_new=True)
        second_state = parse_qs(urlparse(second_url).query)["state"][0]
        release.set()
        worker.join(3)
        assert not worker.is_alive()
        assert responses[0].status_code == (502 if late_result == "failure" else 200)
        assert server.pending_auth_url == second_url
        assert server.pending_oauth_state == second_state
        assert server._attempt.outcome == package.Outcome.PENDING
        assert not package.token_acquired.is_set()
        assert dotenv.dotenv_values(env_path)["ACCESS_TOKEN"] == ("previous-token" if late_result == "failure" else "first-token")
    finally:
        release.set()
        worker.join(3)


@pytest.mark.parametrize("action", ["success", "denial", "cancel", "timeout", "exchange_failure"])
@pytest.mark.filterwarnings("ignore:Unverified HTTPS request")
def test_https_listener_outcomes_and_cleanup(helper, monkeypatch, action):
    package, server, env_path = helper
    # Use an ephemeral port in tests without changing the consumer's port 5000.
    make_server = server.make_server
    listeners = []
    def ephemeral_server(host, port, app, **kwargs):
        listener = make_server(host, 0, app, **kwargs)
        listeners.append(listener)
        return listener
    monkeypatch.setattr(server, "make_server", ephemeral_server)
    url = package.get_auth_url(timeout=1.0 if action == "timeout" else 10)
    state = parse_qs(urlparse(url).query)["state"][0]
    payload = {"access_token": "callback-token", "expires_in": 3600}
    monkeypatch.setattr(server.requests, "post", Mock(return_value=Mock(status_code=500 if action == "exchange_failure" else 200, json=lambda: payload)))
    browser_opened = threading.Event()
    monkeypatch.setattr(server.webbrowser, "open", lambda *args, **kwargs: browser_opened.set())
    outcomes = []
    browser = package.local_browser_capture()
    waiter = threading.Thread(target=lambda: outcomes.append(package.wait_for_token()))
    waiter.start()
    try:
        assert server.listener_ready.wait(3)
        assert browser_opened.wait(2)
        listener = listeners[0]
        if action in ("success", "denial", "exchange_failure"):
            params = {"state": state, "error": "access_denied"} if action == "denial" else {"state": state, "code": "fixture-code"}
            response = requests.get(f"https://127.0.0.1:{listener.server_port}/callback", params=params, verify=False, timeout=3)
            assert response.status_code == {"success": 200, "denial": 400, "exchange_failure": 502}[action]
        elif action == "cancel":
            package.stop_server()
        waiter.join(4)
        assert not waiter.is_alive()
        expected = {"success": package.Outcome.SUCCEEDED, "denial": package.Outcome.DENIED, "cancel": package.Outcome.CANCELLED, "timeout": package.Outcome.TIMED_OUT, "exchange_failure": package.Outcome.FAILED}
        assert outcomes == [expected[action]]
        assert not server.listener_ready.is_set()
        assert not server._server_running
        with socket.socket() as probe:
            assert probe.connect_ex(("127.0.0.1", listener.server_port)) != 0
        assert dotenv.dotenv_values(env_path)["ACCESS_TOKEN"] == ("callback-token" if action == "success" else "previous-token")
    finally:
        package.stop_server()
        waiter.join(5)
        browser.join(1)
