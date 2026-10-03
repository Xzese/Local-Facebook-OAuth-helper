#!/usr/bin/env python3
"""Local OAuth callback server with explicit, bounded authentication outcomes."""
import datetime
import os
from pathlib import Path
import re
import tempfile
import threading
import webbrowser
from urllib.parse import urlencode

import dotenv
import requests
from flask import Flask, Response, request
from werkzeug.serving import make_server

if __package__:
    from .oauth_attempt import OAuthAttempt, Outcome
else:
    from oauth_attempt import OAuthAttempt, Outcome

app = Flask(__name__)
oauth_state_lock = threading.RLock()
listener_ready = threading.Event()
_attempt = None
_auth_url = None
_server_running = False
token_thread = None
token_acquired = threading.Event()
pending_oauth_state = None
pending_auth_url = None

DEFAULT_GRAPH_API_VERSION = "v26.0"


def get_env_path():
    if os.getenv("TOKEN_ENV_PATH"):
        return os.path.abspath(os.environ["TOKEN_ENV_PATH"])
    root = Path(__file__).resolve().parent
    return str((root if __name__ == "__main__" else root.parent) / ".env")


# Parent applications historically receive their configuration during import.
dotenv.load_dotenv(get_env_path())


def _required(name):
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required.")
    return value


def get_graph_api_version():
    """Use a supported default without requiring changes to existing .env files."""
    version = os.getenv("GRAPH_API_VERSION", "").strip() or DEFAULT_GRAPH_API_VERSION
    if not re.fullmatch(r"v[1-9][0-9]*\.[0-9]+", version):
        raise RuntimeError("GRAPH_API_VERSION must have the form vNN.N.")
    return version


def _graph_version():
    return get_graph_api_version()


def _redirect_uri():
    return f"https://{_required('CLIENT_IP_ADDRESS')}:5000/callback"


def get_auth_url(force_new=False, timeout=180.0):
    global _attempt, _auth_url, pending_oauth_state, pending_auth_url
    with oauth_state_lock:
        if not force_new and _attempt is not None and _attempt.outcome in {Outcome.PENDING, Outcome.EXCHANGING}:
            return _auth_url
        if _server_running:
            raise RuntimeError("Stop the active listener before starting a new OAuth attempt.")
        dotenv.load_dotenv(get_env_path())
        params = {"client_id": _required("APP_ID"), "redirect_uri": _redirect_uri(), "scope": _required("GRAPH_SCOPE"), "response_type": "code"}
        version = _graph_version()
        if _attempt is not None:
            _attempt.finish(Outcome.CANCELLED)
        _attempt = OAuthAttempt(timeout)
        token_acquired.clear()
        params["state"] = _attempt.state
        _auth_url = f"https://www.facebook.com/{version}/dialog/oauth?" + urlencode(params)
        pending_oauth_state = _attempt.state
        pending_auth_url = _auth_url
        return _auth_url


def _expiry(payload, token):
    seconds = payload.get("expires_in")
    if seconds is not None:
        seconds = int(seconds)
        if seconds <= 0:
            raise ValueError("Invalid token lifetime.")
        return datetime.datetime.now() + datetime.timedelta(seconds=seconds)
    response = requests.get(
        f"https://graph.facebook.com/{_graph_version()}/debug_token",
        params={"input_token": token, "access_token": f"{_required('APP_ID')}|{_required('APP_SECRET')}"},
        timeout=(5, 30), allow_redirects=False,
    )
    response.raise_for_status()
    data = response.json()["data"]
    if not isinstance(data, dict):
        raise ValueError("Invalid token validation response.")
    if data.get("is_valid") is not True:
        raise ValueError("Token validation failed.")
    # Token expiry and data-access expiry are different. Do not substitute one.
    expiry = datetime.datetime.fromtimestamp(int(data["expires_at"]))
    if expiry <= datetime.datetime.now():
        raise ValueError("Token expiry is not in the future.")
    return expiry


def _fetch_token(code):
    """Fetch and validate without persisting a cancelled callback's token."""
    try:
        response = requests.post(
            f"https://graph.facebook.com/{_graph_version()}/oauth/access_token",
            data={"client_id": _required("APP_ID"), "client_secret": _required("APP_SECRET"), "grant_type": "authorization_code", "redirect_uri": _redirect_uri(), "code": code},
            timeout=(5, 30), allow_redirects=False,
        )
        if response.status_code != 200:
            return None
        payload = response.json()
        if not isinstance(payload, dict):
            return None
        token = payload["access_token"]
        if not isinstance(token, str) or not token.strip():
            return None
        return payload, _expiry(payload, token)
    except (requests.RequestException, ValueError, KeyError, TypeError, OverflowError, RuntimeError, OSError):
        return None


def exchange_code_for_token(code):
    """Legacy standalone exchange: save the token and return Meta's payload."""
    result = _fetch_token(code)
    if result is None:
        return None
    payload, expiry = result
    _persist_token(payload["access_token"], expiry)
    return payload


def _persist_token(token, expiry):
    path = Path(get_env_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    expiry_text = expiry.strftime("%Y-%m-%d %H:%M:%S.%f")
    fd, temporary = tempfile.mkstemp(prefix=".oauth-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(path.read_text(encoding="utf-8") if path.exists() else "")
        dotenv.set_key(temporary, "ACCESS_TOKEN", token)
        dotenv.set_key(temporary, "ACCESS_TOKEN_EXPIRY", expiry_text)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.environ["ACCESS_TOKEN"] = token
        os.environ["ACCESS_TOKEN_EXPIRY"] = expiry_text
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@app.route("/")
def index():
    return Response("Authorization listener is running.", mimetype="text/plain")


@app.route("/callback")
def callback():
    with oauth_state_lock:
        attempt = _attempt
    if attempt is None or not attempt.claim(request.args.get("state")):
        return Response("Invalid, expired or already used OAuth state.", status=400, mimetype="text/plain")
    if request.args.get("error"):
        attempt.finish(Outcome.DENIED)
        _clear_pending_oauth_attempt(attempt)
        return Response("Authorization was denied.", status=400, mimetype="text/plain")
    code = request.args.get("code")
    if not code:
        attempt.finish(Outcome.FAILED)
        _clear_pending_oauth_attempt(attempt)
        return Response("Authorization code is missing.", status=400, mimetype="text/plain")
    result = _fetch_token(code)
    if result is None:
        attempt.finish(Outcome.FAILED)
        _clear_pending_oauth_attempt(attempt)
        return Response("Token exchange failed. Start a new attempt.", status=502, mimetype="text/plain")
    try:
        payload, expiry = result
        completed = attempt.complete(lambda: _persist_token(payload["access_token"], expiry))
    except Exception:
        return Response("Token storage failed.", status=500, mimetype="text/plain")
    if not completed:
        return Response("Authorization was cancelled or expired.", status=409, mimetype="text/plain")
    with oauth_state_lock:
        if _attempt is attempt:
            token_acquired.set()
            _clear_pending_oauth_attempt(attempt)
    return Response("Authorization completed. You can close this window.", mimetype="text/plain")


def run_server():
    server = make_server(_required("CLIENT_IP_ADDRESS"), 5000, app, threaded=True, ssl_context="adhoc")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    listener_ready.set()
    return server, thread


def wait_for_token():
    global _server_running
    with oauth_state_lock:
        if _server_running:
            raise RuntimeError("An OAuth listener is already active.")
        if _attempt is None:
            get_auth_url()
        attempt = _attempt
        if attempt.outcome not in {Outcome.PENDING, Outcome.EXCHANGING}:
            return attempt.outcome
        _server_running = True
    server = thread = None
    try:
        server, thread = run_server()
        return attempt.wait()
    except (Exception, SystemExit):
        return attempt.finish(Outcome.FAILED)
    finally:
        listener_ready.clear()
        _clear_pending_oauth_attempt(attempt)
        if server is not None:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        with oauth_state_lock:
            _server_running = False


def open_webbrowser(auth_url):
    """Retain the original public browser helper."""
    return webbrowser.open(auth_url, new=1, autoraise=True)


def local_browser_capture(auth_url=None):
    global token_thread
    url = auth_url or get_auth_url()
    with oauth_state_lock:
        attempt = _attempt
    def open_when_ready():
        if listener_ready.wait(timeout=10) and attempt is not None and attempt.outcome == Outcome.PENDING:
            open_webbrowser(url)
    token_thread = threading.Thread(target=open_when_ready, daemon=True)
    token_thread.start()
    return token_thread


def _clear_pending_oauth_attempt(attempt=None):
    global pending_oauth_state, pending_auth_url
    with oauth_state_lock:
        if attempt is not None and attempt is not _attempt:
            return
        pending_oauth_state = None
        pending_auth_url = None


def stop_server():
    with oauth_state_lock:
        if _attempt is not None:
            _attempt.finish(Outcome.CANCELLED)
        _clear_pending_oauth_attempt()
        token_acquired.set()
    listener_ready.clear()


if __name__ == "__main__":
    authorization_url = get_auth_url()
    local_browser_capture(authorization_url)
    raise SystemExit(0 if wait_for_token() == Outcome.SUCCEEDED else 1)
