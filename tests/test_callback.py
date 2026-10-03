import datetime
from unittest.mock import Mock
import pytest

import auth_server as server
from oauth_attempt import OAuthAttempt, Outcome


@pytest.fixture
def attempt(monkeypatch):
    attempt = OAuthAttempt()
    monkeypatch.setattr(server, "_attempt", attempt)
    monkeypatch.setattr(server, "_fetch_token", Mock(return_value=({"access_token": "fixture-token"}, datetime.datetime(2099, 1, 1))))
    monkeypatch.setattr(server, "_persist_token", Mock())
    return attempt


def test_bad_state_never_exchanges(attempt):
    with server.app.test_client() as client:
        assert client.get("/callback?state=bad&code=fixture").status_code == 400
    server._fetch_token.assert_not_called()


def test_success_and_replay(attempt):
    with server.app.test_client() as client:
        url = f"/callback?state={attempt.state}&code=fixture"
        assert client.get(url).status_code == 200
        assert client.get(url).status_code == 400
    server._persist_token.assert_called_once()
    assert attempt.outcome == Outcome.SUCCEEDED


def test_denied_callback_finishes_waiter(attempt):
    with server.app.test_client() as client:
        assert client.get(f"/callback?state={attempt.state}&error=access_denied").status_code == 400
    assert attempt.wait() == Outcome.DENIED
    server._fetch_token.assert_not_called()


def test_cancel_during_exchange_does_not_store(attempt, monkeypatch):
    def exchange(code):
        attempt.finish(Outcome.CANCELLED)
        return {"access_token": "fixture-token"}, datetime.datetime(2099, 1, 1)
    monkeypatch.setattr(server, "_fetch_token", exchange)
    with server.app.test_client() as client:
        assert client.get(f"/callback?state={attempt.state}&code=fixture").status_code == 409
    server._persist_token.assert_not_called()
