from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock
import pytest
from oauth_attempt import OAuthAttempt, Outcome


def test_state_is_random_and_reusable_until_claimed():
    a, b = OAuthAttempt(), OAuthAttempt()
    assert a.state != b.state
    assert not a.claim("incorrect")
    assert a.outcome == Outcome.PENDING
    assert a.claim(a.state)
    assert not a.claim(a.state)


@pytest.mark.parametrize("state", [None, "", "é"])
def test_invalid_state_does_not_claim(state):
    attempt = OAuthAttempt()
    assert not attempt.claim(state)
    assert attempt.outcome == Outcome.PENDING


def test_only_one_concurrent_callback_claims_state():
    attempt = OAuthAttempt()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt.claim, [attempt.state] * 8))
    assert results.count(True) == 1


def test_cancelled_exchange_does_not_persist():
    attempt = OAuthAttempt()
    assert attempt.claim(attempt.state)
    attempt.finish(Outcome.CANCELLED)
    persist = Mock()
    assert not attempt.complete(persist)
    persist.assert_not_called()
    assert attempt.wait() == Outcome.CANCELLED


def test_expired_exchange_does_not_persist():
    now = [0.0]
    attempt = OAuthAttempt(2, clock=lambda: now[0])
    assert attempt.claim(attempt.state)
    now[0] = 2.0
    persist = Mock()
    assert not attempt.complete(persist)
    persist.assert_not_called()
    assert attempt.outcome == Outcome.TIMED_OUT


def test_success_cannot_be_changed_by_late_cancel():
    attempt = OAuthAttempt()
    attempt.claim(attempt.state)
    persist = Mock()
    assert attempt.complete(persist)
    assert attempt.finish(Outcome.CANCELLED) == Outcome.SUCCEEDED
    persist.assert_called_once()


def test_storage_failure_is_not_success():
    attempt = OAuthAttempt()
    attempt.claim(attempt.state)
    with pytest.raises(OSError):
        attempt.complete(Mock(side_effect=OSError()))
    assert attempt.wait() == Outcome.FAILED


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_invalid_deadline_is_rejected(timeout):
    with pytest.raises(ValueError):
        OAuthAttempt(timeout)


def test_denial_is_terminal():
    attempt = OAuthAttempt()
    attempt.claim(attempt.state)
    assert attempt.finish(Outcome.DENIED) == Outcome.DENIED
    assert not attempt.claim(attempt.state)
