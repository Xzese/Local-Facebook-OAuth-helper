"""Thread-safe, single-use OAuth attempt state. No network or storage side effects."""
from enum import Enum
import math
import secrets
import threading
import time


class Outcome(str, Enum):
    PENDING = "pending"
    EXCHANGING = "exchanging"
    SUCCEEDED = "succeeded"
    DENIED = "denied"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class OAuthAttempt:
    def __init__(self, timeout=180.0, *, clock=time.monotonic):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("OAuth timeout must be positive and finite.")
        self.state = secrets.token_urlsafe(32)
        self.clock = clock
        self.deadline = clock() + timeout
        self.done = threading.Event()
        self.lock = threading.RLock()
        self._outcome = Outcome.PENDING

    @property
    def outcome(self):
        with self.lock:
            self._expire()
            return self._outcome

    def _expire(self):
        if self._outcome in {Outcome.PENDING, Outcome.EXCHANGING} and self.clock() >= self.deadline:
            self._outcome = Outcome.TIMED_OUT
            self.done.set()

    def claim(self, state):
        with self.lock:
            self._expire()
            if self._outcome != Outcome.PENDING or not isinstance(state, str) or not state.isascii():
                return False
            if not secrets.compare_digest(state, self.state):
                return False
            self._outcome = Outcome.EXCHANGING
            return True

    def finish(self, outcome):
        if outcome not in {Outcome.DENIED, Outcome.CANCELLED, Outcome.FAILED, Outcome.TIMED_OUT}:
            raise ValueError("Use complete() to confirm success.")
        with self.lock:
            self._expire()
            if self._outcome in {Outcome.PENDING, Outcome.EXCHANGING}:
                self._outcome = outcome
                self.done.set()
            return self._outcome

    def complete(self, persist):
        with self.lock:
            self._expire()
            if self._outcome != Outcome.EXCHANGING:
                return False
            try:
                persist()
            except Exception:
                self._outcome = Outcome.FAILED
                self.done.set()
                raise
            self._outcome = Outcome.SUCCEEDED
            self.done.set()
            return True

    def wait(self):
        self.done.wait(max(0, self.deadline - self.clock()))
        with self.lock:
            self._expire()
            return self._outcome
