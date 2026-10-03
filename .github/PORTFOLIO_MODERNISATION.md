# OAuth lifecycle modernisation

Status: implementation started. Keep the PR in draft.

## Implemented
- Explicit pending, exchanging, succeeded, denied, cancelled, timed-out and failed outcomes.
- Monotonic attempt deadline and one-time state claim protected by a lock.
- Cancellation and expiry prevent a late exchange from persisting credentials.
- Listener-ready signal before the browser opens.
- Threaded listener and deterministic cleanup of the waiter.
- Explicit TOKEN_ENV_PATH override and atomic token/expiry file replacement.
- Configurable Graph API version; no unverified current-version default.
- Fourteen isolated tests passed; auth_server.py compiles.

## Validation limits

The HTTP callback test module was skipped locally because Flask was absent. Live Meta, TLS, socket lifecycle and browser/QR flows were not tested.

## Remaining

Complete integration tests, storage abstraction, log redaction and listener/redirect policy. Verify Meta compatibility. Add packaging and CI. Update each pinned consumer only after it handles explicit outcomes correctly. The legacy inferred token-file location remains a documented migration fallback.
