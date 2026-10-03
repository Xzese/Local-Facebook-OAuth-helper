# OAuth lifecycle modernisation

Placeholder for strengthening the local Facebook/Instagram OAuth helper while keeping it focused.

## Scope
- Represent authentication attempts and outcomes explicitly: success, denial, cancellation, timeout and failure.
- Add bounded attempt lifetimes instead of allowing indefinite waits.
- Start and verify the callback listener before opening the browser or exposing the authentication URL.
- Make shutdown and cancellation deterministic.
- Put token persistence behind an explicit storage interface rather than inferred parent-project .env paths.
- Make listener/redirect configuration explicit for local-browser and LAN/QR workflows.
- Retain and test OAuth state generation and comparison.
- Add tests for state mismatch, repeated callbacks, expiry, denial, occupied ports and cancellation.
- Review current Meta OAuth/Graph API compatibility before changing protocol behaviour.
- Coordinate any breaking changes with pinned Smart Display and Instagram publishing consumers.
- Update README setup and lifecycle documentation.

## Portfolio outcome
Present this either as a focused, well-tested local OAuth utility or as a clearly documented earlier implementation after consumers migrate elsewhere.

No implementation is included in this placeholder PR.