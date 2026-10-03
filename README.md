# Local Facebook OAuth helper

A local callback server for operator-owned Facebook/Instagram integrations. This branch contains the first OAuth lifecycle implementation. Keep the PR in draft until HTTP, listener and live-provider checks are complete.

## Setup

Use Python 3.11 or later. Install requirements.txt and copy .env.example to .env. Configure your own Meta application, permissions and supported GRAPH_API_VERSION. The callback URI is exactly `https://<CLIENT_IP_ADDRESS>:5000/callback`.

The listener uses an ad-hoc certificate and retains the existing local/LAN model. It is not a public production authentication service. A QR flow on another device requires an address reachable from that device, not its loopback address. Verify Meta redirect and certificate requirements before use.

## Authentication lifecycle

```python
from auth_server import get_auth_url, local_browser_capture, wait_for_token
from oauth_attempt import Outcome

url = get_auth_url(timeout=180)
local_browser_capture(url)
outcome = wait_for_token()
if outcome == Outcome.SUCCEEDED:
    print("Authentication completed")
else:
    print("Authentication did not complete:", outcome.value)
```

The browser thread waits for listener readiness. Each attempt has a monotonic deadline and one claimable OAuth state. A repeated, cancelled or expired callback cannot persist a token. Denial, cancellation, timeout and failure are distinct terminal results. Shutdown releases the waiting caller.

When importing as a package, use the corresponding package imports. Existing function names remain, but callers must now inspect the returned Outcome. Do not treat any completed thread as successful authentication.

Set TOKEN_ENV_PATH explicitly when embedding. The previous inferred .env location remains a fallback until consumers migrate. Token and expiry are written together through a restricted temporary file and atomic replacement. This is a local storage implementation, not cross-process file locking or a keychain integration.

## Validation

Fourteen isolated lifecycle tests passed. The callback test module was skipped locally because Flask was not installed. Python syntax compilation passed. Run `python -m pytest -q tests` after installing all requirements to execute the callback tests too. No live authentication was performed.

## Remaining work

Complete listener/socket and callback tests, log redaction, configurable TLS/redirect handling, packaging and CI. Review the actual Meta flow and expiry semantics with a test application. Update Smart Display's result handling before changing its auth submodule pin. Do not archive this helper or change consumer pins as part of this first pass.
