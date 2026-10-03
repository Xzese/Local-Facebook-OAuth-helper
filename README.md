# Local Facebook OAuth helper

A local callback server for operator-owned Facebook/Instagram integrations, with bounded authentication attempts and explicit outcomes.

## Setup

Use Python 3.11 or later. Install requirements.txt and copy .env.example to .env. Configure `APP_ID`, `APP_SECRET`, `GRAPH_SCOPE` and `CLIENT_IP_ADDRESS` for your own Meta application. The callback URI is exactly `https://<CLIENT_IP_ADDRESS>:5000/callback`.

`GRAPH_API_VERSION` is optional: missing or blank uses `v26.0`, replacing the previous hardcoded `v20.0`. Set it explicitly to another supported version when needed. OAuth, code exchange and token inspection all use the same setting. Parent applications can call `get_graph_api_version()` to use that version for their Graph requests too. Changing this helper does not change versions hardcoded by a consumer. Meta's [official Python SDK](https://github.com/facebook/facebook-python-business-sdk/blob/main/facebook_business/apiconfig.py) currently targets `v26.0`; validate your application's login and downstream permissions before rolling out the upgrade.

The listener uses an ad-hoc certificate and retains the existing local/LAN model. It is not a public production authentication service. A QR flow on another device requires an address reachable from that device, not its loopback address. Verify Meta redirect and certificate requirements before use.

## Authentication lifecycle

```python
from auth_server import Outcome, get_auth_url, local_browser_capture, wait_for_token

url = get_auth_url(timeout=180)
local_browser_capture(url)
outcome = wait_for_token()
if outcome == Outcome.SUCCEEDED:
    print("Authentication completed")
else:
    print("Authentication did not complete:", outcome.value)
```

The browser thread waits for listener readiness. Each attempt has a monotonic deadline and one claimable OAuth state. A repeated, cancelled or expired callback cannot persist a token. Denial, cancellation, timeout and failure are distinct terminal results. Shutdown releases the waiting caller.

When importing as a package, use the corresponding package imports. Existing function names and optional browser argument remain. `wait_for_token()` now returns an `Outcome`; callers must capture it even when running the waiter on a thread. Only `Outcome.SUCCEEDED` means a token was saved. Denial, cancellation, timeout and listener failure must not enable authenticated features. A new attempt must wait until the previous listener has shut down.

Importing the helper loads the parent project's `.env`, preserving the existing submodule setup. Running the script directly uses the `.env` beside it. `TOKEN_ENV_PATH` overrides both locations when set. Token and expiry are written together through a restricted temporary file and atomic replacement; `ACCESS_TOKEN` and `ACCESS_TOKEN_EXPIRY` are also updated in `os.environ`. The expiry retains the consumer-compatible `%Y-%m-%d %H:%M:%S.%f` format. This is a local storage implementation, not cross-process file locking or a keychain integration.

The public `exchange_code_for_token(code)` retains its standalone contract: it saves a successful token and returns the provider's response dictionary, or returns `None` if exchange or validation fails. OAuth callbacks use an internal fetch step and persist only when the attempt is still active, so cancellation cannot save a late callback's token. `open_webbrowser()` and the legacy `token_acquired` event remain available; the event also signals cancellation, as before, and does not replace checking `Outcome`.

## Validation

Install all requirements and pytest, then run `python -m pytest -q tests`. The suite exercises package imports, legacy configuration, standalone token exchange, expiry fallback, callback replay/cancellation and real HTTPS listener readiness and shutdown. Provider responses and browser launches are mocked; listener tests bind ephemeral loopback ports. No live authentication was performed.

## Remaining work

Live Meta login and downstream Graph requests still require validation with a test application, its approved permissions and exact redirect URI. Configurable TLS/redirect handling, packaging and CI remain future work. Update consumers to handle outcomes and share the Graph version before deploying a new submodule pin.
