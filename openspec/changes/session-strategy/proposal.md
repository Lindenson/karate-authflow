## Why

Many systems behind Karate tests are protected by a stateful login: authenticate once with credentials, receive a session cookie, then send that cookie on every subsequent request. This change implements that pattern for **Ory Kratos**, the identity system the target system uses — modelling the client side of a Kratos browser/SPA login flow. After this, a tester points the plugin at a Kratos endpoint with an identifier and password, and every request transparently carries a valid `ory_kratos_session` cookie.

## What Changes

- Add `KratosSessionStrategy` (an `AuthStrategy`): logs in once via Kratos, caches the session cookie, and injects `Cookie: ory_kratos_session=…` into every request.
- Add `KratosClient`: performs the Kratos **browser login flow** over `java.net.http.HttpClient` with a `CookieManager` — (1) `GET /self-service/login/browser` (`Accept: application/json`) to obtain the flow `action` URL, the `csrf_token` value, and the CSRF cookie; (2) `POST` the action URL with `{method:"password", identifier, password, csrf_token}` and the CSRF cookie; (3) capture the `ory_kratos_session` cookie from the success response.
- Lazy, thread-safe, login-once semantics so a single shared strategy is safe under `Runner.parallel(n)`.
- Add `com.fasterxml.jackson.core:jackson-databind` in `provided` scope (already supplied transitively by Karate) to parse the flow JSON.
- Add a hermetic integration test that **models a Kratos server** with a JDK `com.sun.net.httpserver.HttpServer` (login-flow + submit + a session-protected endpoint) and runs an auth-free Karate feature through the strategy against it — no network, runs in the default `mvn verify`.

## Capabilities

### New Capabilities
- `session-auth`: Stateful, login-once authentication that reuses a captured session credential (here, a cookie) across all subsequent requests, thread-safe under parallel execution.
- `kratos-login`: The Ory Kratos browser login-flow protocol — flow initialization, CSRF handling, password submission, and session-cookie capture.

### Modified Capabilities
<!-- None — auth-interceptor and basic-auth requirements are unchanged. -->

## Impact

- **New code**: `…/authflow/session/KratosSessionStrategy.java`, `…/authflow/session/KratosClient.java` (+ small flow DTOs); test: a fake-Kratos `HttpServer` harness, a feature resource, and unit/integration tests.
- **Dependencies**: `jackson-databind` (`provided`); no new runtime dependency for consumers (their Karate already provides Jackson).
- **Non-goals**: automatic re-login on `401` (deferred — requires extending the `KarateBinding` seam with `afterHttpCall`); Kratos native/API token flow; MFA/second-factor.
