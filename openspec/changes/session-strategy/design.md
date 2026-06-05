## Context

Builds on `auth-interceptor-core`: `AuthStrategy` (a named `PreRequestInterceptor` mutating `AuthRequest`), registered via `KarateAuth.register(...)`. This change adds the first *stateful* strategy.

Kratos browser login flow (verified against Ory docs):
1. `GET {publicUrl}/self-service/login/browser` with `Accept: application/json` → JSON with `ui.action` (POST URL) and a hidden `ui.nodes[]` entry `name=="csrf_token"` → `attributes.value`; response sets a `csrf_token` cookie.
2. `POST {action}` with `Accept`/`Content-Type: application/json`, the CSRF **cookie**, and body `{method:"password", identifier, password, csrf_token}`.
3. Success `200` → `Set-Cookie: ory_kratos_session=…` (HttpOnly).

The CSRF token must match in **both** the cookie (step 1) and the body (step 2).

## Goals / Non-Goals

**Goals:**
- Transparent cookie-based session auth against Kratos: configure credentials once, inject the session cookie on every request.
- Login exactly once, lazily, thread-safe; safe to share under parallel execution.
- Hermetic test that models a Kratos server (no network, default build).

**Non-Goals:**
- Auto re-login on `401` (deferred; needs an `afterHttpCall` seam extension).
- Kratos native/API token flow, MFA, registration/recovery flows.

## Decisions

- **Browser flow, not API flow.** The requirement is cookie-based session reuse; the browser flow yields `ory_kratos_session`, whereas the API flow yields a bearer `session_token`. *Alternative (API flow + token):* rejected for this requirement, but the same `KratosClient` can grow a token mode later.
- **`java.net.http.HttpClient` + `CookieManager` for the login, not Karate's client.** The login must run inside the interceptor, before/independent of the request under test; the JDK client is dependency-free and the `CookieManager` carries the CSRF cookie between the two steps automatically. *Alternative:* reuse Karate's HTTP engine — rejected, it would couple the strategy to Karate internals and re-enter the interceptor recursively.
- **Jackson (`provided`) for JSON parsing.** Karate already brings `jackson-databind` (2.19.x) transitively; declaring it `provided` lets us parse the flow tree without fattening our jar or imposing a runtime dependency. *Alternative:* hand-rolled string/regex parsing — rejected as fragile and unprofessional.
- **Lazy login with double-checked locking** over a `volatile` cookie field. The first request that needs auth triggers one login; subsequent requests and threads reuse the cached cookie. *Alternative:* eager login in the constructor — rejected, constructing a strategy shouldn't perform network I/O; `karate.callSingle()` — viable but ties the contract to Karate config rather than the strategy object.
- **Cookie injection appends to an existing `Cookie` header** rather than overwriting, so a test that sets its own cookies is not clobbered.
- **Fake Kratos via JDK `HttpServer` in tests.** Models `/self-service/login/browser`, `/self-service/login`, and a session-protected endpoint; lets the live-style proof run hermetically in the default build. *Alternative:* Karate mock server — viable but pulls Karate mock types into tests; the JDK server keeps the harness self-contained and also unit-tests `KratosClient` directly.

## Risks / Trade-offs

- **Login failure surfacing.** A wrong password / non-200 submit must fail loudly, not silently inject no cookie. → `KratosClient` throws a clear `KratosLoginException` (request fails visibly) on non-success.
- **Thread race on first login.** → Double-checked locking guarded by a dedicated lock; the login HTTP calls happen once inside the lock.
- **Jackson version drift between our `provided` pin and the consumer's Karate.** → We use only stable tree-model APIs (`readTree`, `path`, `get`) compatible across 2.x; runtime uses the consumer's version.
- **`HttpOnly` on the session cookie.** → Irrelevant to a non-browser HTTP client; we read `Set-Cookie` headers directly.

## Open Questions

- Whether to expose the captured session (e.g. `whoami` verification) as an opt-in post-login check. Leaning: add later with the 401-refresh change.
