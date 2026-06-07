## Why

So far strategies can only mutate the outgoing request. The next class of auth — crypto / encrypted-envelope flows (e.g. TMS device onboarding) — must also transform the **response**: decrypt the server payload and hand the scenario cleartext so `match response.X` works. Those flows are also **stateful per scenario** (each scenario onboards its own device), but a single strategy instance is registered for the whole parallel run. This change extends the interceptor seam to cover responses and to expose a stable per-scenario key, unblocking both the crypto strategy and the deferred Kratos `401` auto-refresh.

A spike confirmed that mutating Karate's `Response` inside `RuntimeHook.afterHttpCall` is visible to the scenario (`match response` sees the mutated body).

## What Changes

- Add `AuthResponse`: a version-agnostic, mutable view of the HTTP response (status, headers, body) — the response counterpart of `AuthRequest`.
- Add `PostResponseInterceptor` (`void intercept(AuthResponse response)`), invoked after each HTTP call, before the scenario reads `response`.
- Add a stable `scenarioId()` to both `AuthRequest` and `AuthResponse` (derived from Karate's `ScenarioRuntime.scenario.getUniqueId()`), so a shared strategy instance can partition per-scenario state and stay parallel-safe.
- Extend `KarateBinding` / `KarateV1Binding` to wire `RuntimeHook.afterHttpCall` and build a mutable `AuthResponse`; add a `KarateAuth.register(builder, pre, post)` overload. Existing request-only registration is unchanged.

## Capabilities

### New Capabilities
- `response-interception`: Post-response interception with a mutable response view and a per-scenario identity, plus the additive `scenarioId()` on the request view — enabling response-transforming and stateful strategies while existing request-only strategies keep working.

### Modified Capabilities
<!-- None archived yet; the additive request-view change is captured under response-interception. -->>

## Impact

- **New code**: `spi/AuthResponse.java`, `spi/PostResponseInterceptor.java`; `AuthRequest` gains `scenarioId()`; `KarateV1Binding` gains a `V1AuthResponse` and `afterHttpCall` wiring; `KarateAuth` gains a 3-arg `register`.
- **Backward compatible**: `BasicAuthStrategy` / `KratosSessionStrategy` and the existing `createHook(PreRequestInterceptor)` / `register(builder, interceptor)` continue to work.
- **Unblocks**: `tms-onboarding-strategy` (crypto) and a future Kratos `401` refresh.
