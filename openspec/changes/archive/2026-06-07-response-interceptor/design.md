## Context

The v1 seam wires `RuntimeHook.beforeHttpCall(HttpRequest, ScenarioRuntime)` and exposes a mutable `AuthRequest`. Verified against Karate 1.5.2:
- `RuntimeHook.afterHttpCall(HttpRequest, Response, ScenarioRuntime)` exists; `com.intuit.karate.http.Response` has `setBody(byte[]/String)`, `setStatus(int)`, `getBodyAsString()`.
- A spike proved a body mutated in `afterHttpCall` is what the scenario's `response` sees.
- `ScenarioRuntime.scenario` (public final) → `getUniqueId()` is a stable id for the whole scenario (same across all its steps and the before/after of each call); distinct per scenario instance under `Runner.parallel`.

## Goals / Non-Goals

**Goals:**
- A mutable `AuthResponse` and a `PostResponseInterceptor`, wired through the existing binding.
- A stable `scenarioId()` on request and response views for per-scenario state partitioning.
- Strictly additive: existing request-only strategies and registration calls keep working.

**Non-Goals:**
- No crypto, no Kratos refresh here (consumers of this seam).
- No Karate v2 binding.

## Decisions

- **Separate `PostResponseInterceptor`, not a fattened `AuthStrategy`.** Request-only strategies (Basic) shouldn't gain a response method they ignore. A strategy that needs both (crypto) implements `PreRequestInterceptor` + `PostResponseInterceptor`. *Alternative:* one combined interface — rejected, forces no-op methods on simple strategies.
- **`scenarioId()` on the views, not a new parameter.** Adding `scenarioId()` to `AuthRequest`/`AuthResponse` keeps the interceptor signatures unchanged and gives stateful strategies a partition key without threading extra arguments. Derived from `sr.scenario.getUniqueId()`. *Alternative:* `ThreadLocal` keyed state inside the strategy — rejected, brittle across Karate's thread reuse between scenarios.
- **`createHook(pre, post)` with `post` nullable; old single-arg delegates.** The binding registers a single `RuntimeHook` whose `beforeHttpCall` runs `pre` and whose `afterHttpCall` runs `post` (only if non-null). Keeps one hook per registration.
- **`AuthResponse.body(...)` mirrors `AuthRequest`.** `setBody(String)`/`setBody(byte[])`, `status()`, `header()`. The v1 impl delegates to `com.intuit.karate.http.Response`.
- **Karate types stay confined to `spi`.** `V1AuthResponse` wraps `Response`; `scenarioId()` reads `sr.scenario.getUniqueId()` — all inside `spi`.

## Risks / Trade-offs

- **`afterHttpCall` ordering vs scenario read** — relied upon for response mutation. → Proven by spike; a permanent test locks it in.
- **`getUniqueId()` format/stability across Karate minors.** → Treated as an opaque stable token, only used for equality/partitioning, never parsed; localized to the v1 binding.
- **Adding `scenarioId()` to `AuthRequest`** could break external `AuthRequest` implementors. → The only implementation is internal (`V1AuthRequest`); documented as an internal SPI surface pre-1.0.
