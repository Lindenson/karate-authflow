## Context

`bootstrap-project` established: `AuthRequest` (version-agnostic mutable request), `PreRequestInterceptor` (`void intercept(AuthRequest)`), `KarateBinding` + `KarateV1Binding` (wires an interceptor into `RuntimeHook.beforeHttpCall`). Verified Karate 1.5.2 runner API: `Runner.path(String...)` → `Runner.Builder`, with `.hook(RuntimeHook)`, `.tags(String...)`, `.parallel(int)` → `Results` (`getFailCount()`, `getErrorMessages()`).

## Goals / Non-Goals

**Goals:**
- One contract (`AuthStrategy`) that every present and future auth scheme implements.
- Transparent application: feature files contain no auth steps; one line in the runner wires it in.
- A stateless Basic strategy proven against a real endpoint.
- Keep all `com.intuit.karate.*` references inside the `spi` package (preserve the v2 seam).

**Non-Goals:**
- Per-scenario / per-tag strategy switching (designed-for, not built here).
- Any stateful behavior (sessions, token refresh) or crypto.

## Decisions

- **`AuthStrategy extends PreRequestInterceptor`, adding `String name()`.** Rationale: a strategy *is* a pre-request interceptor; reusing the contract means the binding needs no new type, and `name()` gives logging/diagnostics a handle. *Alternative:* a separate `apply(AuthRequest)` method — rejected as a redundant parallel contract.
- **Registration entry point is a generic helper in `spi`, not in the core package.** Signature `static <T extends Runner.Builder<T>> T register(T builder, PreRequestInterceptor interceptor)` returns the builder for fluent chaining (`register(Runner.path(...), strategy).parallel(1)`). Rationale: it must reference `Runner.Builder`, so it belongs in `spi`; generics preserve the builder's concrete type and avoid wildcard-capture pain. The strategy classes themselves stay Karate-free. *Alternative:* put registration on the core `AuthFlow` facade — rejected, would leak Karate types out of `spi`.
- **Basic strategy is stateless.** It computes the header from final fields on each call; no shared mutable state → inherently safe across parallel scenarios. This sidesteps the thread-safety trap of the original singleton design.
- **Live test isolated behind a JUnit5 `live` tag, excluded by default** via surefire `excludedGroups` (driven by an overridable `${authflow.test.excludedGroups}` property defaulting to `live`). Rationale: keep `mvn verify` hermetic/offline-green; run network checks on demand with `-Dauthflow.test.excludedGroups=`. *Alternative:* always-on network test — rejected, makes CI flaky and offline builds fail.

## Risks / Trade-offs

- **Public Basic-auth endpoint availability/flakiness.** → Use a well-known echo endpoint; keep the test opt-in (`live`) so its outages never break the default build; assert on `authenticated == true` rather than brittle response shape.
- **`Runner.Builder` generic self-type (`Builder<T extends Builder>`).** → The generic `register` signature was validated against the 1.5.2 bytecode; a smoke compile covers it.
- **Users might expect per-scenario strategies now.** → README documents single-strategy MVP scope and that resolver-based switching is planned; the interceptor contract already accommodates it later without breaking changes.
