## Why

The foundation (`bootstrap-project`) shipped the `KarateBinding` seam but no authentication behavior. This change delivers the first usable capability: a transparent interceptor that applies a pluggable `AuthStrategy` to every outgoing request, plus the first concrete strategy (HTTP Basic). After this, a team can drop `karate-authflow` into a Karate suite and have credentials injected on every request without touching feature files — and we prove it against a real login-protected endpoint.

## What Changes

- Add an `AuthStrategy` contract (a named `PreRequestInterceptor`) — the extension point all auth schemes implement.
- Add `BasicAuthStrategy`: encodes `user:pass` into an `Authorization: Basic …` header on every request. Stateless and therefore safe under `Runner.parallel(n)`.
- Add a Karate-1.x registration entry point so a single line wires a strategy into a `Runner.Builder` (`hook`), keeping feature files unchanged. The entry point lives in the `spi` package (the only place allowed to touch `com.intuit.karate.*`); the strategy classes stay Karate-agnostic.
- Add an integration test that runs an auth-free Karate feature against a public Basic-auth endpoint and asserts a `200` / authenticated response — proving transparent injection end-to-end. The test is tagged `live` and excluded from the default offline build.

## Capabilities

### New Capabilities
- `auth-interceptor`: The core engine — the `AuthStrategy` contract, how a strategy is registered with a Karate runner, and the guarantee that it is applied transparently to every request before send.
- `basic-auth`: HTTP Basic authentication as the first concrete strategy.

### Modified Capabilities
<!-- None — build-and-packaging requirements are unchanged. -->

## Impact

- **New code**: `…/authflow/AuthStrategy.java`, `…/authflow/BasicAuthStrategy.java`; a registration helper in `…/authflow/spi`; integration test + a `*.feature` resource; surefire `live`-group exclusion wiring in `pom.xml`.
- **Dependencies**: none new (uses existing Karate `provided` + test scope).
- **Behavior**: still no stateful/session or crypto logic — those are later changes that implement the same `AuthStrategy` contract.
