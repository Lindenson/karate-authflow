## ADDED Requirements

### Requirement: Mutable response view

The library SHALL provide `AuthResponse`, a Karate-agnostic, mutable view of an HTTP response exposing the status, headers, and body (read and replace), as the response counterpart of `AuthRequest`.

#### Scenario: Response body can be read and replaced
- **WHEN** a post-response interceptor receives an `AuthResponse`
- **THEN** it can read the status and body and replace the body, with the replacement visible downstream

### Requirement: Post-response interception

The library SHALL provide `PostResponseInterceptor` (`void intercept(AuthResponse response)`), invoked once per HTTP call after the response is received and before the scenario reads `response`, such that a replaced body is what the scenario's `match response.X` observes.

#### Scenario: Mutated body is what the scenario sees
- **WHEN** a registered post-response interceptor replaces the response body
- **THEN** the Karate scenario's `response` reflects the replaced body, not the original

#### Scenario: Request-only strategies are unaffected
- **WHEN** a strategy registers only a `PreRequestInterceptor`
- **THEN** no post-response behavior is added and existing registration calls keep working

### Requirement: Stable per-scenario identity

`AuthRequest` and `AuthResponse` SHALL each expose a `scenarioId()` that is stable across all requests of a single scenario and distinct between scenarios, so a shared strategy instance can partition per-scenario state safely under `Runner.parallel(n)`.

#### Scenario: Same scenario, same id
- **WHEN** several requests are intercepted within one scenario
- **THEN** they all report the same `scenarioId()`

#### Scenario: Different scenarios, different ids
- **WHEN** requests from two scenarios are intercepted
- **THEN** their `scenarioId()` values differ

### Requirement: Registration of a response interceptor

The library SHALL allow registering a request and a response interceptor together on a Karate runner in one call, keeping Karate types confined to the `spi` package.

#### Scenario: Register both interceptors
- **WHEN** a test registers a pre-request and a post-response interceptor via the entry point
- **THEN** both are wired to the run and the builder is returned for chaining
