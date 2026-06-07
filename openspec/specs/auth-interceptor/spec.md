# auth-interceptor Specification

## Purpose
TBD - created by archiving change auth-interceptor-core. Update Purpose after archive.
## Requirements
### Requirement: Auth strategy contract

The library SHALL define an `AuthStrategy` extension point that is a named pre-request interceptor: it receives the mutable `AuthRequest` for every outgoing HTTP request and MAY modify its headers and/or body. The contract MUST NOT reference any Karate type, so a single strategy implementation works across Karate versions.

#### Scenario: Strategy implements the interceptor contract
- **WHEN** a class implements `AuthStrategy`
- **THEN** it provides `void intercept(AuthRequest request)` and `String name()`, and references no `com.intuit.karate.*` type

### Requirement: Transparent registration with a Karate runner

The library SHALL provide a registration entry point that wires an `AuthStrategy` (or any `PreRequestInterceptor`) into a Karate `Runner.Builder` in a single call and returns the builder for fluent chaining, without requiring any change to feature files.

#### Scenario: One-line wiring
- **WHEN** a test calls the registration helper with a runner builder and a strategy
- **THEN** the same builder is returned, now carrying a Karate hook that will invoke the strategy

#### Scenario: Feature files are unchanged
- **WHEN** a registered strategy is active during a run of an existing feature that contains no authentication steps
- **THEN** the feature executes unchanged and the strategy is applied to its requests

### Requirement: Applied to every request before send

When a strategy is registered, the library SHALL invoke it exactly once for each outgoing HTTP request, before the request leaves Karate, with mutations reflected on the wire.

#### Scenario: Header mutation reaches the server
- **WHEN** a registered strategy adds an `Authorization` header
- **THEN** the request sent to the server carries that header

### Requirement: Karate types confined to the seam

All registration and interception code that references `com.intuit.karate.*` SHALL reside in the `io.github.lindenson.karate.authflow.spi` package; strategy classes SHALL reside outside it.

#### Scenario: No Karate imports leak into strategies
- **WHEN** `src/main/java` is searched for `com.intuit.karate` imports
- **THEN** matches occur only within the `…authflow.spi` package

