## ADDED Requirements

### Requirement: HTTP Basic authentication strategy

The library SHALL provide `BasicAuthStrategy`, configured with a username and password, that sets the `Authorization` header to `Basic <base64(username:password)>` on every request, per RFC 7617.

#### Scenario: Authorization header is set
- **WHEN** a `BasicAuthStrategy("alice", "s3cret")` intercepts a request
- **THEN** the request's `Authorization` header equals `Basic ` followed by the Base64 encoding of `alice:s3cret`

#### Scenario: Overwrites any pre-existing Authorization header
- **WHEN** the request already carries an `Authorization` header and the strategy intercepts it
- **THEN** the header is replaced with the Basic credentials

### Requirement: Stateless and parallel-safe

`BasicAuthStrategy` SHALL hold no mutable state, so the same instance can be shared safely across scenarios running under `Runner.parallel(n)`.

#### Scenario: Concurrent reuse produces identical headers
- **WHEN** one `BasicAuthStrategy` instance intercepts many requests concurrently
- **THEN** each request receives the same correct `Authorization` header with no interference

### Requirement: Proven against a live endpoint

The project SHALL include an opt-in integration test (JUnit5 tag `live`, excluded from the default build) that runs an authentication-free Karate feature against a public HTTP Basic endpoint with `BasicAuthStrategy` registered, and asserts an authenticated `200` response.

#### Scenario: Transparent injection authenticates
- **WHEN** the `live` test runs the auth-free feature with a correctly-configured `BasicAuthStrategy`
- **THEN** the endpoint returns HTTP 200 and an authenticated response, and the Karate run reports zero failures

#### Scenario: Default build stays offline
- **WHEN** `mvn verify` runs without enabling the `live` group
- **THEN** the live test is skipped and the build requires no network
