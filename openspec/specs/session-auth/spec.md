# session-auth Specification

## Purpose
TBD - created by archiving change session-strategy. Update Purpose after archive.
## Requirements
### Requirement: Login once, reuse the session

A session strategy SHALL authenticate at most once and reuse the captured session credential for all subsequent requests, performing the login lazily on first use rather than at construction.

#### Scenario: Single login across many requests
- **WHEN** a session strategy intercepts many requests in sequence
- **THEN** the login is performed exactly once and every request carries the session credential from that login

#### Scenario: No network at construction
- **WHEN** a session strategy is constructed
- **THEN** no login request is sent until the first request is intercepted

### Requirement: Session credential injected on every request

Once authenticated, the strategy SHALL attach the captured session credential to every intercepted request. For cookie-based sessions it SHALL add the session cookie to the request's `Cookie` header, preserving any cookies already present.

#### Scenario: Cookie added
- **WHEN** an authenticated cookie-session strategy intercepts a request with no `Cookie` header
- **THEN** the request gains a `Cookie` header containing the session cookie

#### Scenario: Existing cookies preserved
- **WHEN** the request already has a `Cookie` header
- **THEN** the session cookie is appended and the pre-existing cookies remain

### Requirement: Thread-safe under parallel execution

A single session-strategy instance SHALL be safe to share across scenarios running under `Runner.parallel(n)`: concurrent first-use SHALL trigger only one login, and credential injection SHALL not corrupt requests.

#### Scenario: Concurrent first use logs in once
- **WHEN** multiple threads intercept their first request concurrently through one strategy instance
- **THEN** exactly one login is performed and all threads observe the same session credential

### Requirement: Login failure is visible

If authentication does not succeed, the strategy SHALL raise a clear error rather than silently proceeding without a session credential.

#### Scenario: Bad credentials fail loudly
- **WHEN** the login submission returns a non-success response
- **THEN** an exception describing the login failure is raised and no request is sent without the session credential

