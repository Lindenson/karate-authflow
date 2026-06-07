## ADDED Requirements

### Requirement: Initialize the Kratos browser login flow

The Kratos client SHALL initialize a login flow by sending `GET {publicUrl}/self-service/login/browser` with header `Accept: application/json`, and SHALL extract the submission `action` URL and the `csrf_token` value from the returned flow, retaining the CSRF cookie set on that response.

#### Scenario: Flow action and CSRF token extracted
- **WHEN** the client initializes a flow against a Kratos endpoint
- **THEN** it reads `ui.action` as the submission URL and the value of the hidden `ui.nodes[]` entry whose `attributes.name` is `csrf_token`, and retains the response's `csrf_token` cookie

### Requirement: Submit credentials with the password method

The Kratos client SHALL submit credentials by sending `POST` to the flow action URL with `Accept` and `Content-Type` of `application/json`, the retained CSRF cookie, and a JSON body containing `method: "password"`, `identifier`, `password`, and the `csrf_token` value.

#### Scenario: Password submission includes CSRF in cookie and body
- **WHEN** the client submits the login
- **THEN** the POST carries the CSRF cookie AND a body `csrf_token` equal to the value from the flow, plus `method`, `identifier`, and `password`

### Requirement: Capture the session cookie

On a successful submission the Kratos client SHALL capture the `ory_kratos_session` cookie from the response's `Set-Cookie` header and expose its value for injection into subsequent requests.

#### Scenario: Session cookie captured on success
- **WHEN** Kratos responds with success and a `Set-Cookie: ory_kratos_session=…`
- **THEN** the client returns the `ory_kratos_session` value

#### Scenario: Missing session cookie is an error
- **WHEN** the submission succeeds but no `ory_kratos_session` cookie is present
- **THEN** the client raises a login failure rather than returning an empty session

### Requirement: End-to-end transparency against a modelled Kratos

The project SHALL include a hermetic test that models a Kratos server (login-flow initialization, password submission, and a session-protected endpoint) and runs an authentication-free Karate feature through `KratosSessionStrategy` against it, asserting the protected endpoint returns success.

#### Scenario: Auth-free feature reaches a protected endpoint
- **WHEN** the test runs the auth-free feature with `KratosSessionStrategy` registered against the modelled Kratos
- **THEN** the protected request returns HTTP 200 and the Karate run reports zero failures, using no network
