## ADDED Requirements

### Requirement: Step routing and order enforcement

The strategy SHALL map each request to an onboarding step by `(HTTP method, path suffix)` per the fixed route table, reject any URL not in the table, and enforce that a step's prerequisite steps have completed before the request is sent.

#### Scenario: Known route maps to its step
- **WHEN** a `POST /api/v1/init` request is intercepted
- **THEN** it is handled as Step 1 (Init)

#### Scenario: Unknown route is rejected
- **WHEN** a request targets a path not in the onboarding route table (e.g. `/api/v1/init/password/verify`)
- **THEN** the strategy raises an out-of-scope error and the scenario fails

#### Scenario: Out-of-order step fails before sending
- **WHEN** Step 3 (confirm-otp) is intercepted while Step 2 (credentials) has not completed
- **THEN** the strategy raises an ordering error locally, before any request is sent

### Requirement: Transparent request encryption

For encrypted steps the strategy SHALL read the cleartext per-step body written by the feature, base64-encode (UTF-8) exactly the inner fields that are `byte[]` on the server DTO, encrypt the resulting JSON under RGK, and assemble the wire envelope (`InitGeneralRequest` for Step 1, `RegistrationGeneralRequest` for Steps 2–4) with the correct base64 layering — replacing the outgoing request body. The feature author never writes crypto, base64, `rid`, `rgke`, or `dsn`.

#### Scenario: Step 1 envelope assembled
- **WHEN** Step 1 is intercepted with a cleartext `{dfrgprt, fbrid, lag, dad{...}}` body
- **THEN** the outgoing body is an `InitGeneralRequest` carrying `rid`, `v`, `pkr`, `rgke` (RSA-wrapped RGK, double-base64) and `ed` (RGK-encrypted payload, double-base64), and the inner `byte[]` fields (`fbrid`, `dad.*`) are base64-encoded while `dfrgprt`/`lag` are passed through

#### Scenario: Steps 2–4 carry the device serial
- **WHEN** an encrypted Step 2/3/4 request is intercepted
- **THEN** the outgoing body is a `RegistrationGeneralRequest` with the same sticky `rid`, the `dsn` from Step 1, and the step payload encrypted into `ed`

### Requirement: Transparent response decryption

For encrypted steps the strategy SHALL parse the `GeneralResponse`, decrypt `ecd` (single base64 → RGK), and replace Karate's response body with the cleartext payload so `match response.X` asserts on plaintext. If `mcc` is present it SHALL be verified; on onboarding it is absent and not verified.

#### Scenario: Response decrypted to cleartext
- **WHEN** Step 1 returns a `GeneralResponse` whose `ecd` decrypts to `{deviceSn}`
- **THEN** the scenario's `response.deviceSn` is the cleartext device serial

#### Scenario: Appended error block is tolerated
- **WHEN** the decrypted payload also contains a success-shape `error` block
- **THEN** the strategy still exposes the payload and the scenario's assertions on the real fields succeed

### Requirement: Both onboarding flavors

The strategy SHALL support the `standard` flavor (4 steps, built-in TMS public key + `pkr` from config) and the `ukrsib` flavor (5 steps; Step 0 `POST /api/v1/init/initial_handshake_key` is plain JSON and yields the per-device TMS public key used to wrap the RGK at Step 1).

#### Scenario: ukrsib handshake captured
- **WHEN** Step 0 returns `{ihshky}`
- **THEN** the strategy stores the TMS public key and `pkr` and uses them to wrap the RGK at Step 1

#### Scenario: standard skips the handshake
- **WHEN** the strategy is configured for the standard flavor
- **THEN** no Step 0 is required and the configured built-in TMS public key + `pkr` are used at Step 1
