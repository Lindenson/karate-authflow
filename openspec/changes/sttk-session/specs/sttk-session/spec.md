## ADDED Requirements

### Requirement: Session-key derivation from onboarding keys

The library SHALL derive the session keys from the onboarding master keys: `sessionId = Hex(rid)`, `STTK = HmacSHA256(mTTK, sessionId)`, `STMK = HmacSHA256(mTMK, sessionId)`, where `mTTK`/`mTMK` are first unwrapped from their onboarding form (wrapped under the RGK). Derivation SHALL match the reference soft-HSM byte-for-byte.

#### Scenario: Derived keys match the reference implementation
- **WHEN** STTK and STMK are derived for a given `rid` and master keys
- **THEN** they equal the reference `deriveSttk`/`deriveStmk` output for the same inputs

#### Scenario: Master keys unwrapped with the onboarding RGK
- **WHEN** the onboarding-delivered `mTTK`/`mTMK` (wrapped under the RGK) are loaded
- **THEN** they are unwrapped with the scenario's RGK before derivation

### Requirement: STTK request encryption and MAC

For an STTK endpoint the strategy SHALL read the cleartext body, encrypt it under a per-`rid` STTK (AES-CBC, zero IV) into `ed`, assemble the `FullGeneralRequest` envelope (`rid`, `v`, `dsn`, `ed`, `mccd`), and set `mccd` to the 128-bit HMAC-SHA256 (under STMK) of the `ed` ciphertext — without the feature writing any crypto.

#### Scenario: Encrypted, MAC'd request
- **WHEN** an STTK request is intercepted with a cleartext body
- **THEN** the outgoing body is a `FullGeneralRequest` whose `ed` is the STTK-encrypted payload and whose `mccd` is the STMK MAC over that ciphertext

### Requirement: Response decryption and MAC verification

The strategy SHALL verify the response `mcc` (STMK MAC over the `ecd` ciphertext) and, on success, decrypt `ecd` under STTK and replace the response body with the cleartext. A MAC mismatch SHALL fail the scenario.

#### Scenario: Verified and decrypted response
- **WHEN** a valid STTK response is received
- **THEN** its `mcc` verifies and the scenario sees the decrypted cleartext

#### Scenario: Tampered response is rejected
- **WHEN** the response `mcc` does not match
- **THEN** the strategy raises an error and the scenario fails

### Requirement: Consumes the onboarding result

The session strategy SHALL obtain `mTTK`/`mTMK`/RGK/`deviceSn` from the onboarding key store for the scenario, and SHALL fail clearly if onboarding has not completed.

#### Scenario: Requires onboarding first
- **WHEN** an STTK request runs before onboarding completed for that scenario
- **THEN** the strategy fails with a clear "not onboarded" error

### Requirement: End-to-end working flow

The project SHALL demonstrate, hermetically, a full journey: onboard a device, then drive `POST /api/v1/devices/language` under STTK, with the feature cleartext and zero failures.

#### Scenario: Onboard then change language
- **WHEN** the journey feature runs against the modelled backend
- **THEN** onboarding completes and the STTK `devices/language` call returns success with verified MAC
