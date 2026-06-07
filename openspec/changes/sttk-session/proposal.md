## Why

Onboarding ends with the master keys (`mTMK`/`mTTK`) captured in `OnboardingKeyStore`. The *working* flows (transactions, device settings, etc.) run under a **session key (STTK)** derived from those master keys, with a per-request **MAC (STMK)**. This change adds that session layer so a tester can, in one cleartext feature, onboard a device and then drive an STTK-protected endpoint (first target: `POST /api/v1/devices/language`) — with the plugin handling session-key derivation, encryption, and MAC transparently in both directions.

Reverse-engineered from the backend's `SoftHsmCryptoService`: the LMK wrapping is fixed constants, so the whole STTK layer is **pure JCE** — no private vendor dependency at runtime.

## What Changes

- Extend the crypto codec with STTK primitives (pure JCE): unwrap `mTTK`/`mTMK` (delivered under the onboarding RGK), `deriveSttk`/`deriveStmk` = `HmacSHA256(masterKey, sessionId)` where `sessionId = hex(rid)`, AES-256/CBC encryption under STTK, and the 128-bit HMAC-SHA256 MAC under STMK.
- Add `SttkSessionStrategy` (`PreRequestInterceptor` + `PostResponseInterceptor`): builds the `FullGeneralRequest` envelope (`rid,v,dsn,ed,mccd`), encrypts `ed` under a per-`rid` STTK, computes the request MAC `mccd`, decrypts the response `ecd`, and verifies the response MAC `mcc`. Consumes the onboarding result (`mTTK`/`mTMK`/RGK/`deviceSn`) from `OnboardingKeyStore`.
- Add a composite registration so a single feature can onboard (handshake/standard) **and** then call STTK endpoints, sharing per-scenario state.
- Extend `FakeCryptoBackend` with `POST /api/v1/devices/language` (server-side STTK decrypt + MAC verify + encrypted empty response).
- A test-scope parity check against the real `transenix-crypto` jar (`SoftHsmCryptoService`) proving our pure-JCE STTK/STMK/MAC match byte-for-byte; a hermetic integration test (onboard → language); and a live runner for the real backend.

## Capabilities

### New Capabilities
- `sttk-session`: Deriving a session key from the onboarding master keys and driving STTK-encrypted, MAC'd working-flow endpoints from cleartext features.

### Modified Capabilities
<!-- None archived for modification; builds on encrypted-onboarding + onboarding-key-store. -->

## Impact

- **New code**: STTK methods in the crypto codec; `SttkSessionStrategy` + a composite/dispatch entry; `FakeCryptoBackend` language endpoint; tests + a `devices-language` feature + live runner.
- **Dependencies**: none new at runtime (pure JCE); `transenix-crypto:3.6.1` added in **test scope only** as the parity oracle.
- **Non-goals**: PIN/SPTK/DUKPT flows, transaction (ISO8583) endpoints beyond `devices/language`, automatic session rotation policy.
