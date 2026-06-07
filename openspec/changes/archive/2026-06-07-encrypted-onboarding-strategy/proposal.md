## Why

The crypto crown. 's `the crypto backend` (crypto backend) onboards a device through 4 (standard) or 5 (handshake) encrypted calls on `InitialisationController`: each carries an RGK-encrypted JSON payload inside a JSON envelope, and the final step issues the master keys `mTMK` / `mTTK`. Today a tester would have to hand-write RGK generation, RSA wrapping, AES-CBC, the double/single base64 "matryoshka", envelope assembly, and sticky-`rid` bookkeeping in every scenario. This change moves all of it into a strategy: the `.feature` file writes and asserts **cleartext only**, and the captured `mTMK` / `mTTK` land in a per-scenario store for the working flows that come later.

Source of truth: `ForKarate/onboarding-crypto-keys.md` (cross-checked against the actual controller/DTOs/processors). This change implements the **registration (onboarding) flow only** — the ongoing transaction flows are a separate, later strategy that consumes the key store.

## What Changes

- Add `RgkCryptoCodec` — plain-JCE primitives (RGK AES-128 gen, `RSA/ECB/PKCS1Padding` wrap of RGK under the crypto backend public key, `AES/CBC/PKCS5Padding` with a 16-zero IV for `ed`/`ecd`) plus the matryoshka helpers (§5/§8.8 of the handover).
- Add an envelope codec — build `InitGeneralRequest` (Step 1) and `RegistrationGeneralRequest` (Steps 2–4), parse `GeneralResponse`, honouring the request/response base64 asymmetry (double base64 on request `byte[]` fields, single on response `String` fields). No MAC on onboarding (RGK ≠ STTK → `mcc` is absent).
- Add `EncryptedOnboardingStrategy` — a `PreRequestInterceptor` + `PostResponseInterceptor` that routes by `(method, pathSuffix)` to a step, enforces step order, encrypts the request and decrypts the response so scenarios stay cleartext, and captures `deviceSn` (Step 1) and `mTMK` / `mTTK` (Step 4). Supports both `standard` and `handshake` flavors (Step 0 handshake).
- Add `OnboardingKeyStore` — per-scenario crypto state (RGK, sticky `rid`, `deviceSn`, `mTMK`, `mTTK`, completed steps), parallel-isolated via `scenarioId()`, with `resetKeys()`.
- Add `FakeCryptoBackend` test harness (JDK `HttpServer` implementing the **server side** of the crypto) + unit round-trip tests for the codec + hermetic integration tests running the §12 features (standard and handshake).
- Add a consumer README section and a "raised questions" log for any mismatch found against the doc.

## Capabilities

### New Capabilities
- `encrypted-onboarding`: Driving the crypto backend device-onboarding flow from cleartext `.feature` files — step routing and ordering, the RGK encrypt/decrypt + envelope wire encoding, out-of-scope URL rejection, and the two flavors.
- `onboarding-key-store`: Per-scenario capture and retention of the onboarding crypto material (`mTMK` / `mTTK`, `deviceSn`, `rid`, RGK), parallel-isolated, with explicit reset, ready for follow-up flows.

### Modified Capabilities
<!-- None archived yet. Builds additively on response-interception (AuthResponse / scenarioId). -->

## Impact

- **New code**: package `io.github.lindenson.karate.authflow.onboarding` (`EncryptedOnboardingStrategy`, `RgkCryptoCodec`, envelope DTOs/codec, `OnboardingKeyStore`, config, exceptions); test `FakeCryptoBackend` + features + README section.
- **Dependencies**: none new — plain JCE; Jackson already `provided` (§8.6: a vendor crypto library is NOT needed for onboarding).
- **Non-goals**: transaction / STTK / SPTK / DEK flows; MAC verification (absent on onboarding); `KeyAttestationController` (§11, out of scope); key derivation from `mTMK`/`mTTK` (next strategy); a real crypto backend dev server (we test against `FakeCryptoBackend`; the same features will run against the real server when wired).
- **Publication note**: per the owner's decision this ships in the public repo, exposing the the crypto backend onboarding wire format.
