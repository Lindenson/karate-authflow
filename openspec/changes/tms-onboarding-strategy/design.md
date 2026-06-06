## Context

Builds on `response-interceptor`: a strategy can implement `PreRequestInterceptor` (encrypt the outgoing request) and `PostResponseInterceptor` (decrypt the response so `match response.X` sees cleartext), and `scenarioId()` gives a stable per-scenario partition key. The protocol is fully specified in `ForKarate/onboarding-crypto-keys.md`; this design only decides *how* to structure the implementation. All crypto parameters there were code-verified; we treat them as fixed.

Key wire facts we depend on:
- Steps & envelopes: Step 1 `POST /api/v1/init` → `InitGeneralRequest` (`rid,v,pkr,rgke,ed`); Steps 2–4 (`PUT …/credentials`, `…/otp/confirm-otp`, `…/access-code/register`) → `RegistrationGeneralRequest` (`rid,v,dsn,ed`); Step 0 (ukrsib) `POST …/initial_handshake_key` is plain JSON.
- Crypto: RGK = AES-128; `ed`/`ecd` = `AES/CBC/PKCS5Padding`, IV = 16 zero bytes; `rgke` = `RSA/ECB/PKCS1Padding` wrap of RGK under the TMS public key (X509 DER). No MAC on onboarding.
- Base64 asymmetry: request `byte[]` fields are **double** base64 on the wire (inner legacy b64 + Jackson b64); response `String` fields are **single** base64.
- `rid` is generated at Step 1 and sticky for the whole onboarding; `deviceSn` from Step 1 feeds `dsn` on Steps 2–4; `mTMK`/`mTTK` arrive in Step 4's `ecd`.

## Goals / Non-Goals

**Goals:**
- `.feature` files write/assert the cleartext per-step payloads of §6; the strategy does all crypto + envelope + base64 + `rid`/`dsn` bookkeeping.
- Per-scenario isolation under `Runner.parallel(n)`; `mTMK`/`mTTK` retained until `resetKeys()`.
- Hermetic, reproducible tests via a `FakeTms` that performs the real server-side crypto.
- Both flavors (standard 4-step, ukrsib 5-step).

**Non-Goals:** transaction/STTK flows, key derivation, MAC, attestation, real dev server, `transenix-crypto` dependency.

## Decisions

- **One shared strategy instance, state partitioned by `scenarioId()`.** A `ConcurrentHashMap<String, TmsScenarioState>` keyed by `scenarioId()`; both the request and response hooks resolve the same state for a call. *Alternative:* one instance per scenario — rejected: registration happens once on the runner before `parallel(n)`, so a single instance must self-partition. `resetKeys(scenarioId)` and `resetAll()` provided.
- **Step inferred from `(method, pathSuffix)` via a fixed `ROUTES` map (§7).** Unknown URL → `OutOfScopeOnboardingException`; prerequisites not in the state's `EnumSet<OnboardStep>` → `OnboardingOrderException`, thrown locally **before** sending. Both fail the scenario loudly.
- **Request transform (PreRequest).** Read the cleartext body the feature wrote (the inner per-step DTO). Then per step:
  - Step 0 (ukrsib): leave the plain body as-is (it's `{dfrgprt}`); no envelope.
  - Step 1: lazily generate RGK + sticky `rid`; pick `tmsPublicKey`+`pkr` (from Step 0 state for ukrsib, from config for standard); build `ed` = matryoshka(encrypt(json(body))), `rgke` = matryoshka(wrap(rgk)); assemble `InitGeneralRequest`; replace the request body with `json(envelope)`.
  - Steps 2–4: build `ed` from the body; assemble `RegistrationGeneralRequest` with `dsn`; replace body. (Step 4's `ed` carries `acd/otp/atp`; OTP for Step 3 is pulled from `otpSupplier`.)
- **Response transform (PostResponse).** Parse `GeneralResponse`; if `mcc` present, verify (won't be, on onboarding); decrypt `ecd` (single base64 → AES); replace the response body with the cleartext DTO so `match response.deviceSn` / `response.mttk` work. Capture `deviceSn` (Step 1), `mTMK`/`mTTK` (Step 4); advance `completedSteps`. Step 0: read `ihshky` from the plain response, store `tmsPublicKey`+`pkr`.
- **`TmsCryptoCodec` is pure JCE (no `transenix-crypto`).** Lifted from handover §8.8; the matryoshka helpers (`buildEdField`, `buildRgkeField`, `parseEcdField`) live here. Isolated and unit-tested for round-trip.
- **Envelope DTOs via Jackson** with `@JsonInclude(NON_NULL)`; `byte[]` fields reproduce the server's double-base64 (we assign the **inner-base64 string's UTF-8 bytes** to the `byte[]`, Jackson adds the outer base64). Field names match the wire (`rid,v,pkr,rgke,ed,dsn,reid,ecd,mcc`).
- **`FakeTms` mirrors the server crypto** so tests are hermetic and trustworthy: it owns an RSA key pair (its public key is the `ihshky`/built-in TMS key), unwraps `rgke` → RGK, decrypts `ed`, validates per-step inputs (login/password, OTP, access-code shape), and encrypts `ecd`. It is the executable oracle for "did the strategy encode the wire correctly". *Alternative:* a dumb stub returning canned ciphertext — rejected, wouldn't prove our encryption is correct.
- **Config object** (immutable per strategy): `flavor`, `deviceFingerprint`, `appVersion`+`versionHash`, `builtInTmsPublicKey`+`builtInPkr` (standard), `userLogin`/`userPassword`, `accessCode`, `otpSupplier`, optional RGK length (default 128). `otpSupplier` lets the test inject the stubbed OTP at Step 3.

## Risks / Trade-offs

- **The base64 matryoshka asymmetry is the #1 bug magnet.** → A dedicated codec round-trip test (`buildEdField` → server-style decode → original) and a `FakeTms` that decodes exactly as the server does; any asymmetry mistake fails immediately.
- **RGK length / `versionCode` encoding** may differ per real flavor. → Make RGK length configurable (default 128 per §8.1); encode `v` as `ByteBuffer.putInt` (§5.6); record uncertainties in the raised-questions log.
- **`FakeTms` could "agree" with a strategy bug** if both share a wrong assumption. → Keep `FakeTms` decoding logic written straight from the server-side description (decode like `AbstractEncryptedRequestProcessor`), not by mirroring the strategy; add at least one assertion against a hand-computed fixture.
- **Per-scenario state leak across reused threads.** → Keyed by `scenarioId()` (not ThreadLocal); entries created on demand; `resetAll()` for between-suite hygiene.
- **Cleartext body shape from the feature** must match the inner DTO. → Document the per-step cleartext schema (§6) in the README; on a missing required field, fail with a clear message.

## Verified against softpos-core source (HEAD ee94b8a)

Cross-checked the live backend (the graphify graph was stale; read current source). Confirmed and refined:
- **Matryoshka — both directions confirmed.** Request `ed`/`rgke` are DOUBLE base64 (`AbstractEncryptedRequestProcessor`: `new String(getEd())` is the inner base64, then `CryptographyService.getDecryptedData` base64-decodes + AES-decrypts). Response `ecd` is SINGLE base64 (`CryptographyService.encryptData = Base64.encodeToString(getEncryptedData(...))`). `mcc` is `@JsonInclude(NON_NULL)` and null for non-STTK → absent on onboarding.
- **Envelope `byte[]` fields carry UTF-8 of their string form; Jackson adds ONE base64** (`rid` via `new String(rid)`; `v` = `ByteBuffer.putInt(versionCode)` 4 bytes; `pkr` = refCode string; `dsn` = the opaque deviceSn token from Step 1). Only `ed` and `rgke` are double (their byte[] content is itself a base64 string).
- **Per-step inner field-encode schema (the bit the strategy must get right).** The strategy accepts plain values from the feature and base64-encodes (UTF-8) exactly these inner `byte[]` fields before encrypting; everything else is passed through:
  - Step 1 `InitialisationEncryptedRequest`: encode `fbrid`, `dad.dn`, `dad.did`, `dad.sen`, `dad.osv`, `dad.imi`, `dad.iso`. Pass-through: `dfrgprt` (String), `lag` (enum → `LanguageToLocaleJacksonSerializer`, e.g. `en-US`).
  - Step 2 `CredentialsEncryptedRequest`: encode `ussLg`, `urrPsa`.
  - Step 3 `OtpEncryptedRequest`: none (all String/Date/object: `otp`, `reLLo7eh`, `timezone`, `acceptedTosTime?`, `requiredDataConfirmedTime?`, `device?`).
  - Step 4 `AccessCodeRegistrationEncryptedRequest`: none (`acd` String, `otp` `MmaPasswordOperationType` enum, `atp` `AuthType` enum).
- **Responses:** Step 1 `DeviceSnEncryptedResponse.deviceSn` is `byte[]` → appears as a base64 string in the decrypted JSON; the strategy keeps it as the opaque `deviceSn` token (and feeds it straight into `dsn`). Step 4 `AccessCodeEncryptedResponse` = `{mttk, mtmk}` (Strings). A success-shape `error` block is appended INSIDE the decrypted `ecd` JSON — the strategy ignores it.
- **Envelope rules:** `os` must be null/empty (non-empty → iOS path); `se` omit. `GeneralResponse` fields all `NON_NULL`.

Implication: the strategy carries a small **per-step field schema** (which inner paths are `byte[]`) driving the base64 transform — data-driven, matching the DTOs above.

## Open Questions (seed for the §14.4 raised-questions log)

- Doc §5.6 calls `dsn` "single base64, inner = plain string"; precise behaviour is that the inner `deviceSn` token is itself base64 — operationally unchanged (strategy treats it opaque), flagged for doc accuracy.

- Exact `versionCode` / `versionHash` values the dev server expects (test fixture).
- RGK length actually used by the target mobile flavor (16 vs 32).
- Whether the standard-flavor built-in TMS public key + `pkr` will be provided as fixtures, or we generate a self-consistent pair for `FakeTms` only.
- Whether any onboarding response ever carries a non-null `error` block that must be surfaced even on 2xx.
