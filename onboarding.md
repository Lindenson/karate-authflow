# Encrypted device onboarding & session crypto (STTK)

The crypto layer is `karate-authflow`'s reason to exist: Karate has no native
support for request-body encryption or custom key derivation. This document
describes the two cooperating strategies — **encrypted device onboarding** (the
RGK envelope) and the **STTK session layer** (working-flow endpoints) — and the
exact algorithms behind them. Tests stay 100% cleartext; the plugin owns every
crypto step in both directions.

A fully runnable, zero-setup demonstration of the whole journey lives in
[`examples/`](examples) (`OnboardingExample` + an in-process `FakeCryptoBackend`):
onboard a device → derive session keys → `POST /api/v1/devices/language`.

---

## 1. Encrypted device onboarding (RGK)

`EncryptedOnboardingStrategy` drives an encrypted device-onboarding handshake
against a crypto backend from **cleartext** feature files. It owns the whole
envelope — RGK generation, RSA-wrapping the RGK under the backend's public key,
AES-CBC of each payload, the request/response base64 layering, and the sticky
`rid`/`dsn` bookkeeping — and decrypts each response so `match response.X` works
on plaintext. After the final step the master keys `mTTK` / `mTMK` are captured
into a per-scenario `OnboardingKeyStore` for the session layer.

### Flavors

| Flavor | Steps | First call |
|---|---|---|
| `STANDARD` | 4 | `POST /api/v1/init` |
| `HANDSHAKE` | 5 | `POST /api/v1/init/initial_handshake_key` (then the 4 standard steps) |

The standard four steps are: `init` (device info + RGK exchange → `deviceSn`),
`credentials`, `otp/confirm-otp`, `access-code/register` (→ master keys
`mttk`/`mtmk`).

### The RGK envelope (wire format)

Each encrypted request is an envelope around an AES-encrypted payload:

- **RGK** — a random AES key generated per onboarding `rid`. The payload (`ed`)
  is `AES/CBC/PKCS5Padding` with a 16-byte zero IV under the RGK.
- **`rgke`** — the RGK itself, RSA-wrapped: `RSA/ECB/PKCS1Padding` under the
  backend's public key (X.509 DER), so only the backend can recover it.
- **base64 "matryoshka"** — request `byte[]` fields `ed` and `rgke` are **double**
  base64-encoded on the wire; `rid`, `v`, `pkr`, `dsn` (and response `ecd`) are
  **single** base64. (Jackson serializes `byte[]` as base64, and the field values
  are themselves base64 strings — hence the doubling on binary fields.)
- **No MAC on onboarding** — the RGK envelope carries no `mcc` (that belongs to
  the STTK layer below).
- Selected inner `byte[]` fields are base64(UTF-8) per step (e.g. the device-info
  block and credentials); the handshake fingerprint `dfrgprt` is base64 on the
  wire.

The response is `GeneralResponse{ reid, ecd }`; `ecd` is the AES-encrypted,
base64'd payload, decrypted under the same RGK.

### Configuration & registration

```java
EncryptedOnboardingConfig config = EncryptedOnboardingConfig.builder()
        .flavor(OnboardingFlavor.HANDSHAKE)   // or STANDARD (+ builtInServerKey + builtInPkr)
        .appVersion(100_005_000)              // must exist in the server's version table
        .otp("123456")                        // optional: fix the OTP step (test accounts)
        .build();
EncryptedOnboardingStrategy strategy = new EncryptedOnboardingStrategy(config);

Results results = KarateAuth
        .register(Runner.path("classpath:onboarding.feature"), strategy, strategy) // pre + post
        .parallel(5);

// the captured keys, per scenario:
OnboardingKeyStore.Onboarded keys = strategy.keyStore(scenarioId).requireOnboarded();
// keys.mtmk(), keys.mttk(), keys.deviceSn(), keys.rid()
```

The feature stays pure (no crypto, no base64, no `rid`/`rgke`/`dsn`):

```gherkin
Given path '/api/v1/init'
And request { dad: { dn: 'Pixel 7', ... }, dfrgprt: 'fp-1', fbrid: 'token', lag: 'en-US' }
When method post
Then status 200
And match response.deviceSn == '#string'
```

State is isolated per scenario (`scenarioId()`), so a single strategy instance is
parallel-safe. Out-of-scope URLs and out-of-order steps fail the scenario loudly.
A real OTP delivered out-of-band can be resolved via `otpSupplier(...)`; for test
accounts use a server-side fixed OTP and pass it with `otp(...)`.

> Verified end-to-end against a live crypto-backend sandbox (both flavors), and
> hermetically in CI against an in-process `FakeCryptoBackend`.

---

## 2. Session crypto (STTK) — working-flow endpoints

Onboarding is only the door. Once a device is onboarded, every *working* request
(change language, fetch config, post a transaction, …) is protected by a
**per-request session layer** the plugin derives and applies transparently. The
running example endpoint is `POST /api/v1/devices/language` with a cleartext body
`{ language: 'en' }`.

`OnboardingSessionFlow` is a single composite strategy that routes by URL:
onboarding endpoints go through `EncryptedOnboardingStrategy` (RGK), everything
else through `SttkSessionStrategy` (the session layer) — both sharing the same
per-scenario `OnboardingKeyStore`. Register it once and write a plain feature that
onboards and then calls the working endpoint; the crypto is invisible.

```java
EncryptedOnboardingConfig config = EncryptedOnboardingConfig.builder()
        .flavor(OnboardingFlavor.HANDSHAKE)
        .appVersion(100_005_000)
        .build();
OnboardingSessionFlow flow = new OnboardingSessionFlow(config, false); // false = full encryption

Results results = KarateAuth
        .register(Runner.path("classpath:journey.feature"), flow, flow)
        .parallel(5);
```

```gherkin
# journey.feature — 100% cleartext, no crypto, no base64, no key handling
Given path '/api/v1/init/initial_handshake_key'   # ... onboarding steps ...
...
# working flow — transparently wrapped in the session envelope both ways:
Given path '/api/v1/devices/language'
And request { language: 'en' }
When method post
Then status 200
```

### Key derivation

The master keys arrive (at onboarding's access-code step) **wrapped under the RGK
and hex-encoded**: `hex( AES/ECB/NoPadding(RGK, masterRaw) )`. The plugin unwraps
them once per scenario, then derives **fresh per-request** session keys:

```
sessionId = hex(rid)                              # 16 bytes from the request UUID
STTK      = HMAC-SHA256(masterTransportKey, sessionId)   # 32 bytes → AES-256 encryption key
STMK      = HMAC-SHA256(masterMacKey,       sessionId)   # session MAC key
```

`rid` is regenerated for every request, so `STTK`/`STMK` are one-time per call.

### Per-request flow (all pure JCE, no native/vendor code)

1. Derive `STTK`/`STMK` from the master keys and a fresh `rid` (as above).
2. Encrypt the cleartext body under `STTK` (`AES/CBC/PKCS5Padding`, zero IV) → `ed`.
3. Compute the request MAC: `mccd = base64( HMAC-SHA256(STMK, ed-ciphertext)[0..15] )`.
4. Build the request envelope `{ rid, v, dsn, ed, mccd }`.
5. On the response, verify the server MAC `mcc` with `STMK`, then decrypt `ecd`
   with `STTK`, so `match response.X` sees plaintext.

### Two operating modes

| Mode | How to enable | Wire shape | When to use |
|---|---|---|---|
| **Full encryption** | `new OnboardingSessionFlow(config, false)` | `ed` = AES ciphertext, `mccd` = real STTK/STMK MAC, response MAC verified | production-equivalent crypto |
| **Skip-encryption** (test build) | `new OnboardingSessionFlow(config)` (default) | `ed` = base64(plaintext), MAC skipped server-side | backends running in a test build that bypasses session crypto |

> Both modes are proven end-to-end against a live backend (full-encryption
> `devices/language` returns a decrypted live response and the request/response
> MACs match), and hermetically against the in-process `FakeCryptoBackend`. The
> session crypto is reproduced in plain JCE and validated byte-for-byte against a
> reference implementation.
