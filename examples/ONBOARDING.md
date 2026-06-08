# Encrypted device onboarding & STTK session — how the example works

This walks through [`OnboardingExample`](src/test/java/io/github/lindenson/karate/authflow/examples/OnboardingExample.java)
step by step: the exact JSON on the wire at each step, which classes and methods do
the work, how the master keys are captured, and how they drive the **session layer**
that protects a working-flow endpoint (`POST /api/v1/devices/language`).

Unlike the Basic or Kratos examples (one header / one cookie), this is a **stateful,
multi-step, encrypted** flow with **two crypto layers**:

1. **Onboarding (RGK)** — 4 steps that exchange a key and capture the master keys
   `mTTK` / `mTMK` (§2–§4).
2. **Session (STTK)** — every subsequent working request derives a fresh per-request
   session key from those master keys, encrypts the body, and MACs it (§5).

The point of `karate-authflow` is that the `.feature` file stays **cleartext** end to
end — the plugin does all the crypto and envelope work, in both directions, for both
layers.

---

## 1. The moving parts

| Class | Role |
|---|---|
| `OnboardingSessionFlow` | The composite the example registers. Routes by URL: onboarding endpoints → `EncryptedOnboardingStrategy` (RGK), everything else → `SttkSessionStrategy` (STTK). Shares one `OnboardingKeyStore` per scenario. |
| `EncryptedOnboardingStrategy` | The onboarding brain. Implements **both** `PreRequestInterceptor` (encrypt the request) and `PostResponseInterceptor` (decrypt the response). Routes each call to a step, enforces order, holds per-scenario state. |
| `SttkSessionStrategy` | The session brain. Per request: derive `STTK`/`STMK`, encrypt the body (`ed`), MAC it (`mccd`); on the response verify `mcc` and decrypt `ecd`. |
| `EncryptedOnboardingConfig` | Immutable config: flavor, app version, built-in server public key + key ref (`STANDARD`), RGK size, and the fixed/`otpSupplier` OTP. |
| `RgkCryptoCodec` | Pure-JCE crypto: RGK generation (AES-128), RSA-wrap of the RGK, AES-CBC of payloads, and the base64 "matryoshka" helpers. Reused for STTK payload AES. |
| `SttkCryptoCodec` | Pure-JCE session crypto: unwrap master keys under the RGK, derive `STTK`/`STMK` (`HmacSHA256`), compute the MAC. |
| `OnboardingKeyStore` | Per-scenario state: `rid`, `rgk`, `deviceSn`, completed steps, and the captured `mTMK` / `mTTK`. |
| `OnboardingFlavor` | `STANDARD` (4 steps, built-in key) or `HANDSHAKE` (5 steps, Step 0 fetches the key). The example uses `HANDSHAKE` — same as the real working flow. |
| `KarateAuth.register(builder, pre, post)` | Wires the composite into Karate as both interceptors (one line). |
| `FakeCryptoBackend` | **Example only** — an in-process server doing the real server-side crypto for **both** layers (RGK onboarding + STTK language) so the example needs no network/Docker. |

How it plugs into Karate (the seam, in package `…authflow.spi`):

```
KarateAuth.register(runner, flow, flow)          // flow = OnboardingSessionFlow
        │
        ▼
KarateV1Binding  ──►  RuntimeHook.beforeHttpCall(req) ─► flow.intercept(AuthRequest)   // encrypt (RGK or STTK)
                 └─►  RuntimeHook.afterHttpCall(resp) ─► flow.intercept(AuthResponse)  // decrypt (RGK or STTK)
```

`AuthRequest` / `AuthResponse` are Karate-agnostic mutable views; `scenarioId()`
(from Karate's `ScenarioRuntime`) lets one shared strategy keep **isolated state per
scenario**, so parallel onboardings never collide.

---

## 2. The crypto envelope (what the strategy hides)

Every encrypted step wraps a per-step JSON payload (`ed`) inside an envelope. Two
keys are involved:

- **RGK** — a fresh AES‑128 key the client generates once (Step 1). Payloads are
  `AES/CBC/PKCS5Padding`, IV = 16 zero bytes.
- **Server public key** — an RSA key. The RGK is wrapped with `RSA/ECB/PKCS1Padding`
  and sent as `rgke` so the server can recover it.

**base64 "matryoshka" (the easy thing to get wrong):**
- Request crypto fields (`ed`, `rgke`) are **double** base64 on the wire (an inner
  base64 produced by `RgkCryptoCodec`, plus the outer base64 the JSON layer adds to a
  `byte[]`).
- Request string fields (`rid`, `v`, `pkr`, `dsn`) are **single** base64 of their
  UTF‑8 bytes (`v` is a 4‑byte big‑endian int).
- The response `ecd` is **single** base64 of the ciphertext.

All of this lives in `RgkCryptoCodec`: `generateRgk`, `wrapRgk`, `buildRgkeField`,
`buildEdField`, `parseEcdField`.

---

## 3. Step by step (HANDSHAKE flavor, 5 steps)

> Notation: `b64(x)` = base64. The feature writes the **cleartext request**; the
> strategy emits the **wire request**; the server replies with the **wire response**;
> the strategy hands the scenario back the **decrypted response**.

### Step 0 — `POST /api/v1/init/initial_handshake_key` (fetch the server key)

The `HANDSHAKE` flavor opens by fetching the crypto-backend public key, so no key
has to be built into the client.

**Feature writes (cleartext):** `{ "dfrgprt": "fingerprint-123" }`

**Strategy** (`rememberFingerprint`): keeps the fingerprint as `pkr` (the server stores
the handshake key under it) and base64-encodes `dfrgprt` on the wire (it is a `byte[]`
server-side). No RGK yet.

**Wire response:** `{ "ihshky": "b64( server public key, X.509 DER )" }`

**Strategy** (`captureServerKey`): base64-decodes `ihshky` into the server public key
and stores it; Step 1 will RSA-wrap the RGK with it. Nothing is decrypted here.

### Step 1 — `POST /api/v1/init` (init: RGK exchange + device info)

**Feature writes (cleartext):**
```json
{
  "dad": { "dn": "Pixel 7", "did": "device-1", "sen": "serial-1",
           "osv": "14", "imi": "imei-1", "iso": "PlayStore" },
  "dfrgprt": "fingerprint-123",
  "fbrid": "firebase-token-1",
  "lag": "en-US"
}
```

**Strategy** (`intercept(AuthRequest)` → `buildInit`):
1. Lazily generate the RGK (`RgkCryptoCodec.generateRgk(128)`) and a sticky `rid`
   (UUID); use the server public key captured at Step 0 + `pkr` (the fingerprint).
2. base64‑encode the inner fields the server models as `byte[]` — `fbrid` and every
   `dad.*` — leaving `dfrgprt` (string) and `lag` (enum) as‑is.
3. Encrypt that JSON under the RGK → `ed`; wrap the RGK → `rgke`.

**Wire request (`InitGeneralRequest`):**
```json
{
  "rid":  "b64('…uuid…')",
  "v":    "b64(int32: 100005000)",
  "pkr":  "b64('demo-pkr')",
  "rgke": "b64( b64( RSA-wrap(rgk) ) )",
  "ed":   "b64( b64( AES-RGK( {dad:{dn:'b64(Pixel 7)',…}, dfrgprt:'fingerprint-123', fbrid:'b64(firebase-token-1)', lag:'en-US'} ) ) )"
}
```

**Wire response (`GeneralResponse`):**
```json
{ "reid": "…uuid…", "ecd": "b64( AES-RGK( {\"deviceSn\":\"b64(DEMO-DEVICE-1)\"} ) )" }
```

**Strategy** (`intercept(AuthResponse)`): `RgkCryptoCodec.parseEcdField(ecd, rgk)`
decrypts `ecd`, the response body is replaced with the cleartext, and `deviceSn` is
stored in the `OnboardingKeyStore`.

**Decrypted response the scenario sees:**
```json
{ "deviceSn": "b64(DEMO-DEVICE-1)" }
```
```gherkin
Then status 200
And match response.deviceSn == '#string'
```

### Step 2 — `PUT /api/v1/init/credentials`

**Feature writes:** `{ "ussLg": "user@example.com", "urrPsa": "p@ssw0rd" }`

**Strategy** (`buildRegistration`): base64‑encode `ussLg` and `urrPsa` (both `byte[]`
server‑side), encrypt → `ed`, attach the `dsn` from Step 1.

**Wire request (`RegistrationGeneralRequest`):**
```json
{
  "rid": "b64('…uuid…')",
  "v":   "b64(int32: 100005000)",
  "dsn": "b64( deviceSn-token-from-step-1 )",
  "ed":  "b64( b64( AES-RGK( {ussLg:'b64(user@example.com)', urrPsa:'b64(p@ssw0rd)'} ) ) )"
}
```
**Wire response:** `{ "reid": "…", "ecd": "b64(AES-RGK({}))" }` → **decrypted:** `{}` → `status 200`.

### Step 3 — `PUT /api/v1/init/otp/confirm-otp`

**Feature writes:** `{ "otp": "000000", "reLLo7eh": "user@example.com", "timezone": "Europe/Kyiv" }`

**Strategy:** if `config.otp("…")`/`otpSupplier(...)` is set, it **overrides** the
`otp` field with the configured value (here `000000`). All fields are strings — no
base64 — then encrypt → `ed` (+ `rid` + `v` + `dsn`).

**Wire response:** `ecd` of `{}` → **decrypted:** `{}` → `status 200`.

### Step 4 — `PUT /api/v1/init/access-code/register` (master keys issued)

**Feature writes:** `{ "acd": "9999", "otp": "VERIFY", "atp": "CODE" }`

**Strategy:** strings/enums, encrypt → `ed` (+ `rid` + `v` + `dsn`).

**Wire response** — the master keys are delivered **wrapped under the RGK and
hex-encoded** (`hex( AES/ECB/NoPadding(RGK, masterRaw) )`), exactly as the real
backend does, so only this device can recover them:
```json
{ "reid": "…", "ecd": "b64( AES-RGK( {\"mttk\":\"<hex…>\",\"mtmk\":\"<hex…>\"} ) )" }
```
**Strategy:** decrypts `ecd`, then `OnboardingKeyStore.captureMasterKeys(mtmk, mttk)`
(still wrapped/hex) → status `ONBOARDED`. The keys are **unwrapped** lazily by the
session layer (§5), not here.

**Decrypted response the scenario sees:**
```json
{ "mttk": "<hex…>", "mtmk": "<hex…>" }
```
```gherkin
Then status 200
And match response.mttk == '#string'
And match response.mtmk == '#string'
```

---

## 4. Where `mTMK` / `mTTK` are kept (for later flows)

The master keys are **not** returned to the test author — they are retained in the
strategy's per‑scenario `OnboardingKeyStore`, ready for follow‑up (transaction) flows
that derive session keys from them.

```java
// after onboarding, a later flow (or an after-hook) reaches the captured keys:
OnboardingKeyStore.Onboarded keys =
        strategy.keyStore(scenarioId).requireOnboarded();

keys.mtmk();      // master traffic MAC key
keys.mttk();      // master traffic transport key
keys.deviceSn();  // server-issued device serial token
keys.rid();       // sticky request id
```

- **Scope:** one `OnboardingKeyStore` per `scenarioId()` (a `ConcurrentHashMap` inside
  the strategy) — parallel scenarios are fully isolated.
- **Lifetime:** in memory from the moment Step 4 succeeds until `strategy.resetKeys(scenarioId)`
  (simulate a wiped device) or scenario end. No time-based expiry.
- **`requireOnboarded()`** throws `OnboardingException.NotOnboarded` if called before
  Step 4 completed — a follow-up flow fails loudly rather than running unauthenticated.

This is the seam between onboarding and the next layer: `SttkSessionStrategy` reads
`requireOnboarded()` and derives its session keys (`STTK`/`STMK`) from `mTMK`/`mTTK`
— which is exactly what Step 5 below does.

---

## 5. Step 5 — `POST /api/v1/devices/language` (the STTK session layer)

Onboarding is only the door. The fifth step is a **working-flow** request, protected
not by the RGK but by a **per-request session key** derived from the master keys.
Because `OnboardingSessionFlow` routes by URL, this call goes to `SttkSessionStrategy`
automatically — the feature author writes nothing special:

```gherkin
Given path '/api/v1/devices/language'
And request { language: 'en' }
When method post
Then status 200
```

### Key derivation (`SttkCryptoCodec`)

The master keys were captured **wrapped under the RGK and hex-encoded** (Step 4). On
the first session request the strategy unwraps them once per scenario, then derives a
**fresh per-request** key pair:

```
mttkRaw  = AES/ECB/NoPadding-decrypt(RGK, hexDecode(mttk))      # unwrap, once per scenario
mtmkRaw  = AES/ECB/NoPadding-decrypt(RGK, hexDecode(mtmk))
sessionId = hex(rid)                                            # 16 bytes from a fresh request UUID
STTK = HmacSHA256(mttkRaw, sessionId)                           # 32 bytes → AES-256 encryption key
STMK = HmacSHA256(mtmkRaw, sessionId)                           # session MAC key
```

`rid` is regenerated for every request, so `STTK`/`STMK` are one-time per call.

### Wire request (`intercept(AuthRequest)`)

The example uses **full encryption** (`new OnboardingSessionFlow(config, false)`):

1. Encrypt `{ "language": "en" }` under `STTK` (`AES/CBC/PKCS5Padding`, zero IV) → `ed`.
2. MAC the ciphertext: `mccd = b64( HmacSHA256(STMK, ed-ciphertext)[0..15] )`.

```json
{
  "rid":  "b64('…uuid…')",
  "v":    "b64(int32: 100005000)",
  "dsn":  "b64( deviceSn-token )",
  "ed":   "b64( b64( AES-STTK( {\"language\":\"en\"} ) ) )",
  "mccd": "b64( b64-mac )"
}
```

### Server side (`FakeCryptoBackend.language`)

The fake re-derives the same `STTK`/`STMK` from the master keys it issued + `rid`,
**verifies `mccd`**, decrypts `ed`, then replies with an encrypted, MAC'd envelope:

```json
{ "reid": "…uuid…", "ecd": "b64( AES-STTK( {} ) )", "mcc": "b64-mac" }
```

### Wire response (`intercept(AuthResponse)`)

The strategy verifies `mcc` with `STMK`, decrypts `ecd` with `STTK`, and hands the
scenario the plaintext — so `Then status 200` (and any `match response.X`) works on
cleartext. A MAC mismatch throws and fails the scenario loudly.

> **Two modes.** The example runs full encryption. The single-arg constructor
> `new OnboardingSessionFlow(config)` selects **skip-encryption** (`se=true`): `ed`
> is `b64(plaintext)` and the server skips the MAC — the path a test-build backend
> uses. Same feature, same code, no other change.

---

## 6. Safety rails

- **Step order** is enforced from the route table; a step whose prerequisites are
  missing fails with `OnboardingException.OutOfOrder` *before* anything is sent.
- **Unknown URLs** (anything outside the onboarding endpoints) fail with
  `OnboardingException.OutOfScope`.
- **STANDARD flavor** (4 steps): the alternative to the `HANDSHAKE` flavor this example
  uses. It drops Step 0 and instead configures the server public key + key ref into the
  strategy up front — `OnboardingFlavor.STANDARD` with `builtInServerKey(...)` and
  `builtInPkr(...)`; the strategy then wraps the RGK with that built-in key at Step 1.
  Everything from Step 1 on is identical.

---

## 7. Run it

```bash
# from the repo root, once:
mvn -q -DskipTests install
# then:
cd examples
mvn -q test -Dtest=OnboardingExample
```

No network, no Docker — the in-process `FakeCryptoBackend` performs the real
server-side crypto for both layers (RGK: RSA-unwrap, AES-decrypt/encrypt; STTK:
re-derive the session keys, verify the request MAC, decrypt, encrypt + MAC the
response), so the whole journey — onboard → session keys → language — runs
end-to-end locally. To target a real backend, drop `FakeCryptoBackend` and configure
the flow with the real base URL, credentials, server public key (or `HANDSHAKE`
flavor), and a valid app version.
