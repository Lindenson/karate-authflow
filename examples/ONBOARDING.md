# Encrypted device onboarding — how the example works

This walks through [`OnboardingExample`](src/test/java/io/github/lindenson/karate/authflow/examples/OnboardingExample.java)
step by step: the exact JSON on the wire at each step, which classes and methods do
the work, and where the master keys end up for later flows.

Unlike the Basic or Kratos examples (one header / one cookie), this is a **stateful,
multi-step, encrypted** flow. The point of `karate-authflow` here is that the
`.feature` file stays **cleartext** — the strategy does all the crypto and envelope
work, in both directions.

---

## 1. The moving parts

| Class | Role |
|---|---|
| `EncryptedOnboardingStrategy` | The brain. Implements **both** `PreRequestInterceptor` (encrypt the request) and `PostResponseInterceptor` (decrypt the response). Routes each call to a step, enforces order, holds per-scenario state. |
| `EncryptedOnboardingConfig` | Immutable config: flavor, app version, built-in server public key + key ref (`STANDARD`), RGK size, and the fixed/`otpSupplier` OTP. |
| `RgkCryptoCodec` | Pure-JCE crypto: RGK generation (AES-128), RSA-wrap of the RGK, AES-CBC of payloads, and the base64 "matryoshka" helpers. |
| `OnboardingKeyStore` | Per-scenario state: `rid`, `rgk`, `deviceSn`, completed steps, and the captured `mTMK` / `mTTK`. |
| `OnboardingFlavor` | `STANDARD` (4 steps, built-in key) or `HANDSHAKE` (5 steps, Step 0 fetches the key). The example uses `STANDARD`. |
| `KarateAuth.register(builder, pre, post)` | Wires the strategy into Karate as both interceptors (one line). |
| `FakeCryptoBackend` | **Example only** — an in-process server doing the real server-side crypto so the example needs no network/Docker. |

How it plugs into Karate (the seam, in package `…authflow.spi`):

```
KarateAuth.register(runner, strategy, strategy)
        │
        ▼
KarateV1Binding  ──►  RuntimeHook.beforeHttpCall(req) ─► strategy.intercept(AuthRequest)   // encrypt
                 └─►  RuntimeHook.afterHttpCall(resp) ─► strategy.intercept(AuthResponse)  // decrypt
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

## 3. Step by step (STANDARD flavor, 4 steps)

> Notation: `b64(x)` = base64. The feature writes the **cleartext request**; the
> strategy emits the **wire request**; the server replies with the **wire response**;
> the strategy hands the scenario back the **decrypted response**.

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
   (UUID); pick the server public key + `pkr` (STANDARD → from config).
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
base64 — then encrypt → `ed` (+ `rid` + `dsn`).

**Wire response:** `ecd` of `{}` → **decrypted:** `{}` → `status 200`.

### Step 4 — `PUT /api/v1/init/access-code/register` (master keys issued)

**Feature writes:** `{ "acd": "9999", "otp": "VERIFY", "atp": "CODE" }`

**Strategy:** strings/enums, encrypt → `ed` (+ `rid` + `dsn`).

**Wire response:**
```json
{ "reid": "…", "ecd": "b64( AES-RGK( {\"mttk\":\"demo-master-traffic-key\",\"mtmk\":\"demo-master-mac-key\"} ) )" }
```
**Strategy:** decrypts, then `OnboardingKeyStore.captureMasterKeys(mtmk, mttk)` →
status `ONBOARDED`.

**Decrypted response the scenario sees:**
```json
{ "mttk": "demo-master-traffic-key", "mtmk": "demo-master-mac-key" }
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

This is the seam between onboarding and the next layer: a transaction strategy reads
`requireOnboarded()` and derives its session keys (`STTK`/`SPTK`) from `mTMK`/`mTTK`.

---

## 5. Safety rails

- **Step order** is enforced from the route table; a step whose prerequisites are
  missing fails with `OnboardingException.OutOfOrder` *before* anything is sent.
- **Unknown URLs** (anything outside the onboarding endpoints) fail with
  `OnboardingException.OutOfScope`.
- **HANDSHAKE flavor** (5 steps): prepend `POST /api/v1/init/initial_handshake_key`
  with `{ "dfrgprt": "<fingerprint>" }`; the strategy captures the returned server
  public key (`ihshky`) and uses it to wrap the RGK at Step 1 — everything else is
  identical. Select it with `OnboardingFlavor.HANDSHAKE` (no built-in key needed).

---

## 6. Run it

```bash
# from the repo root, once:
mvn -q -DskipTests install
# then:
cd examples
mvn -q test -Dtest=OnboardingExample
```

No network, no Docker — the in-process `FakeCryptoBackend` performs the real
server-side crypto (RSA-unwrap the RGK, AES-decrypt the payload, AES-encrypt the
response), so the whole flow runs end-to-end locally. To target a real backend,
drop `FakeCryptoBackend` and configure the strategy with the real base URL,
credentials, server public key (or `HANDSHAKE` flavor), and a valid app version.
