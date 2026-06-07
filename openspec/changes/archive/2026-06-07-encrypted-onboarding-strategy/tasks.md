## 1. Crypto codec (riskiest first)

- [x] 1.1 Add `RgkCryptoCodec` in `…authflow.onboarding.crypto`: `generateRgk(bits)`, `wrapRgk(rgk, serverPubX509Der)` (`RSA/ECB/PKCS1Padding`), `encryptUnderRgk`/`decryptUnderRgk` (`AES/CBC/PKCS5Padding`, IV=16 zero bytes), matryoshka helpers `buildEdField`/`buildRgkeField`/`parseEcdField`
- [x] 1.2 Round-trip unit test: `buildEdField` decoded the server way (`new String` → base64-decode → AES-decrypt) returns the original JSON; `wrapRgk` then RSA-unwrap returns the RGK; against a hand-made RSA key pair

## 2. Envelope codec + field schema

- [x] 2.1 Add envelope DTOs/builders (`InitGeneralRequest`, `RegistrationGeneralRequest`, `GeneralResponse` view) via Jackson, reproducing wire field names and the byte[] double-base64 / String single-base64 asymmetry; `os`/`se` omitted; `v` = `ByteBuffer.putInt`
- [x] 2.2 Add the per-step inner field-encode schema (Step 1: `fbrid`,`dad.dn|did|sen|osv|imi|iso`; Step 2: `ussLg`,`urrPsa`; Steps 3–4: none) and a transform that base64(UTF-8)-encodes those JSON fields from the feature's plain values
- [x] 2.3 Response parse: extract + decrypt `ecd`, tolerate the appended `error` block, verify `mcc` only if present

## 3. Key store + state

- [x] 3.1 Add `OnboardingKeyStore` (per scenario): `rid`, `rgk`, `deviceSn`, `mTMK`, `mTTK`, `EnumSet<OnboardStep>`, `status`, `onboardedAt`; `resetKeys()`, `requireOnboarded()`
- [x] 3.2 Per-scenario partition: `ConcurrentHashMap<scenarioId, OnboardingKeyStore>` inside the strategy

## 4. Strategy

- [x] 4.1 Add config (`EncryptedOnboardingConfig`): flavor, deviceFingerprint, appVersion+versionHash, builtInServerKey+builtInPkr (standard), userLogin/userPassword, accessCode, otpSupplier, rgkBits(=128)
- [x] 4.2 Add `OnboardStep` + `RequestKey` route table; `OutOfScopeOnboardingException`, `OnboardingOrderException`
- [x] 4.3 Add `EncryptedOnboardingStrategy implements PreRequestInterceptor, PostResponseInterceptor`: route → step, order check, Step 0 plain handshake capture, Step 1 RGK+rid+rgke+ed, Steps 2–4 dsn+ed, response decrypt + capture (deviceSn/mTMK/mTTK)
- [x] 4.4 Keep all `com.intuit.karate.*` out of this package (use the spi seam)

## 5. FakeCryptoBackend harness (server-side oracle)

- [x] 5.1 Add `FakeCryptoBackend` (JDK `HttpServer`): own RSA key pair (public = ihshky/built-in); Step 0 returns `{ihshky}`; Step 1 unwrap `rgke` → RGK, decrypt `ed`, return encrypted `{deviceSn}`; Steps 2/3 validate login/password/OTP → encrypted `{}`; Step 4 validate access code → encrypted `{mttk,mtmk}`
- [x] 5.2 Decode/encode in `FakeCryptoBackend` written the server way (independent of the strategy), plus one hand-computed fixture assertion

## 6. Tests

- [x] 6.1 Integration (standard, hermetic): run the §12.1 feature through the strategy + `FakeCryptoBackend`, assert `response.deviceSn`/`mttk`/`mtmk`, zero failures, keys in store
- [x] 6.2 Integration (handshake): prepend Step 0; assert handshake + full flow
- [x] 6.3 Per-scenario isolation under `parallel(n)`; out-of-order + out-of-scope failures
- [x] 6.4 Key store: capture, `requireOnboarded()`, `resetKeys()`

## 7. Docs & verification

- [x] 7.1 README section: configure flavor + credentials, plug an OTP supplier, reach `OnboardingKeyStore` for `mTMK`/`mTTK`
- [x] 7.2 `RAISED_QUESTIONS.md` (or doc section) capturing the §5.6 `dsn` wording and any other mismatch
- [x] 7.3 `mvn verify` green; import isolation; `openspec validate encrypted-onboarding-strategy`
