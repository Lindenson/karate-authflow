## 1. Crypto codec — STTK primitives (riskiest first)

- [ ] 1.1 Add to `RgkCryptoCodec` (or a sibling `SttkCryptoCodec`): `unwrapMasterKeyUnderRgk(hexKey, rgk)`, `sessionIdFromRid(rid)`, `deriveSttk(mttkRaw, sessionId)`, `deriveStmk(mtmkRaw, sessionId)` (HmacSHA256), `encryptUnderSttk`/`decryptUnderSttk` (AES/CBC/PKCS5, zero IV), `mac128(stmk, data)` (HmacSHA256→16 bytes, base64)
- [ ] 1.2 Add the reference crypto library in **test scope**; parity test asserting our STTK/STMK/MAC == the reference implementation’s session-key derivation + MAC (account for the LMK wrap on the reference side)

## 2. Session strategy

- [ ] 2.1 Add `SttkSessionStrategy` (PreRequest + PostResponse) in `…authflow.session`: route STTK endpoints, build `FullGeneralRequest` (`rid,v,dsn,ed,mccd`), per-`rid` derive + encrypt + MAC; stash STTK/STMK per scenario for the response
- [ ] 2.2 Response: verify `mcc`, decrypt `ecd`, replace body
- [ ] 2.3 Consume `OnboardingKeyStore.requireOnboarded()` (mTTK/mTMK/RGK/deviceSn); unwrap master keys once, cache per scenario
- [ ] 2.4 Keep `com.intuit.karate.*` out of the package (use the spi seam)

## 3. Composite onboard→transact

- [ ] 3.1 Add a dispatcher that routes onboarding endpoints to `EncryptedOnboardingStrategy` and STTK endpoints to `SttkSessionStrategy`, sharing one per-scenario `OnboardingKeyStore`; register both pre+post via `KarateAuth`

## 4. FakeCryptoBackend — language endpoint

- [ ] 4.1 Extend `FakeCryptoBackend`: `POST /api/v1/devices/language` — derive STTK/STMK from the request `rid` + the issued master keys, verify request `mccd`, decrypt `ed`, respond encrypted `{}` + `mcc`

## 5. Tests

- [ ] 5.1 Parity test (task 1.2) green
- [ ] 5.2 Hermetic integration: journey feature (onboard → devices/language) via the composite against `FakeCryptoBackend`, zero failures
- [ ] 5.3 MAC-mismatch rejection test
- [ ] 5.4 Live runner (`@Dbackend.base`) for `devices/language` after onboarding

## 6. Docs & verification

- [ ] 6.1 README: STTK session section (derive from onboarding keys, MAC, run)
- [ ] 6.2 `mvn verify` green; import isolation; `openspec validate sttk-session`
