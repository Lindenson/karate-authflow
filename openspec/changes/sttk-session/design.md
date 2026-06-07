## Context

Verified against `softpos-core` + decompiled `SoftHsmCryptoService` (LMK values are fixed constants, so all `*UnderLmk` wrapping is reproducible). The onboarding strategy already captures, per scenario, the RGK and the Step-4 `mTTK`/`mTMK` (delivered hex-encoded, wrapped under the RGK) and `deviceSn` in `OnboardingKeyStore`.

### STTK wire facts (code-grounded)

- `sessionId = Hex.decode(rid.replace("-", ""))` (16 bytes from the request UUID).
- Master keys arrive **wrapped under the onboarding RGK**: server sends `Hex( AES/ECB/NoPadding(rgk, mttkRaw) )`. Client unwraps: `mttkRaw = AES/ECB/NoPadding-decrypt(rgk, Hex.decode(mttkHex))` (32 bytes); same for `mtmkRaw`.
- `STTK = HmacSHA256(key = mttkRaw, msg = sessionId)` (32 bytes → AES-256); `STMK = HmacSHA256(key = mtmkRaw, msg = sessionId)`.
- `ed = matryoshka( AES/CBC/PKCS5Padding(IV = 16 zero bytes, key = STTK, plaintextJson) )` — double base64, same as RGK onboarding.
- MAC = `HmacSHA256(key = STMK, msg = ciphertextBytes)` truncated to 16 bytes, base64. `ciphertextBytes = Base64.decode(ed-inner)` for the request; `Base64.decode(ecd)` for the response.
- Request envelope = `FullGeneralRequest` (`rid, v, dsn, ed, mccd`); `mccd` (byte[] → single base64 of the mac base64 string) carries the request MAC over the `ed` ciphertext. Response = `GeneralResponse{reid, ecd, mcc}`; verify `mcc`.
- First target endpoint: `POST /api/v1/devices/language`, inner payload `{ "language": "en-US" }` (enum via locale serializer), response empty `{}`.

## Goals / Non-Goals

**Goals:** transparent STTK session layer (derive, encrypt, MAC, decrypt, verify) driven from cleartext features; reuse the onboarding result; pure-JCE runtime; parity-proven against the real crypto lib.

**Non-Goals:** PIN/SPTK/DUKPT, ISO8583 transactions, session-rotation policy.

## Decisions

- **Pure-JCE, no vendor runtime dep.** The LMK constants + algorithms are reimplemented in the codec; `transenix-crypto` is used **only in test scope** as a parity oracle (`assert ours == SoftHsmCryptoService.deriveSttk/deriveStmk/calculate128bitHmacSha256WithStmk`). Keeps the public artifact clean and publishable. *Alternative:* depend on the vendor jar at runtime — rejected (private, unpublishable).
- **Reuse `OnboardingKeyStore` as the bridge.** `SttkSessionStrategy` reads `requireOnboarded()` (mTTK/mTMK/RGK/deviceSn) for the scenario. The master-key unwrap (under RGK) → `mttkRaw`/`mtmkRaw` is done once and cached per scenario; STTK/STMK are derived **per request** from that request's `rid`.
- **Per-request session keys, stashed for the response.** `intercept(AuthRequest)` generates `rid`, derives STTK/STMK, encrypts, MACs, and stashes `{STTK, STMK}` keyed by `scenarioId` so `intercept(AuthResponse)` can verify `mcc` and decrypt `ecd`. (Sequential within a scenario.)
- **Composite registration for onboard-then-transact.** A small dispatcher routes onboarding endpoints to `EncryptedOnboardingStrategy` and STTK endpoints to `SttkSessionStrategy`, both sharing the same per-scenario `OnboardingKeyStore`, so one feature can do the full journey. STTK-only usage (keys supplied directly) is also supported via a constructor.
- **`mcc` verification on responses; fail loud.** A mismatch throws — the scenario fails rather than trusting tampered data.

## Risks / Trade-offs

- **Parity with the soft HSM** is the #1 risk → the test-scope oracle asserts exact byte equality of STTK/STMK/MAC against `SoftHsmCryptoService`, and a live `devices/language` run confirms against the real server.
- **AES-256 (STTK is 32 bytes)** requires the JDK unlimited crypto policy — default since JDK 9, fine on 17+.
- **`mttkRaw` form assumption** (wrapped under RGK) is code-verified; the live run is the final proof, with the same `-Dbackend.*` knobs to adjust if needed.
- **Master-key unwrap needs the onboarding RGK** retained in `OnboardingKeyStore` — already kept.
