# Raised questions — TMS onboarding (karate-authflow)

Findings from implementing `TmsOnboardingStrategy` and verifying it against the
`softpos-core` source and a live STG sandbox. Cross-checked against the handover
`onboarding-crypto-keys.md`. None block onboarding — all are resolved or noted for
doc accuracy.

## Resolved against the source / live server

1. **Step 0 `dfrgprt` is base64, not plain.** `InitialKeyRequest.dfrgprt` is a
   `byte[]` (`getDeviceFingerprint()` = `new String(dfrgprt)`), so the wire value
   must be `base64(UTF-8(fingerprint))`; the server stores `refCode = fingerprint`.
   At Step 1 `pkr` must equal that plain fingerprint (`InitEncryptedRequestProcessor`
   does `new String(request.getPkr())`). The strategy now base64-encodes the Step 0
   `dfrgprt` and keeps `pkr` plain. (Handover §6 Step 0 showed base64; §5.6 generic
   wording was ambiguous.)

2. **`dsn` wire encoding (§5.6 wording).** The doc calls `dsn` "single base64, inner =
   plain string". In fact the inner `deviceSn` token returned at Step 1 is itself
   base64 of the SN bytes; the strategy treats `deviceSn` as an opaque token and puts
   its UTF-8 into the `dsn` byte[] (Jackson adds one base64). Behaviour is unchanged;
   only the wording is imprecise.

3. **`versionCode` must exist in the `Version` table.** An unregistered version →
   `HTTP 500 errorCode 3397 "Версія не існує"` at Step 1. On the STG sandbox a valid
   value is **100005000** ("1.5-0-STG"). Looked up by `rhssh` hash if present, else by
   the version string (`GeneralRequest.getVersionStringValue` = `ByteBuffer.getInt`).

4. **MAC (`mcc`) is absent on onboarding.** Confirmed: `GeneralResponse.mcc` is
   `@JsonInclude(NON_NULL)` and `MacCodeService.calculateResponseMac` returns null for
   non-STTK. The strategy verifies `mcc` only if present (never on RGK onboarding).

5. **Success `error` block lives inside the decrypted `ecd`.** `EncryptedResponseEncoder`
   appends a success-shape `error` before encrypting, so the decrypted payload carries
   an extra `error` object. The strategy ignores it; scenario assertions on real fields
   still pass.

6. **OTP is random + out-of-band.** `RegistrationDataService.generateOtp` stores a
   random OTP on `registration_data.otp` and `FirebaseService.sendOtpPush` delivers it;
   `ManualRegistrationService.verifyOtp` is a plain DB compare. For automated tests this
   needs a server-side fixed OTP — provided by the `app.test-merchant` feature
   (`fixed-otp: 123456`, `skip-firebase: true`) on the `dev`-style profile + the
   `V1__test_merchant.sql` seed. Login `test-merchant-01` / `Test1234!` / OTP `123456`.

## Notes / deviations

- **Config holds crypto/flavor only, not credentials.** Unlike handover §7, business
  values (credentials, OTP, access code, device info) are written by the `.feature`
  payloads; `TmsOnboardingConfig` carries flavor, version, built-in TMS key + `pkr`
  (standard), RGK bits, and an optional `otpSupplier`. This matches the §12 cleartext
  features being self-contained.

- **RGK length** defaults to AES-128 (`rgkBits`, configurable). Live STG accepted 128.

- **`registration_data.status`** in the test seed is `ACTIVE`; `verifyCredentials`
  does not check status (only login lookup + bcrypt), so this is fine for onboarding.

## Open

- Whether any onboarding 2xx ever carries a *non-success* `error` block that must be
  surfaced to the scenario (not observed so far).
