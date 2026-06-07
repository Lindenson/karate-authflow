# Notes — encrypted onboarding wire format

Implementation notes and gotchas for `EncryptedOnboardingStrategy`, verified end-to-end
against a live crypto-backend sandbox (both flavors) and hermetically against
`FakeCryptoBackend`. None block onboarding; recorded so the wire encoding stays correct.

## Wire encoding

- **base64 "matryoshka" is asymmetric.** Request `byte[]` fields that carry crypto
  (`ed`, `rgke`) are **double** base64 on the wire — an inner base64 (this codec) plus
  the outer base64 the JSON layer adds to a `byte[]`. The response `ecd` is **single**
  base64 of the ciphertext. Getting this asymmetry wrong looks correct but fails to
  decrypt — it has a dedicated round-trip test (`RgkCryptoCodecTest`).

- **Envelope `byte[]` string-fields carry UTF-8 of their value; the JSON layer adds one
  base64.** `rid` (plain id), `v` (`ByteBuffer.putInt(versionCode)`, 4 bytes), `pkr`
  (key reference), `dsn` (the opaque device-serial token from Step 1). Only `ed`/`rgke`
  are double base64.

- **Step 0 `dfrgprt` is base64.** The handshake request's fingerprint field is a `byte[]`
  server-side, so the wire value is `base64(UTF-8(fingerprint))`; the server stores the
  key under `refCode = fingerprint`, and Step 1's `pkr` must equal that plain fingerprint.

- **Inner cleartext `byte[]` fields are base64 of the value.** The strategy base64-encodes
  exactly the inner fields the server models as `byte[]` (Step 1 device-info + firebase id;
  Step 2 login + password); other inner fields are plain strings / enums.

- **No MAC on the RGK onboarding flow.** The response MAC field is omitted (it applies only
  to the later session-key flow). The strategy verifies a MAC only if one is present.

- **A success-shape `error` block is embedded inside the decrypted response.** The strategy
  ignores it; scenario assertions on the real fields still pass.

## Backend prerequisites for a green run

- **`versionCode` must exist in the backend's version registry**, otherwise Step 1 fails
  with a "version does not exist" error. Configure `appVersion(...)` (or a `versionHash`)
  to a registered value.

- **OTP is generated server-side and delivered out-of-band** (push), then compared against
  the stored value. For automated tests the backend must expose a deterministic OTP for a
  test account (a fixed-OTP / test-merchant feature); pass it with `config.otp("…")`, or
  resolve a real one via `otpSupplier(...)`.

- **The test account/credentials** must be seeded on the backend (status active). Business
  values (credentials, OTP, access code, device info) are written by the `.feature`
  payloads, not by the strategy config.

## Notes / deviations

- **Config holds crypto/flavor only, not credentials.** `EncryptedOnboardingConfig` carries
  flavor, version, the built-in server key + key reference (STANDARD flavor), RGK size, and
  an optional `otpSupplier`. The `.feature` files stay self-contained and cleartext.

- **RGK length** defaults to AES-128 (`rgkBits`, configurable).
