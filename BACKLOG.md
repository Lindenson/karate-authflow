# Backlog (deferred)

## Align `OnboardingExample` with the HANDSHAKE flavor

**Status:** deferred — revisit later.

The bundled/example onboarding currently demonstrates the `STANDARD` flavor (4 steps,
built-in server key), but the real deployment uses the `HANDSHAKE` flavor (5 steps,
Step 0 `/initial_handshake_key` fetches the server key). To make the example mirror
reality:

- Switch `examples/.../OnboardingExample` to `OnboardingFlavor.HANDSHAKE` (drop the
  built-in key; the in-process `FakeCryptoBackend` already serves the handshake endpoint).
- Prepend Step 0 to `examples/.../onboarding/onboarding.feature`.
- Update `examples/ONBOARDING.md` so the main walkthrough is the 5-step handshake flow
  (keep STANDARD as a short note).

Hermetic `FakeCryptoBackend` already supports both flavors, and the live HANDSHAKE flow
is verified via `OnboardingLiveTest`, so this is a documentation/parity change only.
