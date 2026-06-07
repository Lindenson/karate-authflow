# karate-authflow

[![CI](https://github.com/Lindenson/karate-authflow/actions/workflows/ci.yml/badge.svg)](https://github.com/Lindenson/karate-authflow/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Karate](https://img.shields.io/badge/Karate-1.5.2-brightgreen.svg)](https://github.com/karatelabs/karate)
[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://adoptium.net/)

A transparent **authentication & pre-request interceptor layer** for the
[Karate](https://github.com/karatelabs/karate) test framework.

Test authors write ordinary Karate feature files. `karate-authflow` sits in front
of every outgoing HTTP request and applies authentication for them — from a simple
header to full request-body encryption — without changing how tests are written.

> **Status:** early development. HTTP **Basic**, **Ory Kratos session**, and
> **encrypted device onboarding** work today and are verified against live
> endpoints. APIs may change before `1.0.0`.

## Why

Karate is excellent at API testing, but real systems guard their APIs with auth
schemes ranging from trivial to cryptographic. Wiring that into every scenario
clutters tests and couples them to auth mechanics. `karate-authflow` moves all of
it behind one interceptor so tests stay about *behavior*, not credentials.

## Quick start

**1. Add the dependency** (test scope; you already bring your own Karate):

```xml
<!-- Not yet published to Maven Central; coordinates shown for when it is. -->
<dependency>
    <groupId>io.github.lindenson</groupId>
    <artifactId>karate-authflow</artifactId>
    <version>0.1.0</version>
    <scope>test</scope>
</dependency>
```

**2. Write a normal feature — no auth steps:**

```gherkin
Feature: orders

  Scenario: list orders
    Given url 'https://api.example.com/orders'
    When method get
    Then status 200
```

**3. Register a strategy on your runner — one line:**

```java
import com.intuit.karate.Results;
import com.intuit.karate.Runner;
import io.github.lindenson.karate.authflow.BasicAuthStrategy;
import io.github.lindenson.karate.authflow.spi.KarateAuth;

class OrdersTest {

    @org.junit.jupiter.api.Test
    void runOrders() {
        Results results = KarateAuth
                .register(Runner.path("classpath:orders.feature"),
                          new BasicAuthStrategy("user", "pass"))
                .parallel(1);

        org.junit.jupiter.api.Assertions.assertEquals(0, results.getFailCount(), results.getErrorMessages());
    }
}
```

Every request in every scenario now carries `Authorization: Basic …` — and the
feature file never mentions it.

### Session auth with Ory Kratos

For systems behind [Ory Kratos](https://www.ory.sh/kratos/), `KratosSessionStrategy`
performs the Kratos **browser login flow** once (initialize flow → submit
identifier/password with the CSRF token), captures the `ory_kratos_session`
cookie, and injects it on every subsequent request:

```java
KarateAuth.register(
        Runner.path("classpath:features"),
        new KratosSessionStrategy("https://auth.example.com", "alice@example.com", "s3cret"))
    .parallel(5);
```

Login is lazy (on the first request), happens exactly once, and is thread-safe
under parallel execution. Automatic re-login on `401` is planned.

## How it works

`karate-authflow` registers a Karate `RuntimeHook` that, before each HTTP call,
hands the outgoing request to a pluggable `AuthStrategy` which may mutate its
headers and/or body.

```
KarateAuth.register(runner, strategy)     ← one line; feature files are untouched
        │
        ▼
  RuntimeHook.beforeHttpCall(request)  ──►  AuthStrategy.intercept(AuthRequest)
                                                 (headers / body, before send)
```

All Karate-version-specific wiring is confined to a single `KarateBinding` seam
(package `…authflow.spi`), so support for Karate 2.x can be added without touching
strategy code. Strategies implement the Karate-agnostic `AuthStrategy` contract.

### Writing your own strategy

```java
public final class ApiKeyStrategy implements AuthStrategy {
    private final String key;
    public ApiKeyStrategy(String key) { this.key = key; }

    @Override public String name() { return "api-key"; }

    @Override public void intercept(AuthRequest request) {
        request.putHeader("X-Api-Key", key);          // headers...
        // request.body(encrypt(request.body()));      // ...or rewrite the body
    }
}
```

Strategies should be stateless or thread-safe — one instance is shared across
scenarios under `Runner.parallel(n)`.

### Encrypted onboarding & session crypto (STTK)

The crown of the project: drive an **encrypted device-onboarding** handshake (RGK
envelope — RSA + AES, base64 layering) and the follow-up **per-request session
layer** (STTK/STMK key derivation, AES body encryption + MAC, response
decrypt/verify) from **cleartext** features. One composite `OnboardingSessionFlow`
covers the whole journey — onboard a device, then call working endpoints like
`POST /api/v1/devices/language` — with all crypto handled transparently in both
directions.

📖 **Full algorithms, wire format, configuration and the two operating modes are
documented in [onboarding.md](onboarding.md).** A runnable, zero-setup demo of the
entire journey is in [`examples/`](examples) (`OnboardingExample`).

## Authentication scenarios

| Scenario | What it does | Status |
|---|---|---|
| **Basic** | Inject an `Authorization: Basic` header on every request | ✅ available |
| **Session (Ory Kratos)** | Log in once via the Kratos browser flow, reuse the `ory_kratos_session` cookie on every request | ✅ available |
| **Crypto onboarding (crypto backend)** 🔑 | Drive the encrypted device-onboarding flow (RGK envelope, RSA/AES, master-key capture) from cleartext features | ✅ available |
| **Session crypto (STTK)** 🔑 | Per-request session-key derivation (HMAC), AES body encryption + MAC, and response decrypt/verify on working-flow endpoints | ✅ available |
| **Bearer / token** | Inject a bearer token | planned |
| **Session refresh** | Re-login automatically on `401` | planned |
| **Crypto (generic)** | Pluggable session-key derivation + selective JSON-field encryption / body signing | planned |

The crypto layer is the project's reason to exist — Karate has no native support
for request-body encryption or custom key derivation.

## Requirements

- Java 17+
- Karate 1.5.x (declared `provided` — bring your own Karate)

## Building & testing

```bash
mvn verify                 # compile (Java 17), unit tests, JaCoCo report
```

The default build is offline and hermetic. Network-dependent ("live") tests are
tagged `live` and excluded by default. Run them on demand:

```bash
mvn test -Dgroups=live -Dauthflow.test.excludedGroups=
```

The bundled live test proves transparent Basic-auth injection against
`postman-echo.com/basic-auth`.

## License

Licensed under the [Apache License 2.0](LICENSE).
