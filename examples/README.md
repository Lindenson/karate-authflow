# karate-authflow examples

Two runnable, self-contained Karate examples showing transparent auth with
`karate-authflow`. The feature files contain **no authentication steps** — the
plugin injects credentials for them.

| Example | Strategy | Backing service | Needs |
|---|---|---|---|
| [`BasicAuthExample`](src/test/java/io/github/lindenson/karate/authflow/examples/BasicAuthExample.java) | `BasicAuthStrategy` | `postman-echo.com/basic-auth` | internet |
| [`KratosSessionExample`](src/test/java/io/github/lindenson/karate/authflow/examples/KratosSessionExample.java) | `KratosSessionStrategy` | real Ory Kratos via Docker | Docker |

## Prerequisites

- JDK 17+
- Maven 3.9+
- Docker (for the Kratos example only)

## 0. Install the library locally

`karate-authflow` isn't on Maven Central yet, so install it into your local
Maven repository first (run from the **repository root**, one level up):

```bash
mvn -q -DskipTests install
```

## 1. Basic auth example (internet only)

```bash
cd examples
mvn -q test -Dtest=BasicAuthExample
```

The feature calls `https://postman-echo.com/basic-auth` with no auth steps;
`BasicAuthStrategy("postman", "password")` injects the `Authorization` header and
the call returns `{"authenticated": true}`.

## 2. Ory Kratos session example (Docker)

Start a real Ory Kratos. The bundled `docker-compose.yml` boots Kratos with an
in-memory database and seeds one demo identity (`demo@example.com` /
`KarateAuthflowDemo123`):

```bash
cd examples
docker compose up -d          # starts Kratos (ports 4433/4434) and seeds the demo user
docker compose logs seed      # should print "SEED OK (201)"
```

Then run the example:

```bash
mvn -q test -Dtest=KratosSessionExample
```

`KratosSessionStrategy` runs the Kratos browser login flow once (initialize flow →
submit identifier/password with the CSRF token → capture `ory_kratos_session`),
then injects that cookie. The feature's call to `GET /sessions/whoami` returns an
active session for `demo@example.com`.

> **Use `127.0.0.1`, not `localhost`.** Kratos builds the login `action` URL from
> its configured `base_url` (`http://127.0.0.1:4433/`); mixing hostnames makes the
> anti-CSRF cookie mismatch and the login returns `403`.

Tear down when done:

```bash
docker compose down
```

## Run everything

With internet and Kratos up:

```bash
mvn -q test
```
