## 1. Dependency

- [x] 1.1 Add `com.fasterxml.jackson.core:jackson-databind` in `provided` scope with a `${jackson.version}` property (matching Karate's transitive 2.19.x)

## 2. Kratos client

- [x] 2.1 Add `KratosLoginException` (clear failure type) in `…authflow.session`
- [x] 2.2 Add `KratosClient` using `java.net.http.HttpClient` + `CookieManager`: `login(identifier, password)` → returns the `ory_kratos_session` value
- [x] 2.3 Step 1 — `GET /self-service/login/browser` (`Accept: application/json`); parse `ui.action` and the `csrf_token` node value with Jackson
- [x] 2.4 Step 2 — `POST` action URL with CSRF cookie + JSON body `{method:"password", identifier, password, csrf_token}`
- [x] 2.5 Step 3 — capture `ory_kratos_session` from `Set-Cookie`; throw `KratosLoginException` on non-success or missing cookie

## 3. Session strategy

- [x] 3.1 Add `KratosSessionStrategy implements AuthStrategy` (config: `kratosPublicUrl`, `identifier`, `password`, cookie name default `ory_kratos_session`)
- [x] 3.2 Lazy, thread-safe login (double-checked locking over a `volatile` cookie value)
- [x] 3.3 `intercept`: append `Cookie: <name>=<value>` to the request, preserving existing cookies
- [x] 3.4 `name()` returns `"kratos-session"`; validate constructor args non-null
- [x] 3.5 Keep the package free of `com.intuit.karate.*` imports

## 4. Fake Kratos test harness

- [x] 4.1 Add a JDK `HttpServer`-based `FakeKratos` test helper: `/self-service/login/browser` (returns flow JSON + sets `csrf_token` cookie), `/self-service/login` (validates csrf cookie+body + credentials → sets `ory_kratos_session`), and `/protected` (200 if valid session cookie, else 401)
- [x] 4.2 Bind it to an ephemeral localhost port; expose base URL; clean shutdown

## 5. Tests

- [x] 5.1 Unit-test `KratosClient` against `FakeKratos`: happy path returns a session value; bad credentials throw `KratosLoginException`
- [x] 5.2 Unit-test `KratosSessionStrategy`: single login across multiple intercepts (count logins on the fake), cookie appended, existing cookies preserved
- [x] 5.3 Concurrency test: many threads, exactly one login observed
- [x] 5.4 Integration test: auth-free Karate feature hitting `FakeKratos`/protected via `KarateAuth.register`, assert `getFailCount()==0` (hermetic, not tagged `live`)

## 6. Verification

- [x] 6.1 `mvn verify` passes offline including the Kratos integration test; JaCoCo report generated
- [x] 6.2 Import isolation check: no `com.intuit.karate.*` outside `…spi`
- [x] 6.3 `openspec validate session-strategy` is valid
- [x] 6.4 Update README: add Session (Kratos) usage example and mark the scenario available
