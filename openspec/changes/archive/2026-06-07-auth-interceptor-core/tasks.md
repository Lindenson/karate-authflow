## 1. Core contract

- [x] 1.1 Add `AuthStrategy` in `io.github.lindenson.karate.authflow` extending `PreRequestInterceptor` with `String name()`
- [x] 1.2 Confirm `AuthStrategy` and its package reference no `com.intuit.karate.*` types

## 2. Basic strategy

- [x] 2.1 Add `BasicAuthStrategy` (final, stateless) computing `Authorization: Basic base64(user:pass)` in `intercept`
- [x] 2.2 Validate constructor args (non-null user/pass)

## 3. Registration entry point

- [x] 3.1 Add a generic registration helper in `…authflow.spi` (`static <T extends Runner.Builder<T>> T register(T, PreRequestInterceptor)`) returning the builder, delegating to `KarateV1Binding`
- [x] 3.2 Keep all `com.intuit.karate.*` references inside `spi`

## 4. Unit tests

- [x] 4.1 Test `BasicAuthStrategy` sets the exact RFC 7617 header and overwrites a pre-existing one (via the seam + a fabricated `HttpRequest`)
- [x] 4.2 Test `name()` and null-arg validation

## 5. Live integration test

- [x] 5.1 Add `src/test/resources/.../basic-auth-live.feature` (tagged `@live`, no auth steps) hitting a public Basic-auth endpoint
- [x] 5.2 Add a JUnit5 test (`@Tag("live")`) that registers `BasicAuthStrategy` on `Runner.path(...)` and asserts `getFailCount() == 0`
- [x] 5.3 Wire surefire to exclude the `live` group by default via overridable `${authflow.test.excludedGroups}` (default `live`)

## 6. Verification

- [x] 6.1 `mvn verify` passes offline (live test excluded), coverage report still generated
- [x] 6.2 Run the live test on demand (`-Dauthflow.test.excludedGroups=`) and confirm it authenticates (zero failures)
- [x] 6.3 `openspec validate auth-interceptor-core` is valid
