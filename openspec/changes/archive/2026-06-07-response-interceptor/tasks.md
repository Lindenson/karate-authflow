## 1. Response view + interceptor contract

- [x] 1.1 Add `AuthResponse` in `…spi` (status read/replace, `header(name)`, `body()`/`body(byte[])`/`body(String)`/`bodyAsString()`, `scenarioId()`)
- [x] 1.2 Add `PostResponseInterceptor` (`void intercept(AuthResponse)`) in `…spi`
- [x] 1.3 Add `scenarioId()` to `AuthRequest`

## 2. Seam wiring (v1)

- [x] 2.1 `KarateBinding`: add `createHook(PreRequestInterceptor, PostResponseInterceptor)`; keep single-arg as a default delegating with `null` post
- [x] 2.2 `KarateV1Binding`: pass `ScenarioRuntime` into `V1AuthRequest` for `scenarioId()` (= `sr.scenario.getUniqueId()`); add `V1AuthResponse` wrapping `com.intuit.karate.http.Response`; wire `afterHttpCall` to invoke `post` when non-null
- [x] 2.3 `KarateAuth`: add `register(builder, pre, post)` overload
- [x] 2.4 Keep all `com.intuit.karate.*` references inside `…spi`

## 3. Tests

- [x] 3.1 Permanent test: a post-response interceptor replaces the body; a Karate feature asserts the scenario sees the replacement (locks in the spike)
- [x] 3.2 Test `scenarioId()` is identical within a scenario and differs across two scenarios
- [x] 3.3 Regression: existing `BasicAuthStrategy` registration (request-only) still works (existing KarateV1BindingTest / strategy tests stay green)

## 4. Verification

- [x] 4.1 `mvn verify` green (all prior tests + new), JaCoCo generated
- [x] 4.2 Import isolation: no `com.intuit.karate.*` outside `…spi`
- [x] 4.3 `openspec validate response-interceptor` valid
