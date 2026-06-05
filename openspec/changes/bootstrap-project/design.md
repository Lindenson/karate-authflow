## Context

`karate-authflow` is greenfield. The foundation choices here become a permanent public contract (Maven coordinates, base package, Java bytecode level) and set the constraints all later auth work inherits. Stage-1 research (verified against the `io.karatelabs:karate-core:1.5.2` bytecode) established the v1 extension surface we build on:

- `com.intuit.karate.RuntimeHook` — `beforeHttpCall(HttpRequest, ScenarioRuntime)` / `afterHttpCall(...)`; registered via `Runner.builder().hook(...)` / `.hooks(...)` / `.hookFactory(...)`.
- `com.intuit.karate.http.HttpRequest` — mutable before send: `setBody(byte[])`, `getBody()`, `putHeader(...)`, `removeHeader(...)`, `setUrl(...)`.
- `com.intuit.karate.http.HttpClientFactory` — `HttpClient create(ScenarioEngine)` for full client replacement (not needed for body mutation).
- No `META-INF/services` auto-discovery for hooks → registration is explicit.

Karate v2 (`io.karatelabs:karate-junit6:2.0.4`, Java 21+, RC) replaces this with `Ext` + `karate-boot.js` + `HttpClientFactory` and adds native `configure auth` (basic/bearer/oauth2). We target v1 now but must not hard-wire v1 types into auth logic.

## Goals / Non-Goals

**Goals:**
- A reproducible `mvn verify` build producing a Java-17 artifact `io.github.lindenson:karate-authflow`.
- Karate treated as a `provided` dependency so we never force a Karate version on consumers within the 1.5.x line.
- Quality gates wired (JUnit 5, JaCoCo) and Maven Central publishing configured (not executed).
- A thin `KarateBinding` seam that isolates every Karate-version-specific call, proven by a v1 binding skeleton + a smoke test that loads Karate types.

**Non-Goals:**
- No authentication behavior (strategies, interceptor logic) — that is `auth-interceptor-core` and later changes.
- No actual publish to Maven Central, no GitHub repo creation.
- No Karate v2 binding implementation (only the seam that makes it addable).

## Decisions

- **Single Maven module, not multi-module (yet).** Rationale: the codebase is small; premature `core`/`crypto` splitting adds POM overhead. Revisit when the crypto module gains heavy deps (e.g. BouncyCastle) — then split `karate-authflow-crypto`. *Alternative considered:* multi-module from day one — rejected as premature.
- **`maven.compiler.release=17`** (not `source`/`target`). Rationale: `--release` guarantees we don't accidentally call JDK 18+ APIs while building on JDK 25; 17 is the widest still-current LTS for Karate 1.5.x users. *Alternative:* Java 11 (Karate's floor) — rejected, 17 is mainstream and gives records/sealed types; Java 21 — rejected, would exclude 17 shops and is only required by Karate v2.
- **Karate `provided`, version `1.5.2` as the build/test floor.** Rationale: the consumer's project already depends on Karate; `provided` avoids version conflicts and keeps our jar lean. We compile against the API but the consumer supplies the runtime. *Alternative:* `compile` scope — rejected (forces our pinned Karate on everyone).
- **`KarateBinding` seam.** A single interface in package `...authflow.spi` abstracting "register the interceptor with a Karate runner" and "read/mutate a request" so auth code depends on our types, never on `com.intuit.karate.*`. The v1 implementation (`KarateV1Binding`) wraps `RuntimeHook`/`HttpRequest`. *Alternative:* depend on Karate types directly — rejected, would make v2 support a rewrite. The seam is the explicit price we pay now for the v2 migration the user chose.
- **Publishing via Sonatype Central Portal** with `central-publishing-maven-plugin`, plus `maven-source-plugin`, `maven-javadoc-plugin`, `maven-gpg-plugin`, activated under a `release` profile. Rationale: Central is mandatory for `io.github.*` discoverability; gating behind a profile keeps day-to-day `mvn verify` fast and unsigned.
- **JaCoCo with a `check` goal but a low initial threshold** (e.g. line 0% gate now, raised per-change). Rationale: a hard gate from an empty project is noise; we ratchet coverage as real code lands (the `improve-coverage-maven` workflow can drive this later).

## Risks / Trade-offs

- **Karate API is internal-ish; 1.5.x minor bumps could shift `RuntimeHook`/`HttpRequest`.** → The `KarateBinding` seam localizes breakage to one class; CI pins `1.5.2` and we test the binding explicitly.
- **`provided` scope means our tests need Karate on the test classpath explicitly.** → Add `karate-junit5:1.5.2` in `test` scope; document for contributors.
- **Building on JDK 25 while targeting 17.** → `--release 17` enforced; CI matrix includes a real JDK 17 run to catch toolchain drift.
- **Over-abstracting the seam before the second binding exists (speculative generality).** → Keep `KarateBinding` minimal — only the methods auth-interceptor-core actually needs; expand when the v2 binding is really written, not before.
- **`io.github.lindenson` namespace ownership on Central** must be verifiable via the GitHub account. → Confirm the Central Portal namespace claim before the first real publish (out of scope for this change, noted for `docs-release`).

## Open Questions

- Exact initial JaCoCo thresholds and whether to fail the build on them now or in `docs-release`.
- Whether to add Spotless/Checkstyle now or in a dedicated quality change (leaning: defer to keep this change focused).
