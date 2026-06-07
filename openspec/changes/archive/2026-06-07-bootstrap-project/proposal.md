## Why

`karate-authflow` is a new open-source library that adds a transparent authentication / pre-request interceptor layer to the [Karate](https://github.com/karatelabs/karate) test framework, so test authors never write auth boilerplate. Before any auth capability can be built, the project needs a professional, publishable foundation: a reproducible Maven build, a stable public artifact identity, quality gates, and licensing — all chosen to match the Karate ecosystem and to be consumable by other Java teams.

This change establishes that foundation only. No authentication behavior is implemented here.

## What Changes

- Create a single-module Maven project published as `io.github.lindenson:karate-authflow`, base package `io.github.lindenson.karate.authflow`.
- Compile against **Java 17** (`maven.compiler.release=17`) for broad adoption, even though the local JDK is newer.
- Depend on **Karate `io.karatelabs:karate-core:1.5.2`** as a **`provided`** dependency (the consumer already brings Karate); `karate-junit5:1.5.2` + JUnit 5 in `test` scope for the library's own tests.
- Add quality gates: JUnit 5, **JaCoCo** coverage reporting, and a build that fails on test failure (`mvn verify`).
- Add **Apache-2.0** license (`LICENSE`, SPDX headers convention) and a README scaffold describing the project's purpose, the three auth scenarios, and a quick-start placeholder.
- Add a **GitHub Actions** CI workflow building/testing on a Java 17 matrix.
- Introduce a **version-adapter seam**: a small internal abstraction (`KarateBinding`) isolating all Karate-version-specific extension wiring (v1 `RuntimeHook` / `HttpClientFactory`) so a future Karate v2 (`Ext` / `karate-boot.js`) adapter can be added without touching auth logic. This change ships the seam interface and the v1 binding skeleton (no auth behavior yet).
- Configure the project so it is publishable to **Maven Central** (Sonatype Central Portal): packaging, `sources`/`javadoc` jars, signing, and POM metadata (SCM, license, developer). Wiring only — no actual publish.

## Capabilities

### New Capabilities
- `build-and-packaging`: Requirements for how the library is built, tested, versioned, licensed, and packaged for distribution — the verifiable contract that the project is a professional, Java-17, Karate-1.5.2-targeted, Apache-2.0 artifact publishable to Maven Central, with coverage gates and a v2-ready adapter seam.

### Modified Capabilities
<!-- None — this is the first change; no existing specs. -->

## Impact

- **New code/files**: `pom.xml`, `src/main/java/io/github/lindenson/karate/authflow/spi/KarateBinding.java` (seam) + a v1 binding skeleton, `src/test/java/...` smoke test, `LICENSE`, `README.md`, `.github/workflows/ci.yml`, `.gitignore`.
- **Dependencies**: `io.karatelabs:karate-core:1.5.2` (provided), `io.karatelabs:karate-junit5:1.5.2` + `org.junit.jupiter:junit-jupiter` (test).
- **Toolchain**: Maven 3.9+, Java 17 bytecode (buildable on JDK 17–25).
- **Public contract**: groupId/artifactId/base package become permanent once published.
- **No runtime auth behavior** is added; downstream auth changes (`auth-interceptor-core`, `crypto-strategy`, `session-strategy`, `strategy-spi`) build on this foundation.
