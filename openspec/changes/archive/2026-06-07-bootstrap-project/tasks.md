## 1. Maven project skeleton

- [x] 1.1 Create `pom.xml` with groupId `io.github.lindenson`, artifactId `karate-authflow`, version `0.1.0-SNAPSHOT`, packaging `jar`, and `<name>`/`<description>`/`<url>` metadata
- [x] 1.2 Set `maven.compiler.release=17` and `project.build.sourceEncoding=UTF-8` properties
- [x] 1.3 Add `io.karatelabs:karate-core:1.5.2` in `provided` scope
- [x] 1.4 Add `io.karatelabs:karate-junit5:1.5.2` and `org.junit.jupiter:junit-jupiter` in `test` scope
- [x] 1.5 Add `.gitignore` (target/, IDE files, *.class) and create the `src/main/java` + `src/test/java` tree

## 2. Version-adapter seam

- [x] 2.1 Create package `io.github.lindenson.karate.authflow.spi` and define the `KarateBinding` interface (minimal: register-interceptor + request read/mutate abstraction, no auth logic)
- [x] 2.2 Add `KarateV1Binding` skeleton implementing `KarateBinding` against `com.intuit.karate.RuntimeHook` / `HttpRequest` (wiring only, throws/no-op where auth logic will later go)
- [x] 2.3 Confirm no `com.intuit.karate.*` import exists in `src/main/java` outside the `...authflow.spi` package

## 3. Quality gates

- [x] 3.1 Configure `maven-surefire-plugin` (3.2.5+) for JUnit 5
- [x] 3.2 Configure `jacoco-maven-plugin` with `prepare-agent` + `report` bound to `verify`
- [x] 3.3 Add a smoke test that loads a Karate type via the seam and asserts the binding instantiates (proves the test classpath + seam work)

## 4. Licensing & docs

- [x] 4.1 Add `LICENSE` (Apache-2.0 full text) at repo root
- [x] 4.2 Declare Apache-2.0 in the POM `<licenses>` section
- [x] 4.3 Write `README.md` scaffold: purpose, the three auth scenarios (basic/session/crypto), Karate 1.5.2 / Java 17 support note, quick-start placeholder, license badge

## 5. Publishing readiness (Maven Central)

- [x] 5.1 Add POM `<scm>`, `<developers>`, and `<organization>`/`<issueManagement>` metadata required by Central
- [x] 5.2 Add a `release` profile with `maven-source-plugin`, `maven-javadoc-plugin`, `maven-gpg-plugin`, and `central-publishing-maven-plugin` (configured but not executed by default)
- [x] 5.3 Verify `mvn verify -Prelease` builds `-sources`/`-javadoc` jars locally (signing may be skipped if no key present)

## 6. CI

- [x] 6.1 Add `.github/workflows/ci.yml` running `mvn -B verify` on JDK 17 for push and pull_request
- [x] 6.2 (Optional) Extend the CI matrix to also run on JDK 21 to catch toolchain drift

## 7. Verification

- [x] 7.1 Run `mvn verify` and confirm it passes, produces the jar, and generates `target/site/jacoco/index.html`
- [x] 7.2 Run `openspec validate bootstrap-project` and confirm the change is valid
