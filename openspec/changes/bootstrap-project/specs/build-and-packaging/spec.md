## ADDED Requirements

### Requirement: Maven build with Java 17 bytecode

The project SHALL build with Maven and produce artifacts compiled to Java 17 bytecode via `maven.compiler.release=17`, regardless of the JDK used to build (JDK 17 through 25).

#### Scenario: Clean build succeeds
- **WHEN** a contributor runs `mvn verify` on a JDK 17–25
- **THEN** the build completes successfully and produces `target/karate-authflow-<version>.jar`

#### Scenario: Bytecode targets Java 17
- **WHEN** the compiled classes are inspected with `javap -verbose`
- **THEN** the class file major version corresponds to Java 17 (major version 61)

### Requirement: Public artifact identity

The project SHALL publish under groupId `io.github.lindenson`, artifactId `karate-authflow`, with base Java package `io.github.lindenson.karate.authflow`.

#### Scenario: POM coordinates
- **WHEN** the `pom.xml` is read
- **THEN** groupId is `io.github.lindenson` and artifactId is `karate-authflow`

#### Scenario: Source package layout
- **WHEN** main sources are inspected
- **THEN** all production classes reside under `io.github.lindenson.karate.authflow`

### Requirement: Karate as a provided dependency

The library SHALL declare Karate (`io.karatelabs:karate-core:1.5.2`) in `provided` scope so it is not transitively imposed on consumers, and SHALL declare `io.karatelabs:karate-junit5:1.5.2` and JUnit 5 in `test` scope for the library's own tests.

#### Scenario: Karate not leaked transitively
- **WHEN** a consumer adds `io.github.lindenson:karate-authflow` as a dependency and runs `mvn dependency:tree`
- **THEN** `karate-core` does NOT appear as a transitive `compile`/`runtime` dependency of `karate-authflow`

#### Scenario: Library tests can use Karate
- **WHEN** `mvn test` runs
- **THEN** test classes can reference `com.intuit.karate.*` types because Karate is on the test classpath

### Requirement: Version-adapter seam isolates Karate version

The project SHALL provide a `KarateBinding` abstraction in package `io.github.lindenson.karate.authflow.spi` such that no class outside that package references `com.intuit.karate.*` types directly, enabling a future Karate v2 binding without changing auth logic.

#### Scenario: v1 binding present
- **WHEN** the source tree is inspected
- **THEN** a `KarateBinding` interface and a v1 implementation (e.g. `KarateV1Binding`) exist under `...authflow.spi`

#### Scenario: Karate types confined to the seam
- **WHEN** imports of `com.intuit.karate.*` are searched across `src/main/java`
- **THEN** they appear only within the `io.github.lindenson.karate.authflow.spi` package

### Requirement: Quality gates

The build SHALL run JUnit 5 tests under the Surefire plugin and produce a JaCoCo coverage report during `mvn verify`, and SHALL fail the build when any test fails.

#### Scenario: Failing test breaks the build
- **WHEN** a test assertion fails during `mvn verify`
- **THEN** the Maven build exits with a non-zero status

#### Scenario: Coverage report generated
- **WHEN** `mvn verify` completes
- **THEN** a JaCoCo report exists at `target/site/jacoco/index.html`

### Requirement: Apache-2.0 licensing

The project SHALL be licensed under Apache-2.0, with a `LICENSE` file at the repository root and the license declared in the POM.

#### Scenario: License file present
- **WHEN** the repository root is inspected
- **THEN** a `LICENSE` file containing the Apache License 2.0 text is present

#### Scenario: License declared in POM
- **WHEN** the `pom.xml` `<licenses>` section is read
- **THEN** it declares Apache-2.0 with its canonical URL

### Requirement: Maven Central publishing readiness

The project SHALL be configured to publish to Maven Central via the Sonatype Central Portal, producing `-sources` and `-javadoc` jars and GPG-signed artifacts under a `release` profile, without performing the publish during a normal build.

#### Scenario: Release profile produces auxiliary jars
- **WHEN** `mvn verify -Prelease` runs in an environment with signing configured
- **THEN** `-sources.jar` and `-javadoc.jar` are produced and artifacts are GPG-signed

#### Scenario: Normal build skips signing and publish
- **WHEN** `mvn verify` runs without the `release` profile
- **THEN** no GPG signing occurs and nothing is uploaded to a remote repository

### Requirement: Continuous integration

The project SHALL include a GitHub Actions workflow that runs `mvn verify` on a Java 17 matrix for every push and pull request.

#### Scenario: CI runs on push
- **WHEN** a commit is pushed to the repository
- **THEN** a GitHub Actions job checks out the code and runs `mvn verify` on JDK 17
