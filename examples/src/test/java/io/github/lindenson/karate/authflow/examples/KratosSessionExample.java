/*
 * Copyright 2026 Lindenson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.lindenson.karate.authflow.examples;

import com.intuit.karate.Results;
import com.intuit.karate.Runner;
import io.github.lindenson.karate.authflow.session.KratosSessionStrategy;
import io.github.lindenson.karate.authflow.spi.KarateAuth;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Example 2 — Ory Kratos session auth (cookie-based).
 *
 * <p>Requires the bundled Kratos to be running (see this module's README):
 * <pre>docker compose up -d</pre>
 * Then {@link KratosSessionStrategy} logs in once via the Kratos browser flow and
 * injects the {@code ory_kratos_session} cookie so the feature's call to
 * {@code /sessions/whoami} reports an active session — with no login steps in the
 * feature itself.
 *
 * <p>Use {@code 127.0.0.1} (not {@code localhost}) to match the Kratos
 * {@code base_url}, otherwise the CSRF cookie is rejected.
 *
 * <p>Run: {@code mvn test -Dtest=KratosSessionExample}
 */
@DisplayName("Example: Ory Kratos session auth")
class KratosSessionExample {

    private static final String KRATOS_PUBLIC_URL = "http://127.0.0.1:4433";
    private static final String IDENTIFIER = "demo@example.com";
    private static final String PASSWORD = "KarateAuthflowDemo123";

    @Test
    @DisplayName("Kratos whoami reports an active session with no login steps in the feature")
    void kratosSession() {
        Results results = KarateAuth
                .register(Runner.path("classpath:kratos/kratos-whoami.feature"),
                          new KratosSessionStrategy(KRATOS_PUBLIC_URL, IDENTIFIER, PASSWORD))
                .parallel(1);

        assertEquals(0, results.getFailCount(), results.getErrorMessages());
    }
}
