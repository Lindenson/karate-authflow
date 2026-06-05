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
package io.github.lindenson.karate.authflow.session;

import com.intuit.karate.Results;
import com.intuit.karate.Runner;
import io.github.lindenson.karate.authflow.spi.KarateAuth;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * End-to-end, hermetic proof: an auth-free Karate feature reaches a
 * session-protected endpoint purely because {@link KratosSessionStrategy} logged
 * in to the modelled Kratos and injected the session cookie. Uses a local
 * {@link FakeKratos} — no network — so it runs in the default build.
 */
@DisplayName("KratosSessionStrategy end-to-end via Karate")
class KratosSessionIntegrationTest {

    private static final String USER = "alice@example.com";
    private static final String PASS = "s3cret";
    private static final String FEATURE =
            "classpath:io/github/lindenson/karate/authflow/session/kratos-session.feature";

    @Test
    @DisplayName("reaches a protected endpoint with no auth steps in the feature")
    void protectedEndpointReachableTransparently() throws Exception {
        try (FakeKratos kratos = new FakeKratos(USER, PASS)) {
            System.setProperty("kratos.base", kratos.baseUrl());
            try {
                Results results = KarateAuth
                        .register(Runner.path(FEATURE),
                                  new KratosSessionStrategy(kratos.baseUrl(), USER, PASS))
                        .parallel(1);

                assertEquals(0, results.getFailCount(), results.getErrorMessages());
            } finally {
                System.clearProperty("kratos.base");
            }
        }
    }
}
