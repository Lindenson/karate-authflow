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
import io.github.lindenson.karate.authflow.BasicAuthStrategy;
import io.github.lindenson.karate.authflow.spi.KarateAuth;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Example 1 — HTTP Basic auth.
 *
 * <p>Runs a feature with no auth steps against the public
 * {@code postman-echo.com/basic-auth} endpoint; {@link BasicAuthStrategy} injects
 * the credentials. Requires internet access.
 *
 * <p>Run: {@code mvn test -Dtest=BasicAuthExample}
 */
@DisplayName("Example: HTTP Basic auth")
class BasicAuthExample {

    @Test
    @DisplayName("postman-echo basic-auth authenticates with no auth steps in the feature")
    void basicAuth() {
        Results results = KarateAuth
                .register(Runner.path("classpath:basic/basic.feature"),
                          new BasicAuthStrategy("postman", "password"))
                .parallel(1);

        assertEquals(0, results.getFailCount(), results.getErrorMessages());
    }
}
