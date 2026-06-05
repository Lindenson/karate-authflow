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
package io.github.lindenson.karate.authflow;

import com.intuit.karate.Results;
import com.intuit.karate.Runner;
import io.github.lindenson.karate.authflow.spi.KarateAuth;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Network-dependent verification against a public HTTP Basic endpoint.
 *
 * <p>Tagged {@code live} and excluded from the default build. Run with:
 * <pre>mvn test -Dauthflow.test.excludedGroups=</pre>
 */
@Tag("live")
@DisplayName("BasicAuthStrategy against a live endpoint")
class BasicAuthLiveTest {

    private static final String FEATURE =
            "classpath:io/github/lindenson/karate/authflow/basic-auth-live.feature";

    @Test
    @DisplayName("transparently authenticates an auth-free feature")
    void transparentlyAuthenticates() {
        Results results = KarateAuth
                .register(Runner.path(FEATURE), new BasicAuthStrategy("postman", "password"))
                .parallel(1);

        assertEquals(0, results.getFailCount(), results.getErrorMessages());
    }
}
