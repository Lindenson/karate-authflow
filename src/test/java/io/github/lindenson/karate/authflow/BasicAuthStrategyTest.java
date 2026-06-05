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

import com.intuit.karate.RuntimeHook;
import com.intuit.karate.http.HttpRequest;
import io.github.lindenson.karate.authflow.spi.KarateV1Binding;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("BasicAuthStrategy")
class BasicAuthStrategyTest {

    /** Drives a strategy through the real seam against a fabricated native request. */
    private static HttpRequest intercept(BasicAuthStrategy strategy, HttpRequest request) {
        RuntimeHook hook = (RuntimeHook) new KarateV1Binding().createHook(strategy);
        hook.beforeHttpCall(request, null);
        return request;
    }

    private static HttpRequest request() {
        HttpRequest request = new HttpRequest();
        request.setUrl("https://api.example.com/resource");
        request.setMethod("GET");
        return request;
    }

    private static String expectedHeader(String user, String pass) {
        String token = Base64.getEncoder().encodeToString((user + ':' + pass).getBytes(StandardCharsets.UTF_8));
        return "Basic " + token;
    }

    @Test
    @DisplayName("sets the RFC 7617 Authorization header")
    void setsAuthorizationHeader() {
        HttpRequest result = intercept(new BasicAuthStrategy("alice", "s3cret"), request());

        assertEquals(expectedHeader("alice", "s3cret"), result.getHeader("Authorization"));
    }

    @Test
    @DisplayName("overwrites a pre-existing Authorization header")
    void overwritesExistingHeader() {
        HttpRequest request = request();
        request.putHeader("Authorization", "Bearer stale-token");

        HttpRequest result = intercept(new BasicAuthStrategy("bob", "pw"), request);

        assertEquals(expectedHeader("bob", "pw"), result.getHeader("Authorization"));
    }

    @Test
    @DisplayName("reports the strategy name")
    void reportsName() {
        assertEquals("basic", new BasicAuthStrategy("u", "p").name());
    }

    @Test
    @DisplayName("rejects null credentials")
    void rejectsNullCredentials() {
        assertThrows(NullPointerException.class, () -> new BasicAuthStrategy(null, "p"));
        assertThrows(NullPointerException.class, () -> new BasicAuthStrategy("u", null));
    }
}
