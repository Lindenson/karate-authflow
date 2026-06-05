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

import com.intuit.karate.RuntimeHook;
import com.intuit.karate.http.HttpRequest;
import io.github.lindenson.karate.authflow.AuthStrategy;
import io.github.lindenson.karate.authflow.spi.KarateV1Binding;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("KratosSessionStrategy")
class KratosSessionStrategyTest {

    private static final String USER = "alice@example.com";
    private static final String PASS = "s3cret";
    private static final String EXPECTED_COOKIE = "ory_kratos_session=" + FakeKratos.SESSION_VALUE;

    private static HttpRequest intercept(AuthStrategy strategy, HttpRequest request) {
        RuntimeHook hook = (RuntimeHook) new KarateV1Binding().createHook(strategy);
        hook.beforeHttpCall(request, null);
        return request;
    }

    private static HttpRequest get(String url) {
        HttpRequest request = new HttpRequest();
        request.setUrl(url);
        request.setMethod("GET");
        return request;
    }

    @Test
    @DisplayName("logs in once and injects the session cookie on every request")
    void injectsSessionCookieLoggingInOnce() throws Exception {
        try (FakeKratos kratos = new FakeKratos(USER, PASS)) {
            KratosSessionStrategy strategy = new KratosSessionStrategy(kratos.baseUrl(), USER, PASS);

            for (int i = 0; i < 3; i++) {
                HttpRequest result = intercept(strategy, get("https://api.example.com/orders"));
                assertEquals(EXPECTED_COOKIE, result.getHeader("Cookie"));
            }
            assertEquals(1, kratos.loginCount(), "login must happen exactly once across requests");
        }
    }

    @Test
    @DisplayName("appends to an existing Cookie header instead of clobbering it")
    void preservesExistingCookies() throws Exception {
        try (FakeKratos kratos = new FakeKratos(USER, PASS)) {
            KratosSessionStrategy strategy = new KratosSessionStrategy(kratos.baseUrl(), USER, PASS);

            HttpRequest request = get("https://api.example.com/orders");
            request.putHeader("Cookie", "theme=dark");
            intercept(strategy, request);

            assertEquals("theme=dark; " + EXPECTED_COOKIE, request.getHeader("Cookie"));
        }
    }

    @Test
    @DisplayName("performs a single login under concurrent first use")
    void singleLoginUnderConcurrency() throws Exception {
        try (FakeKratos kratos = new FakeKratos(USER, PASS)) {
            KratosSessionStrategy strategy = new KratosSessionStrategy(kratos.baseUrl(), USER, PASS);

            int threads = 16;
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            CountDownLatch start = new CountDownLatch(1);
            CountDownLatch done = new CountDownLatch(threads);
            for (int i = 0; i < threads; i++) {
                pool.execute(() -> {
                    try {
                        start.await();
                        HttpRequest result = intercept(strategy, get("https://api.example.com/orders"));
                        assertEquals(EXPECTED_COOKIE, result.getHeader("Cookie"));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertTrue(done.await(15, TimeUnit.SECONDS), "all threads should finish");
            pool.shutdownNow();

            assertEquals(1, kratos.loginCount(), "concurrent first-use must trigger only one login");
        }
    }

    @Test
    @DisplayName("rejects null constructor arguments")
    void rejectsNullArguments() {
        assertThrows(NullPointerException.class, () -> new KratosSessionStrategy(null, USER, PASS));
        assertThrows(NullPointerException.class, () -> new KratosSessionStrategy("http://x", null, PASS));
        assertThrows(NullPointerException.class, () -> new KratosSessionStrategy("http://x", USER, null));
    }

    @Test
    @DisplayName("reports its name")
    void reportsName() {
        assertEquals("kratos-session", new KratosSessionStrategy("http://x", USER, PASS).name());
    }
}
