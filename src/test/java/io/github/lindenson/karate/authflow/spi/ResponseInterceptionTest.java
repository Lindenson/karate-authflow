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
package io.github.lindenson.karate.authflow.spi;

import com.intuit.karate.Results;
import com.intuit.karate.Runner;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Response interception seam")
class ResponseInterceptionTest {

    private static HttpServer startServer() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = "{\"cipher\":\"opaque\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.setExecutor(null);
        server.start();
        return server;
    }

    @Test
    @DisplayName("a replaced response body is what the scenario sees")
    void postResponseInterceptorMutatesBody() throws Exception {
        HttpServer server = startServer();
        System.setProperty("ri.base", "http://127.0.0.1:" + server.getAddress().getPort());
        try {
            PreRequestInterceptor noRequest = request -> { };
            PostResponseInterceptor decrypt = response -> response.body("{\"value\":\"decrypted\"}");

            Results results = KarateAuth
                    .register(Runner.path("classpath:io/github/lindenson/karate/authflow/spi/resp-mutation.feature"),
                              noRequest, decrypt)
                    .parallel(1);

            assertEquals(0, results.getFailCount(), results.getErrorMessages());
        } finally {
            server.stop(0);
            System.clearProperty("ri.base");
        }
    }

    @Test
    @DisplayName("scenarioId is stable within a scenario and distinct across scenarios")
    void scenarioIdPartitionsState() throws Exception {
        HttpServer server = startServer();
        System.setProperty("ri.base", "http://127.0.0.1:" + server.getAddress().getPort());

        ConcurrentLinkedQueue<String> seen = new ConcurrentLinkedQueue<>();
        PreRequestInterceptor recordId = request -> seen.add(request.scenarioId());

        try {
            Results results = KarateAuth
                    .register(Runner.path("classpath:io/github/lindenson/karate/authflow/spi/scenario-id.feature"),
                              recordId)
                    .parallel(2);

            assertEquals(0, results.getFailCount(), results.getErrorMessages());

            List<String> ids = List.copyOf(seen);
            assertEquals(4, ids.size(), "two scenarios x two requests");
            ids.forEach(id -> assertNotNull(id, "scenarioId must be present"));
            assertTrue(ids.stream().noneMatch(String::isEmpty), "scenarioId must be non-empty under a real run");

            Map<String, Long> byId = ids.stream().collect(Collectors.groupingBy(id -> id, ConcurrentHashMap::new, Collectors.counting()));
            assertEquals(2, byId.size(), "exactly two distinct scenario ids");
            assertTrue(byId.values().stream().allMatch(count -> count == 2L), "each scenario id seen twice");
        } finally {
            server.stop(0);
            System.clearProperty("ri.base");
        }
    }
}
