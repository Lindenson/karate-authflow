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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A minimal in-process model of an Ory Kratos public endpoint for hermetic tests.
 *
 * <p>Implements just enough of the browser login flow to exercise {@link KratosClient}
 * and {@link KratosSessionStrategy}: flow initialization (sets a CSRF cookie), password
 * submission (validates the CSRF cookie + body token and the credentials, then sets the
 * session cookie), and a session-protected endpoint.
 */
final class FakeKratos implements AutoCloseable {

    static final String CSRF_TOKEN = "csrf-token-abc123";
    static final String SESSION_VALUE = "fake-session-value-xyz";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final HttpServer server;
    private final String baseUrl;
    private final String expectedIdentifier;
    private final String expectedPassword;
    private final AtomicInteger loginCount = new AtomicInteger();

    FakeKratos(String expectedIdentifier, String expectedPassword) throws IOException {
        this.expectedIdentifier = expectedIdentifier;
        this.expectedPassword = expectedPassword;
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        // Longest-prefix match: "/self-service/login/browser" wins over "/self-service/login".
        server.createContext("/self-service/login/browser", this::handleInit);
        server.createContext("/self-service/login", this::handleSubmit);
        server.createContext("/protected", this::handleProtected);
        server.setExecutor(null);
        server.start();
    }

    String baseUrl() {
        return baseUrl;
    }

    int loginCount() {
        return loginCount.get();
    }

    private void handleInit(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().add("Set-Cookie", "csrf_token=" + CSRF_TOKEN + "; Path=/; HttpOnly");
        String flow = "{"
                + "\"id\":\"flow-1\",\"type\":\"browser\","
                + "\"ui\":{\"action\":\"" + baseUrl + "/self-service/login?flow=flow-1\",\"method\":\"post\","
                + "\"nodes\":["
                + "{\"type\":\"input\",\"attributes\":{\"name\":\"identifier\"}},"
                + "{\"type\":\"input\",\"attributes\":{\"name\":\"password\",\"type\":\"password\"}},"
                + "{\"type\":\"input\",\"attributes\":{\"name\":\"csrf_token\",\"value\":\"" + CSRF_TOKEN + "\"}}"
                + "]}}";
        respond(exchange, 200, flow);
    }

    private void handleSubmit(HttpExchange exchange) throws IOException {
        String cookieCsrf = cookie(exchange, "csrf_token");
        JsonNode body = MAPPER.readTree(readBody(exchange));
        boolean csrfOk = CSRF_TOKEN.equals(cookieCsrf) && CSRF_TOKEN.equals(body.path("csrf_token").asText(""));
        boolean credentialsOk = expectedIdentifier.equals(body.path("identifier").asText(""))
                && expectedPassword.equals(body.path("password").asText(""));
        boolean methodOk = "password".equals(body.path("method").asText(""));

        if (csrfOk && credentialsOk && methodOk) {
            loginCount.incrementAndGet();
            exchange.getResponseHeaders().add("Set-Cookie",
                    "ory_kratos_session=" + SESSION_VALUE + "; Path=/; HttpOnly; SameSite=Lax");
            respond(exchange, 200, "{\"session\":{\"active\":true}}");
        } else {
            respond(exchange, 400, "{\"error\":{\"reason\":\"invalid credentials or CSRF\"}}");
        }
    }

    private void handleProtected(HttpExchange exchange) throws IOException {
        if (SESSION_VALUE.equals(cookie(exchange, "ory_kratos_session"))) {
            respond(exchange, 200, "{\"ok\":true}");
        } else {
            respond(exchange, 401, "{\"error\":{\"code\":401,\"reason\":\"No valid session cookie found.\"}}");
        }
    }

    private static String cookie(HttpExchange exchange, String name) {
        String header = exchange.getRequestHeaders().getFirst("Cookie");
        if (header == null) {
            return null;
        }
        for (String part : header.split(";")) {
            String trimmed = part.trim();
            String prefix = name + "=";
            if (trimmed.startsWith(prefix)) {
                return trimmed.substring(prefix.length());
            }
        }
        return null;
    }

    private static String readBody(HttpExchange exchange) throws IOException {
        try (InputStream in = exchange.getRequestBody()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void respond(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
