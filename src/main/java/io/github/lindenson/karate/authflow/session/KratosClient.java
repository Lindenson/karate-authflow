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

import java.io.IOException;
import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Performs the Ory Kratos <em>browser</em> login flow and returns the resulting
 * {@code ory_kratos_session} cookie value.
 *
 * <p>The flow is two HTTP calls sharing one {@link CookieManager} (so the CSRF
 * cookie set during initialization is carried into the submission):
 * <ol>
 *   <li>{@code GET {publicBaseUrl}/self-service/login/browser} with
 *       {@code Accept: application/json} → read {@code ui.action} and the
 *       {@code csrf_token} node value.</li>
 *   <li>{@code POST {action}} with the CSRF cookie and a JSON body of
 *       {@code method=password}, {@code identifier}, {@code password},
 *       {@code csrf_token} → capture {@code ory_kratos_session} from
 *       {@code Set-Cookie}.</li>
 * </ol>
 */
public final class KratosClient {

    /** The Ory Kratos session cookie name. */
    public static final String SESSION_COOKIE = "ory_kratos_session";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final String publicBaseUrl;

    /**
     * @param publicBaseUrl the Kratos public endpoint base URL (e.g.
     *                      {@code https://auth.example.com}); a trailing slash is tolerated
     */
    public KratosClient(String publicBaseUrl) {
        Objects.requireNonNull(publicBaseUrl, "publicBaseUrl must not be null");
        this.publicBaseUrl = stripTrailingSlash(publicBaseUrl);
    }

    /**
     * Run the login flow.
     *
     * @param identifier the Kratos identity identifier (e.g. email)
     * @param password   the password
     * @return the {@code ory_kratos_session} cookie value
     * @throws KratosLoginException if the flow does not complete successfully
     */
    public String login(String identifier, String password) {
        Objects.requireNonNull(identifier, "identifier must not be null");
        Objects.requireNonNull(password, "password must not be null");

        CookieManager cookies = new CookieManager();
        HttpClient http = HttpClient.newBuilder()
                .cookieHandler(cookies)
                .connectTimeout(TIMEOUT)
                .build();

        Flow flow = initFlow(http);
        HttpResponse<String> submission = submit(http, flow, identifier, password);
        return extractSessionCookie(submission);
    }

    private Flow initFlow(HttpClient http) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(publicBaseUrl + "/self-service/login/browser"))
                .header("Accept", "application/json")
                .timeout(TIMEOUT)
                .GET()
                .build();

        HttpResponse<String> response = send(http, request, "initialize the Kratos login flow");
        if (!isSuccess(response)) {
            throw new KratosLoginException(
                    "Kratos login-flow initialization failed: HTTP " + response.statusCode());
        }

        JsonNode root = parse(response.body(), "login flow");
        String action = root.path("ui").path("action").asText("");
        if (action.isEmpty()) {
            throw new KratosLoginException("Kratos login flow contained no 'ui.action' URL");
        }
        return new Flow(action, extractCsrfToken(root));
    }

    private HttpResponse<String> submit(HttpClient http, Flow flow, String identifier, String password) {
        String body = MAPPER.createObjectNode()
                .put("method", "password")
                .put("identifier", identifier)
                .put("password", password)
                .put("csrf_token", flow.csrfToken)
                .toString();

        HttpRequest request = HttpRequest.newBuilder(URI.create(flow.action))
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .timeout(TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = send(http, request, "submit the Kratos login");
        if (!isSuccess(response)) {
            throw new KratosLoginException("Kratos login was rejected: HTTP " + response.statusCode());
        }
        return response;
    }

    private static String extractCsrfToken(JsonNode flowRoot) {
        JsonNode nodes = flowRoot.path("ui").path("nodes");
        if (nodes.isArray()) {
            for (JsonNode node : nodes) {
                JsonNode attributes = node.path("attributes");
                if ("csrf_token".equals(attributes.path("name").asText())) {
                    return attributes.path("value").asText("");
                }
            }
        }
        return "";
    }

    private String extractSessionCookie(HttpResponse<String> response) {
        String prefix = SESSION_COOKIE + "=";
        List<String> setCookies = response.headers().allValues("set-cookie");
        for (String setCookie : setCookies) {
            if (setCookie.startsWith(prefix)) {
                int end = setCookie.indexOf(';');
                String value = end >= 0 ? setCookie.substring(prefix.length(), end) : setCookie.substring(prefix.length());
                if (!value.isEmpty()) {
                    return value;
                }
            }
        }
        throw new KratosLoginException(
                "Kratos login succeeded but set no '" + SESSION_COOKIE + "' cookie");
    }

    private static HttpResponse<String> send(HttpClient http, HttpRequest request, String what) {
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new KratosLoginException("Failed to " + what, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new KratosLoginException("Interrupted while trying to " + what, e);
        }
    }

    private static JsonNode parse(String body, String what) {
        try {
            return MAPPER.readTree(body);
        } catch (IOException e) {
            throw new KratosLoginException("Could not parse the Kratos " + what + " response as JSON", e);
        }
    }

    private static boolean isSuccess(HttpResponse<?> response) {
        return response.statusCode() / 100 == 2;
    }

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /** Initialized login flow: where to submit and the CSRF token to include. */
    private static final class Flow {
        final String action;
        final String csrfToken;

        Flow(String action, String csrfToken) {
            this.action = action;
            this.csrfToken = csrfToken;
        }
    }
}
