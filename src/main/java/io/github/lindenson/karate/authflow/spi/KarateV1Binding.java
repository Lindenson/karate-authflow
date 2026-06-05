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

import com.intuit.karate.RuntimeHook;
import com.intuit.karate.Runner;
import com.intuit.karate.core.ScenarioRuntime;
import com.intuit.karate.http.HttpRequest;
import com.intuit.karate.http.Response;

/**
 * Karate 1.5.x binding.
 *
 * <p>Wires a {@link PreRequestInterceptor} into {@link RuntimeHook#beforeHttpCall}
 * (where the outgoing {@link HttpRequest} is mutable) and an optional
 * {@link PostResponseInterceptor} into {@link RuntimeHook#afterHttpCall} (where the
 * {@link Response} is mutable, before the scenario reads it). Carries no auth logic.
 */
public final class KarateV1Binding implements KarateBinding {

    private static final String ID = "karate-1.x";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Object createHook(PreRequestInterceptor request, PostResponseInterceptor response) {
        if (request == null) {
            throw new IllegalArgumentException("request interceptor must not be null");
        }
        return new InterceptingHook(request, response);
    }

    /**
     * Register interceptors on a Karate {@link Runner.Builder} as a {@link RuntimeHook}.
     * Convenience so callers outside this package never touch the {@code com.intuit.karate}
     * hook types.
     *
     * @param builder  the Karate runner builder
     * @param request  the pre-request callback
     * @param response the post-response callback, or {@code null} for none
     */
    public void register(Runner.Builder<?> builder, PreRequestInterceptor request, PostResponseInterceptor response) {
        builder.hook((RuntimeHook) createHook(request, response));
    }

    /** Register a request-only interceptor. */
    public void register(Runner.Builder<?> builder, PreRequestInterceptor request) {
        register(builder, request, null);
    }

    private static String scenarioId(ScenarioRuntime sr) {
        return sr == null ? "" : sr.scenario.getUniqueId();
    }

    /** {@link RuntimeHook} delegating before/after HTTP calls to the interceptors. */
    private static final class InterceptingHook implements RuntimeHook {

        private final PreRequestInterceptor request;
        private final PostResponseInterceptor response;

        InterceptingHook(PreRequestInterceptor request, PostResponseInterceptor response) {
            this.request = request;
            this.response = response;
        }

        @Override
        public void beforeHttpCall(HttpRequest httpRequest, ScenarioRuntime sr) {
            request.intercept(new V1AuthRequest(httpRequest, scenarioId(sr)));
        }

        @Override
        public void afterHttpCall(HttpRequest httpRequest, Response httpResponse, ScenarioRuntime sr) {
            if (response != null) {
                response.intercept(new V1AuthResponse(httpResponse, scenarioId(sr)));
            }
        }
    }

    /** Adapts Karate 1.x {@link HttpRequest} to {@link AuthRequest}. */
    private static final class V1AuthRequest implements AuthRequest {

        private final HttpRequest delegate;
        private final String scenarioId;

        V1AuthRequest(HttpRequest delegate, String scenarioId) {
            this.delegate = delegate;
            this.scenarioId = scenarioId;
        }

        @Override
        public String url() {
            return delegate.getUrl();
        }

        @Override
        public String method() {
            return delegate.getMethod();
        }

        @Override
        public String header(String name) {
            return delegate.getHeader(name);
        }

        @Override
        public void putHeader(String name, String value) {
            delegate.putHeader(name, value);
        }

        @Override
        public void removeHeader(String name) {
            delegate.removeHeader(name);
        }

        @Override
        public byte[] body() {
            return delegate.getBody();
        }

        @Override
        public void body(byte[] body) {
            delegate.setBody(body);
        }

        @Override
        public String bodyAsString() {
            return delegate.getBodyAsString();
        }

        @Override
        public String scenarioId() {
            return scenarioId;
        }
    }

    /** Adapts Karate 1.x {@link Response} to {@link AuthResponse}. */
    private static final class V1AuthResponse implements AuthResponse {

        private final Response delegate;
        private final String scenarioId;

        V1AuthResponse(Response delegate, String scenarioId) {
            this.delegate = delegate;
            this.scenarioId = scenarioId;
        }

        @Override
        public int status() {
            return delegate.getStatus();
        }

        @Override
        public void status(int status) {
            delegate.setStatus(status);
        }

        @Override
        public String header(String name) {
            Object value = delegate.getHeader(name);
            return value == null ? null : value.toString();
        }

        @Override
        public byte[] body() {
            return delegate.getBody();
        }

        @Override
        public void body(byte[] body) {
            delegate.setBody(body);
        }

        @Override
        public void body(String body) {
            delegate.setBody(body);
        }

        @Override
        public String bodyAsString() {
            return delegate.getBodyAsString();
        }

        @Override
        public String scenarioId() {
            return scenarioId;
        }
    }
}
