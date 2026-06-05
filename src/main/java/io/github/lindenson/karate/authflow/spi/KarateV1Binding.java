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

/**
 * Karate 1.5.x binding.
 *
 * <p>Wires a {@link PreRequestInterceptor} into Karate's
 * {@link RuntimeHook#beforeHttpCall(HttpRequest, ScenarioRuntime)} extension
 * point, where the outgoing {@link HttpRequest} is still mutable (headers and
 * body). This bootstrap stage carries no authentication logic: it only proves
 * the seam works end-to-end against the real Karate 1.5.x API.
 */
public final class KarateV1Binding implements KarateBinding {

    private static final String ID = "karate-1.x";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Object createHook(PreRequestInterceptor interceptor) {
        if (interceptor == null) {
            throw new IllegalArgumentException("interceptor must not be null");
        }
        return new InterceptingHook(interceptor);
    }

    /**
     * Register an interceptor on a Karate {@link Runner.Builder} as a
     * {@link RuntimeHook}. Convenience so callers outside this package never
     * touch the {@code com.intuit.karate} hook types.
     *
     * @param builder     the Karate runner builder
     * @param interceptor the pre-request callback to wire in
     */
    public void register(Runner.Builder<?> builder, PreRequestInterceptor interceptor) {
        builder.hook((RuntimeHook) createHook(interceptor));
    }

    /** {@link RuntimeHook} that delegates each HTTP call to a {@link PreRequestInterceptor}. */
    private static final class InterceptingHook implements RuntimeHook {

        private final PreRequestInterceptor interceptor;

        InterceptingHook(PreRequestInterceptor interceptor) {
            this.interceptor = interceptor;
        }

        @Override
        public void beforeHttpCall(HttpRequest request, ScenarioRuntime sr) {
            interceptor.intercept(new V1AuthRequest(request));
        }
    }

    /** Adapts Karate 1.x {@link HttpRequest} to the version-agnostic {@link AuthRequest}. */
    private static final class V1AuthRequest implements AuthRequest {

        private final HttpRequest delegate;

        V1AuthRequest(HttpRequest delegate) {
            this.delegate = delegate;
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
    }
}
