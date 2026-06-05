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

/**
 * Version-agnostic, mutable view of an outgoing HTTP request.
 *
 * <p>This is the only request abstraction authentication logic should depend on.
 * It is backed by a Karate-version-specific object (e.g. Karate 1.x
 * {@code com.intuit.karate.http.HttpRequest}) that lives inside this package, so
 * strategies never reference {@code com.intuit.karate.*} directly and can be
 * reused unchanged across Karate versions.
 */
public interface AuthRequest {

    /** @return the fully-qualified request URL. */
    String url();

    /** @return the HTTP method (e.g. {@code "POST"}). */
    String method();

    /**
     * @param name header name (case-insensitive per HTTP semantics)
     * @return the first value of the header, or {@code null} if absent
     */
    String header(String name);

    /**
     * Sets (replacing any existing) a single-valued header.
     *
     * @param name  header name
     * @param value header value
     */
    void putHeader(String name, String value);

    /**
     * Removes a header if present.
     *
     * @param name header name
     */
    void removeHeader(String name);

    /** @return the raw request body bytes, or {@code null} if there is no body. */
    byte[] body();

    /**
     * Replaces the request body. Implementations are responsible for any
     * content-length bookkeeping the underlying client requires.
     *
     * @param body new body bytes
     */
    void body(byte[] body);

    /** @return the request body decoded as a string, or {@code null} if absent. */
    String bodyAsString();
}
