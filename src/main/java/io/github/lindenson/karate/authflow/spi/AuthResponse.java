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
 * Version-agnostic, mutable view of an HTTP response — the response counterpart
 * of {@link AuthRequest}.
 *
 * <p>A {@link PostResponseInterceptor} receives this after the call returns and
 * before the scenario reads {@code response}; replacing the body here is what the
 * scenario's {@code match response.X} observes. Backed by a Karate-version-specific
 * response object inside this package.
 */
public interface AuthResponse {

    /** @return the HTTP status code. */
    int status();

    /**
     * Replace the HTTP status code.
     *
     * @param status new status code
     */
    void status(int status);

    /**
     * @param name header name
     * @return the first value of the header, or {@code null} if absent
     */
    String header(String name);

    /** @return the raw response body bytes, or {@code null} if there is no body. */
    byte[] body();

    /**
     * Replace the response body with raw bytes.
     *
     * @param body new body bytes
     */
    void body(byte[] body);

    /**
     * Replace the response body with a string (UTF-8).
     *
     * @param body new body text
     */
    void body(String body);

    /** @return the response body decoded as a string, or {@code null} if absent. */
    String bodyAsString();

    /**
     * @return a token identifying the current scenario, stable across all of its
     *         requests and distinct between scenarios — use it to partition
     *         per-scenario state in a shared strategy instance
     */
    String scenarioId();
}
