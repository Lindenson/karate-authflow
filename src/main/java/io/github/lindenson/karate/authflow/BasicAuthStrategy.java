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

import io.github.lindenson.karate.authflow.spi.AuthRequest;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

/**
 * HTTP Basic authentication (RFC 7617).
 *
 * <p>Sets {@code Authorization: Basic <base64(username:password)>} on every request,
 * replacing any pre-existing {@code Authorization} header. The credentials are encoded
 * once at construction; the strategy holds no mutable state and is safe to share across
 * parallel scenarios.
 */
public final class BasicAuthStrategy implements AuthStrategy {

    private static final String NAME = "basic";

    private final String headerValue;

    /**
     * @param username the user name (must not be {@code null})
     * @param password the password (must not be {@code null})
     */
    public BasicAuthStrategy(String username, String password) {
        Objects.requireNonNull(username, "username must not be null");
        Objects.requireNonNull(password, "password must not be null");
        String credentials = username + ':' + password;
        String token = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        this.headerValue = "Basic " + token;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public void intercept(AuthRequest request) {
        request.putHeader("Authorization", headerValue);
    }
}
