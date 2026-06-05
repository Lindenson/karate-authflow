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

import io.github.lindenson.karate.authflow.AuthStrategy;
import io.github.lindenson.karate.authflow.spi.AuthRequest;

import java.util.Objects;

/**
 * Session authentication against Ory Kratos.
 *
 * <p>On first use it performs the Kratos browser login flow once, caches the
 * {@code ory_kratos_session} cookie, and thereafter appends that cookie to every
 * request — so feature files need no login steps. The login is lazy and guarded
 * by double-checked locking, so a single instance is safe to share across
 * scenarios under {@code Runner.parallel(n)}.
 *
 * <p>Re-authentication on session expiry / {@code 401} is not yet handled.
 */
public final class KratosSessionStrategy implements AuthStrategy {

    private static final String NAME = "kratos-session";

    private final KratosClient client;
    private final String identifier;
    private final String password;
    private final String cookieName;

    private final Object loginLock = new Object();
    private volatile String sessionValue;

    /**
     * @param kratosPublicUrl the Kratos public endpoint base URL
     * @param identifier      the identity identifier (e.g. email)
     * @param password        the password
     */
    public KratosSessionStrategy(String kratosPublicUrl, String identifier, String password) {
        this(new KratosClient(kratosPublicUrl), identifier, password, KratosClient.SESSION_COOKIE);
    }

    /** Test/extension constructor allowing a pre-built client and custom cookie name. */
    KratosSessionStrategy(KratosClient client, String identifier, String password, String cookieName) {
        this.client = Objects.requireNonNull(client, "client must not be null");
        this.identifier = Objects.requireNonNull(identifier, "identifier must not be null");
        this.password = Objects.requireNonNull(password, "password must not be null");
        this.cookieName = Objects.requireNonNull(cookieName, "cookieName must not be null");
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public void intercept(AuthRequest request) {
        String cookie = cookieName + '=' + ensureSession();
        String existing = request.header("Cookie");
        request.putHeader("Cookie", (existing == null || existing.isEmpty()) ? cookie : existing + "; " + cookie);
    }

    private String ensureSession() {
        String value = sessionValue;
        if (value == null) {
            synchronized (loginLock) {
                value = sessionValue;
                if (value == null) {
                    value = client.login(identifier, password);
                    sessionValue = value;
                }
            }
        }
        return value;
    }
}
