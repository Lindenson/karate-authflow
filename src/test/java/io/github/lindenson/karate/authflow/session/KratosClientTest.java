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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("KratosClient browser login flow")
class KratosClientTest {

    private static final String USER = "alice@example.com";
    private static final String PASS = "s3cret";

    @Test
    @DisplayName("returns the ory_kratos_session value on a successful login")
    void returnsSessionCookie() throws Exception {
        try (FakeKratos kratos = new FakeKratos(USER, PASS)) {
            String session = new KratosClient(kratos.baseUrl()).login(USER, PASS);

            assertEquals(FakeKratos.SESSION_VALUE, session);
            assertEquals(1, kratos.loginCount());
        }
    }

    @Test
    @DisplayName("tolerates a trailing slash in the base URL")
    void toleratesTrailingSlash() throws Exception {
        try (FakeKratos kratos = new FakeKratos(USER, PASS)) {
            String session = new KratosClient(kratos.baseUrl() + "/").login(USER, PASS);

            assertEquals(FakeKratos.SESSION_VALUE, session);
        }
    }

    @Test
    @DisplayName("throws KratosLoginException on bad credentials")
    void throwsOnBadCredentials() throws Exception {
        try (FakeKratos kratos = new FakeKratos(USER, PASS)) {
            KratosClient client = new KratosClient(kratos.baseUrl());

            assertThrows(KratosLoginException.class, () -> client.login(USER, "wrong-password"));
        }
    }
}
