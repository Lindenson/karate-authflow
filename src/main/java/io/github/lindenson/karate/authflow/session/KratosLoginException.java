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

/**
 * Raised when an Ory Kratos login flow does not complete successfully — for
 * example, on bad credentials, a non-success HTTP status, or a missing session
 * cookie. Thrown rather than silently proceeding without a session, so the
 * failure is visible to the test run.
 */
public class KratosLoginException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public KratosLoginException(String message) {
        super(message);
    }

    public KratosLoginException(String message, Throwable cause) {
        super(message, cause);
    }
}
