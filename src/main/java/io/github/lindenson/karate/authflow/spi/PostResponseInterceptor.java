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
 * Callback invoked once for every HTTP response, after it is received and before
 * the scenario reads {@code response}.
 *
 * <p>Implementations may inspect and/or replace the {@link AuthResponse} body —
 * e.g. to decrypt an encrypted payload so the feature can assert on cleartext.
 */
@FunctionalInterface
public interface PostResponseInterceptor {

    /**
     * Inspect and/or mutate the response.
     *
     * @param response the mutable response view
     */
    void intercept(AuthResponse response);
}
