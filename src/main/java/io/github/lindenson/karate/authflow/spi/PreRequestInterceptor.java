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
 * Callback invoked once for every HTTP request before it leaves Karate.
 *
 * <p>Implementations mutate the supplied {@link AuthRequest} to apply
 * authentication (headers, cookies, body encryption, signing). This bootstrap
 * stage defines the contract only; concrete strategies arrive in later changes.
 */
@FunctionalInterface
public interface PreRequestInterceptor {

    /**
     * Inspect and/or mutate the outgoing request.
     *
     * @param request the mutable request view
     */
    void intercept(AuthRequest request);
}
