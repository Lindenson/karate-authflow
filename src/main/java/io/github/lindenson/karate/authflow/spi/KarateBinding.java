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
 * Adapter that isolates Karate-version-specific extension wiring.
 *
 * <p>Implementations are the <strong>only</strong> place in the codebase allowed
 * to reference {@code com.intuit.karate.*} (Karate 1.x) or future {@code Ext} /
 * {@code HttpClientFactory} types (Karate 2.x). All authentication logic depends
 * on this interface and {@link AuthRequest}, never on Karate types, so adding a
 * new Karate version means adding a binding — not rewriting strategies.
 *
 * @see KarateV1Binding
 */
public interface KarateBinding {

    /**
     * @return a stable identifier for this binding, e.g. {@code "karate-1.x"}
     */
    String id();

    /**
     * Create a Karate-native hook object that invokes {@code request} before every
     * HTTP call. Equivalent to {@link #createHook(PreRequestInterceptor, PostResponseInterceptor)}
     * with no response interceptor.
     *
     * @param request the pre-request callback to wire in
     * @return a Karate-native hook instance
     */
    default Object createHook(PreRequestInterceptor request) {
        return createHook(request, null);
    }

    /**
     * Create a Karate-native hook object that invokes {@code request} before every
     * HTTP call and {@code response} after every HTTP call (before the scenario
     * reads {@code response}).
     *
     * <p>The return type is {@link Object} on purpose, to keep this interface free
     * of Karate types. Callers register it through the binding's version-specific
     * helper (for Karate 1.x, {@link KarateV1Binding#register}).
     *
     * @param request  the pre-request callback to wire in
     * @param response the post-response callback to wire in, or {@code null} for none
     * @return a Karate-native hook instance
     */
    Object createHook(PreRequestInterceptor request, PostResponseInterceptor response);
}
