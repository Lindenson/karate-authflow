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

import com.intuit.karate.Runner;

/**
 * Entry point for wiring an authentication interceptor into a Karate run.
 *
 * <p>This is the single place test code touches to enable {@code karate-authflow};
 * feature files stay unchanged. Example:
 *
 * <pre>{@code
 * Results results = KarateAuth
 *     .register(Runner.path("classpath:features"), new BasicAuthStrategy("user", "pass"))
 *     .parallel(5);
 * }</pre>
 *
 * <p>Karate-version-specific wiring is delegated to a {@link KarateBinding}; this
 * class and the binding are the only code that references {@code com.intuit.karate.*}.
 */
public final class KarateAuth {

    private static final KarateBinding BINDING = new KarateV1Binding();

    private KarateAuth() {
    }

    /**
     * Register a pre-request interceptor (e.g. an {@code AuthStrategy}) on a Karate
     * runner builder and return that same builder for fluent chaining.
     *
     * @param builder     the Karate runner builder
     * @param interceptor the interceptor to apply before every HTTP request
     * @param <T>         the concrete builder type
     * @return the supplied {@code builder}, now carrying the interceptor hook
     */
    public static <T extends Runner.Builder<T>> T register(T builder, PreRequestInterceptor interceptor) {
        builder.hook((com.intuit.karate.RuntimeHook) BINDING.createHook(interceptor));
        return builder;
    }
}
