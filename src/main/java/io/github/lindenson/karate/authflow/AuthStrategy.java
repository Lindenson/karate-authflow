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

import io.github.lindenson.karate.authflow.spi.PreRequestInterceptor;

/**
 * An authentication scheme that can be applied transparently to outgoing requests.
 *
 * <p>An {@code AuthStrategy} <em>is</em> a {@link PreRequestInterceptor}: it mutates
 * the {@code AuthRequest} of every request before it is sent (headers, cookies,
 * body encryption, signing). Implementations reference no Karate type, so the same
 * strategy works across Karate versions.
 *
 * <p>Strategies should be stateless or internally thread-safe, because a single
 * instance is shared across scenarios running under {@code Runner.parallel(n)}.
 */
public interface AuthStrategy extends PreRequestInterceptor {

    /**
     * @return a short, stable name for this strategy (e.g. {@code "basic"}), used
     *         for logging and diagnostics
     */
    String name();
}
