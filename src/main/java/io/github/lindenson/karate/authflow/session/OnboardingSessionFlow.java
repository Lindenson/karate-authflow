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

import io.github.lindenson.karate.authflow.onboarding.EncryptedOnboardingConfig;
import io.github.lindenson.karate.authflow.onboarding.EncryptedOnboardingStrategy;
import io.github.lindenson.karate.authflow.spi.AuthRequest;
import io.github.lindenson.karate.authflow.spi.AuthResponse;
import io.github.lindenson.karate.authflow.spi.PostResponseInterceptor;
import io.github.lindenson.karate.authflow.spi.PreRequestInterceptor;

import java.net.URI;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * One strategy for the full journey: onboarding endpoints are handled by
 * {@link EncryptedOnboardingStrategy} (RGK), every other endpoint by {@link SttkSessionStrategy}
 * (STTK), both sharing the same per-scenario {@code OnboardingKeyStore}. Register once:
 *
 * <pre>{@code
 * OnboardingSessionFlow flow = new OnboardingSessionFlow(onboardingConfig);
 * KarateAuth.register(Runner.path("classpath:journey"), flow, flow).parallel(n);
 * }</pre>
 */
public final class OnboardingSessionFlow implements PreRequestInterceptor, PostResponseInterceptor {

    private final EncryptedOnboardingStrategy onboarding;
    private final SttkSessionStrategy session;
    /** scenarioId → was the in-flight request handled by onboarding? (responses carry no URL). */
    private final ConcurrentHashMap<String, Boolean> onboardingHandledLast = new ConcurrentHashMap<>();

    public OnboardingSessionFlow(EncryptedOnboardingConfig config) {
        Objects.requireNonNull(config, "config");
        this.onboarding = new EncryptedOnboardingStrategy(config);
        this.session = new SttkSessionStrategy(onboarding::keyStore, config.appVersion());
    }

    /** @return the underlying onboarding strategy (e.g. to inspect the key store). */
    public EncryptedOnboardingStrategy onboarding() {
        return onboarding;
    }

    @Override
    public void intercept(AuthRequest request) {
        boolean onb = onboarding.handles(request.method(), pathOf(request.url()));
        onboardingHandledLast.put(request.scenarioId(), onb);
        if (onb) {
            onboarding.intercept(request);
        } else {
            session.intercept(request);
        }
    }

    @Override
    public void intercept(AuthResponse response) {
        if (Boolean.TRUE.equals(onboardingHandledLast.get(response.scenarioId()))) {
            onboarding.intercept(response);
        } else {
            session.intercept(response);
        }
    }

    private static String pathOf(String url) {
        try {
            return URI.create(url).getPath();
        } catch (RuntimeException e) {
            return url;
        }
    }
}
