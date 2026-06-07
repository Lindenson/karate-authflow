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
package io.github.lindenson.karate.authflow.examples;

import com.intuit.karate.Results;
import com.intuit.karate.Runner;
import io.github.lindenson.karate.authflow.onboarding.EncryptedOnboardingConfig;
import io.github.lindenson.karate.authflow.onboarding.OnboardingFlavor;
import io.github.lindenson.karate.authflow.session.OnboardingSessionFlow;
import io.github.lindenson.karate.authflow.spi.KarateAuth;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Example 3 — encrypted device onboarding + STTK working flow.
 *
 * <p>Self-contained: an in-process {@link FakeCryptoBackend} stands in for the real crypto backend,
 * so this runs with no network and no Docker. A single {@link OnboardingSessionFlow} drives the
 * whole journey: the onboarding endpoints under the RGK envelope (generate, RSA-wrap, AES, base64
 * matryoshka), then {@code POST /api/v1/devices/language} under the per-request STTK session key
 * (derive STTK/STMK from the captured master keys + rid, encrypt + MAC the body, verify + decrypt
 * the response). The feature stays cleartext throughout.
 *
 * <p>Run: {@code mvn test -Dtest=OnboardingExample}
 */
@DisplayName("Example: encrypted device onboarding + STTK language")
class OnboardingExample {

    @Test
    @DisplayName("onboards a device, then changes its language under STTK — all crypto handled by the plugin")
    void onboarding() throws Exception {
        try (FakeCryptoBackend backend = new FakeCryptoBackend()) {
            System.setProperty("backend.base", backend.baseUrl());
            try {
                EncryptedOnboardingConfig config = EncryptedOnboardingConfig.builder()
                        .flavor(OnboardingFlavor.STANDARD)
                        .appVersion(100_005_000)
                        .builtInServerKey(backend.serverPublicKeyX509())
                        .builtInPkr("demo-pkr")
                        .otp("000000")
                        .build();
                // false = full STTK encryption on working-flow endpoints (request AES + MAC,
                // response decrypt + MAC verify). One composite strategy = onboard + work.
                OnboardingSessionFlow flow = new OnboardingSessionFlow(config, false);

                Results results = KarateAuth
                        .register(Runner.path("classpath:onboarding/onboarding.feature"), flow, flow)
                        .parallel(1);

                assertEquals(0, results.getFailCount(), results.getErrorMessages());
            } finally {
                System.clearProperty("backend.base");
            }
        }
    }
}
