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
import io.github.lindenson.karate.authflow.onboarding.EncryptedOnboardingStrategy;
import io.github.lindenson.karate.authflow.onboarding.OnboardingFlavor;
import io.github.lindenson.karate.authflow.spi.KarateAuth;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Example 3 — encrypted device onboarding.
 *
 * <p>Self-contained: an in-process {@link FakeCryptoBackend} stands in for the real crypto backend,
 * so this runs with no network and no Docker. {@code EncryptedOnboardingStrategy} performs the full
 * RGK envelope (generate, RSA-wrap, AES, base64 matryoshka) and decrypts each response, so the
 * feature stays cleartext and ends with the master keys captured.
 *
 * <p>Run: {@code mvn test -Dtest=OnboardingExample}
 */
@DisplayName("Example: encrypted device onboarding")
class OnboardingExample {

    @Test
    @DisplayName("onboards a device and receives master keys, all crypto handled by the strategy")
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
                EncryptedOnboardingStrategy strategy = new EncryptedOnboardingStrategy(config);

                Results results = KarateAuth
                        .register(Runner.path("classpath:onboarding/onboarding.feature"), strategy, strategy)
                        .parallel(1);

                assertEquals(0, results.getFailCount(), results.getErrorMessages());
            } finally {
                System.clearProperty("backend.base");
            }
        }
    }
}
