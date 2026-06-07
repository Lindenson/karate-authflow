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
package io.github.lindenson.karate.authflow.onboarding;

import com.intuit.karate.Results;
import com.intuit.karate.Runner;
import io.github.lindenson.karate.authflow.spi.KarateAuth;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * End-to-end onboarding (handshake flavor) against {@link FakeCryptoBackend}: the Step 0 handshake yields the
 * crypto backend public key, which the strategy uses to wrap the RGK at Step 1. Hermetic — no network.
 */
@DisplayName("crypto backend onboarding — handshake flavor")
class OnboardingHandshakeTest {

    private static final String FEATURE =
            "classpath:io/github/lindenson/karate/authflow/onboarding/onboarding-handshake.feature";

    @Test
    @DisplayName("5-step onboarding handshakes, decrypts, and issues master keys")
    void onboardsViaHandshake() throws Exception {
        try (FakeCryptoBackend backend = new FakeCryptoBackend()) {
            System.setProperty("backend.base", backend.baseUrl());
            try {
                EncryptedOnboardingConfig config = EncryptedOnboardingConfig.builder()
                        .flavor(OnboardingFlavor.HANDSHAKE)
                        .appVersion(100_000_007)
                        .build();
                EncryptedOnboardingStrategy strategy = new EncryptedOnboardingStrategy(config);

                Results results = KarateAuth
                        .register(Runner.path(FEATURE), strategy, strategy)
                        .parallel(1);

                assertEquals(0, results.getFailCount(), results.getErrorMessages());
            } finally {
                System.clearProperty("backend.base");
            }
        }
    }
}
